import { mkdtemp, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import pkg from '../package.json' with { type: 'json' }
import {
  ApiError,
  CLI_USER_AGENT,
  createClient,
  mcpUserAgent,
  PairingError,
  redeemCode,
  refreshGrant,
  TokenError
} from './api.js'
import { readCredentials, writeCredentials } from './store.js'

const API = 'https://api.example.test/v1'
const CREDENTIALS = { keyId: 'K1', refreshToken: 'R1', label: 'test', senderName: 'Ada' }

let root
let dir

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'armadoc-api-'))
  dir = join(root, 'prod')
})

afterEach(() => rm(root, { recursive: true, force: true }))

const json = (status, body) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  })

const fakeFetch = (handler) => {
  const calls = []
  const fetch = async (url, init) => {
    const call = { url, ...init }
    calls.push(call)
    return handler(call, calls)
  }
  return { fetch, calls }
}

const isToken = (call) => call.url === `${API}/oauth/token`
const tokens = (n) => json(200, { access_token: `A${n}`, refresh_token: `R${n}` })

const PRODUCT = `armadoc-cli/${pkg.version}`

it('names this client, its version and the CLI in the User-Agent', () => {
  expect(CLI_USER_AGENT).toBe(`${PRODUCT} (cli)`)
})

it('names the MCP server and its host, reduced to token characters', () => {
  expect(mcpUserAgent({ name: 'claude-ai', version: '0.12.0' })).toBe(
    `${PRODUCT} (mcp; claude-ai/0.12.0)`
  )
  expect(mcpUserAgent({ name: 'Visual Studio Code (Insiders)' })).toBe(
    `${PRODUCT} (mcp; Visual-Studio-Code-Insiders-)`
  )
  expect(mcpUserAgent({ name: 'x'.repeat(100) })).toBe(`${PRODUCT} (mcp; ${'x'.repeat(64)})`)
  expect(mcpUserAgent(undefined)).toBe(`${PRODUCT} (mcp)`)
})

describe('token grants', () => {
  it('redeems a code, form-encoded', async () => {
    const { fetch, calls } = fakeFetch(() => tokens(1))

    const result = await redeemCode({
      apiBase: API,
      code: 'C',
      verifier: 'V',
      redirectUri: 'http://127.0.0.1:5000/callback',
      fetch,
      userAgent: CLI_USER_AGENT
    })

    expect(result).toMatchObject({ accessToken: 'A1', refreshToken: 'R1' })
    expect(Date.parse(result.refreshExpiresAt) - Date.now()).toBeGreaterThan(29 * 86_400_000)
    expect(calls[0].method).toBe('POST')
    expect(calls[0].headers['User-Agent']).toBe(CLI_USER_AGENT)
    expect(Object.fromEntries(calls[0].body)).toEqual({
      grant_type: 'authorization_code',
      code: 'C',
      code_verifier: 'V',
      redirect_uri: 'http://127.0.0.1:5000/callback'
    })
  })

  it('throws the OAuth error with its description', async () => {
    const { fetch } = fakeFetch(() =>
      json(400, {
        error: 'unsupported_client_version',
        error_description: 'armadoc 0.2.0 or later is required'
      })
    )

    const failure = refreshGrant({ apiBase: API, refreshToken: 'R1', fetch })

    await expect(failure).rejects.toThrow(TokenError)
    await expect(failure).rejects.toMatchObject({
      status: 400,
      error: 'unsupported_client_version',
      message: 'armadoc 0.2.0 or later is required'
    })
  })

  it('gives up on a refresh that does not answer in time', async () => {
    const fetch = (_url, { signal }) =>
      new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason))
      })

    await expect(
      refreshGrant({ apiBase: API, refreshToken: 'R1', fetch, timeoutMs: 20 })
    ).rejects.toMatchObject({ name: 'TimeoutError' })
  })
})

describe('createClient', () => {
  it('sends the bearer token and returns the data', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, { links: [] }))
    const client = createClient({
      apiBase: API,
      dir,
      accessToken: 'A0',
      fetch,
      userAgent: CLI_USER_AGENT
    })

    expect(await client.get('/me/inventory', { direction: 'inbound' })).toEqual({
      ok: true,
      data: { links: [] }
    })
    expect(calls[0].url).toBe(`${API}/me/inventory?direction=inbound`)
    expect(calls[0].headers).toMatchObject({
      'User-Agent': CLI_USER_AGENT,
      Authorization: 'Bearer A0'
    })
  })

  it('posts JSON', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, { keyId: 'K2' }))
    const client = createClient({ apiBase: API, dir, accessToken: 'A0', fetch })

    await client.post('/me/keys', { holder: 'agent' })

    expect(calls[0].method).toBe('POST')
    expect(calls[0].headers['Content-Type']).toBe('application/json')
    expect(JSON.parse(calls[0].body)).toEqual({ holder: 'agent' })
  })

  it('returns a deny as an outcome with the server reason', async () => {
    const { fetch } = fakeFetch(() =>
      json(403, { error: 'Expiry exceeds your plan', code: 'EXPIRY_EXCEEDED', enforced: true })
    )
    const client = createClient({ apiBase: API, dir, accessToken: 'A0', fetch })

    expect(await client.post('/store-encrypted-key', {})).toEqual({
      ok: false,
      code: 'EXPIRY_EXCEEDED',
      reason: 'Expiry exceeds your plan'
    })
  })

  it('throws on a 403 with no code, and on any other failure', async () => {
    const { fetch } = fakeFetch((call) =>
      call.url.endsWith('/forbidden')
        ? json(403, { message: 'Forbidden' })
        : json(404, { code: 'LINK_NOT_FOUND', kind: 'domain' })
    )
    const client = createClient({ apiBase: API, dir, accessToken: 'A0', fetch })

    await expect(client.get('/forbidden')).rejects.toMatchObject({ status: 403 })
    await expect(client.get('/link-info')).rejects.toThrow(ApiError)
    await expect(client.get('/link-info')).rejects.toMatchObject({
      status: 404,
      code: 'LINK_NOT_FOUND'
    })
  })

  it('refreshes before the first request when it holds no access token', async () => {
    await writeCredentials(dir, CREDENTIALS)
    const { fetch, calls } = fakeFetch((call) => (isToken(call) ? tokens(2) : json(200, {})))
    const client = createClient({ apiBase: API, dir, fetch })

    await client.get('/me/inventory')

    expect(Object.fromEntries(calls[0].body)).toEqual({
      grant_type: 'refresh_token',
      refresh_token: 'R1'
    })
    expect(calls[1].headers.Authorization).toBe('Bearer A2')
    expect(await readCredentials(dir)).toMatchObject({ ...CREDENTIALS, refreshToken: 'R2' })
    expect(await readdir(dir)).toEqual(['credentials.json'])
  })

  it('refreshes once and retries once on a 401', async () => {
    await writeCredentials(dir, CREDENTIALS)
    const { fetch, calls } = fakeFetch((call) => {
      if (isToken(call)) return tokens(2)
      return call.headers.Authorization === 'Bearer A2' ? json(200, { ok: 1 }) : json(401)
    })
    const client = createClient({ apiBase: API, dir, accessToken: 'A0', fetch })

    expect(await client.get('/me/inventory')).toEqual({ ok: true, data: { ok: 1 } })
    expect(calls.filter(isToken)).toHaveLength(1)
    expect(calls).toHaveLength(3)
  })

  it('throws when the retry is refused too', async () => {
    await writeCredentials(dir, CREDENTIALS)
    const { fetch, calls } = fakeFetch((call) =>
      isToken(call) ? tokens(2) : json(401, { message: 'Unauthorized' })
    )
    const client = createClient({ apiBase: API, dir, accessToken: 'A0', fetch })

    await expect(client.get('/me/inventory')).rejects.toMatchObject({ status: 401 })
    expect(calls.filter(isToken)).toHaveLength(1)
  })

  it('shares one refresh between concurrent requests', async () => {
    await writeCredentials(dir, CREDENTIALS)
    const { fetch, calls } = fakeFetch((call) => (isToken(call) ? tokens(2) : json(200, {})))
    const client = createClient({ apiBase: API, dir, fetch })

    await Promise.all([client.get('/a'), client.get('/b'), client.get('/c')])

    expect(calls.filter(isToken)).toHaveLength(1)
  })

  it('asks for a login when nothing is paired', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, {}))
    const client = createClient({ apiBase: API, dir, fetch })

    await expect(client.get('/me/inventory')).rejects.toThrow(PairingError)
    expect(calls).toHaveLength(0)
  })

  it('asks for a logout and login when the refresh token is refused, and keeps the credentials', async () => {
    await writeCredentials(dir, CREDENTIALS)
    const { fetch } = fakeFetch((call) =>
      isToken(call) ? json(400, { error: 'invalid_grant' }) : json(401)
    )
    const client = createClient({ apiBase: API, dir, accessToken: 'A0', fetch })

    await expect(client.get('/me/inventory')).rejects.toThrow(
      new PairingError(
        'The pairing was revoked or has lapsed; run `armadoc logout`, then `armadoc login`'
      )
    )
    expect(await readCredentials(dir)).toEqual(CREDENTIALS)
  })
})
