import pkg from '../package.json' with { type: 'json' }
import { withRefreshLock, writeCredentials } from './store.js'

const PRODUCT = `armadoc-cli/${pkg.version}`

export const CLI_USER_AGENT = `${PRODUCT} (cli)`

export const CLIENT_ID = 'armadoc-cli'

const token = (value) =>
  String(value)
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .slice(0, 64)

export const mcpUserAgent = (host) => {
  if (!host?.name) return `${PRODUCT} (mcp)`
  const version = host.version ? `/${token(host.version)}` : ''
  return `${PRODUCT} (mcp; ${token(host.name)}${version})`
}

const REFRESH_TIMEOUT_MS = 10_000
const REFRESH_IDLE_MS = 30 * 24 * 60 * 60 * 1000

export class ApiError extends Error {
  constructor(message, { status, code } = {}) {
    super(message)
    this.status = status
    this.code = code
  }
}

export class TokenError extends Error {
  constructor({ status, error, description }) {
    super(description ?? error)
    this.status = status
    this.error = error
  }
}

export class PairingError extends Error {}

export class NetworkError extends Error {}

export const fetchStep = async (step, request) => {
  try {
    return await request()
  } catch (error) {
    throw new NetworkError(`${step} failed`, { cause: error.cause ?? error })
  }
}

const failed = (method, path, status, data) =>
  `${method} ${path} failed (${[status, data?.code].filter(Boolean).join(', ')})`

const readBody = async (response) => {
  const text = await response.text()
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

const tokenGrant = async ({ apiBase, step, params, fetch, signal, userAgent }) => {
  const response = await fetchStep(step, () =>
    fetch(`${apiBase}/oauth/token`, {
      method: 'POST',
      headers: { 'User-Agent': userAgent },
      body: new URLSearchParams({ client_id: CLIENT_ID, ...params }),
      signal
    })
  )
  const body = await readBody(response)

  if (!response.ok) {
    throw new TokenError({
      status: response.status,
      error: body?.error ?? `http_${response.status}`,
      description: body?.error_description
    })
  }

  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token,
    refreshExpiresAt: new Date(Date.now() + REFRESH_IDLE_MS).toISOString()
  }
}

export const redeemCode = ({
  apiBase,
  code,
  verifier,
  redirectUri,
  fetch = globalThis.fetch,
  userAgent
}) =>
  tokenGrant({
    apiBase,
    step: 'Redeeming the pairing code',
    fetch,
    userAgent,
    params: {
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: redirectUri
    }
  })

export const refreshGrant = ({
  apiBase,
  refreshToken,
  fetch = globalThis.fetch,
  timeoutMs = REFRESH_TIMEOUT_MS,
  userAgent
}) =>
  tokenGrant({
    apiBase,
    step: 'Refreshing the pairing',
    fetch,
    userAgent,
    params: { grant_type: 'refresh_token', refresh_token: refreshToken },
    signal: AbortSignal.timeout(timeoutMs)
  })

export const createClient = ({
  apiBase,
  dir,
  accessToken = null,
  fetch = globalThis.fetch,
  userAgent
}) => {
  let current = accessToken
  let inflight = null

  const rotate = () =>
    withRefreshLock(dir, async (credentials) => {
      if (!credentials?.refreshToken) throw new PairingError('Not paired; run `armadoc login`')

      let tokens
      try {
        tokens = await refreshGrant({
          apiBase,
          refreshToken: credentials.refreshToken,
          fetch,
          userAgent
        })
      } catch (error) {
        if (error instanceof TokenError && error.error === 'invalid_grant') {
          throw new PairingError(
            'The pairing was revoked or has lapsed; run `armadoc logout`, then `armadoc login`'
          )
        }
        throw error
      }

      await writeCredentials(dir, {
        ...credentials,
        refreshToken: tokens.refreshToken,
        refreshExpiresAt: tokens.refreshExpiresAt
      })
      return tokens.accessToken
    })

  const refresh = async (stale) => {
    if (current !== stale) return
    inflight ??= rotate().finally(() => {
      inflight = null
    })
    current = await inflight
  }

  const send = (method, path, url, body) =>
    fetchStep(`${method} ${path}`, () =>
      fetch(url, {
        method,
        headers: {
          'User-Agent': userAgent,
          Authorization: `Bearer ${current}`,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' })
        },
        body: body === undefined ? undefined : JSON.stringify(body)
      })
    )

  const request = async (method, path, { query, body } = {}) => {
    const search = query ? `?${new URLSearchParams(query)}` : ''
    const url = `${apiBase}${path}${search}`

    if (current === null) await refresh(null)
    const token = current
    let response = await send(method, path, url, body)
    if (response.status === 401) {
      await refresh(token)
      response = await send(method, path, url, body)
    }

    const data = await readBody(response)
    if (response.ok) return { ok: true, data }
    if (response.status === 403 && data?.code) {
      return { ok: false, code: data.code, reason: data.error ?? data.code }
    }

    throw new ApiError(
      data?.error ?? data?.message ?? failed(method, path, response.status, data),
      {
        status: response.status,
        code: data?.code
      }
    )
  }

  return {
    get: (path, query) => request('GET', path, { query }),
    post: (path, body) => request('POST', path, { body })
  }
}
