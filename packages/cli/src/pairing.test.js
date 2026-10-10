import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  authorizeUrl,
  createPkce,
  defaultLabel,
  listenForCallback,
  PairingDeniedError,
  readCallback
} from './pairing.js'

describe('createPkce', () => {
  it('makes an S256 challenge of the verifier', () => {
    const { verifier, challenge } = createPkce()

    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(challenge).toBe(createHash('sha256').update(verifier).digest('base64url'))
  })
})

describe('defaultLabel', () => {
  it('names the host, cut to 64 characters', () => {
    expect(defaultLabel('mbp')).toBe('armadoc CLI on mbp')
    expect(defaultLabel('h'.repeat(80))).toHaveLength(64)
  })
})

describe('authorizeUrl', () => {
  it('opens the consent page as armadoc-cli with the loopback callback and an S256 challenge', () => {
    const url = new URL(
      authorizeUrl({
        webOrigin: 'https://dev.armadoc.link',
        redirectUri: 'http://127.0.0.1:5000/callback',
        challenge: 'C',
        state: 'S',
        label: 'armadoc CLI on mbp'
      })
    )

    expect(url.origin + url.pathname).toBe('https://dev.armadoc.link/oauth/authorize/')
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: 'armadoc-cli',
      redirect_uri: 'http://127.0.0.1:5000/callback',
      code_challenge: 'C',
      code_challenge_method: 'S256',
      state: 'S',
      label: 'armadoc CLI on mbp'
    })
  })
})

describe('readCallback', () => {
  const params = (query) => new URLSearchParams(query)

  it('returns the code when the state matches', () => {
    expect(readCallback(params('code=C&state=S'), 'S')).toBe('C')
  })

  it('ignores a callback with another state', () => {
    expect(readCallback(params('code=C&state=X'), 'S')).toBeNull()
    expect(readCallback(params('code=C'), 'S')).toBeNull()
  })

  it('throws on a denial', () => {
    expect(() => readCallback(params('error=access_denied&state=S'), 'S')).toThrow(
      'The pairing was denied in the browser'
    )
  })
})

describe('listenForCallback', () => {
  it('listens on loopback and resolves with the code', async () => {
    const callback = await listenForCallback('S')

    expect(callback.redirectUri).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/)
    const response = await fetch(`${callback.redirectUri}?code=C&state=S`)
    expect(response.status).toBe(200)
    expect(await callback.code).toBe('C')
  })

  it('refuses other paths and other states, and keeps listening', async () => {
    const callback = await listenForCallback('S')
    const base = callback.redirectUri.replace('/callback', '')

    expect((await fetch(`${base}/other?code=C&state=S`)).status).toBe(404)
    expect((await fetch(`${callback.redirectUri}?code=C&state=X`)).status).toBe(400)

    await fetch(`${callback.redirectUri}?code=C&state=S`)
    expect(await callback.code).toBe('C')
  })

  it('rejects on a denial', async () => {
    const callback = await listenForCallback('S')

    await fetch(`${callback.redirectUri}?error=access_denied&state=S`)
    await expect(callback.code).rejects.toThrow(PairingDeniedError)
  })

  it('gives up after the timeout', async () => {
    const callback = await listenForCallback('S', { timeoutMs: 20 })

    await expect(callback.code).rejects.toThrow('Timed out waiting for the browser')
  })
})
