import { createHash, randomBytes } from 'node:crypto'
import { createServer } from 'node:http'

export const MAX_LABEL_LENGTH = 64

export class PairingDeniedError extends Error {}

export const createPkce = () => {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge }
}

export const createState = () => randomBytes(16).toString('base64url')

export const defaultLabel = (hostname) => `armadoc CLI on ${hostname}`.slice(0, MAX_LABEL_LENGTH)

export const authorizeUrl = ({ webOrigin, redirectUri, challenge, state, label }) => {
  const url = new URL('/oauth/authorize/', webOrigin)
  url.search = new URLSearchParams({
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    label
  })
  return url.href
}

const DENIALS = {
  access_denied: 'The pairing was denied in the browser',
  invalid_request: 'The consent page refused the pairing request'
}

export const readCallback = (params, state) => {
  if (params.get('state') !== state) return null

  const error = params.get('error')
  if (error) throw new PairingDeniedError(DENIALS[error] ?? `The pairing failed: ${error}`)

  const code = params.get('code')
  if (!code) throw new PairingDeniedError('The consent page returned no code')
  return code
}

const PAGE = (message) =>
  `<!doctype html><meta charset="utf-8"><title>Armadoc</title><p>${message}</p>\n`

export const listenForCallback = async (state, { timeoutMs = 600_000 } = {}) => {
  let settle
  const result = new Promise((resolve, reject) => {
    settle = { resolve, reject }
  })

  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1')
    if (req.method !== 'GET' || url.pathname !== '/callback') {
      res.writeHead(404).end()
      return
    }

    let code
    try {
      code = readCallback(url.searchParams, state)
    } catch (error) {
      res.writeHead(200, { 'Content-Type': 'text/html' }).end(PAGE(error.message))
      settle.reject(error)
      return
    }
    if (code === null) {
      res.writeHead(400).end()
      return
    }

    res
      .writeHead(200, { 'Content-Type': 'text/html' })
      .end(PAGE('Paired. You can close this tab and return to the terminal.'))
    settle.resolve(code)
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })

  const timer = setTimeout(
    () => settle.reject(new PairingDeniedError('Timed out waiting for the browser')),
    timeoutMs
  )
  const close = () => {
    clearTimeout(timer)
    server.close()
    server.closeAllConnections()
  }

  const code = result.finally(close)
  code.catch(() => {})

  return {
    redirectUri: `http://127.0.0.1:${server.address().port}/callback`,
    code
  }
}
