import { createClient, PairingError } from './api.js'
import { onStage } from './config.js'
import { readCredentials, readPrivateKey } from './store.js'

export const createSession = ({ apiBase, stage, dir, fetch, userAgent }) => {
  let client = null

  return async ({ needsKey = false } = {}) => {
    const credentials = await readCredentials(dir)
    if (!credentials?.refreshToken) {
      throw new PairingError(`Not logged in${onStage(stage, 'to')}; run \`armadoc login\``)
    }

    let privateKey = null
    if (needsKey) {
      privateKey = credentials.keyId ? await readPrivateKey(dir) : null
      if (!privateKey) throw new PairingError('No key is enrolled; run `armadoc login` to finish')
    }

    client ??= createClient({ apiBase, dir, fetch, userAgent: userAgent() })
    return { client, credentials, privateKey }
  }
}
