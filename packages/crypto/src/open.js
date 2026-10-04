import { str2ab } from './encoding.js'
import { DecryptionError, PrivateKeyNotFoundError } from './errors.js'
import { IV_LENGTH } from './seal.js'

export const pickWrap = (wrappedKeys, localKeyIds) => {
  const wrap = wrappedKeys.find(({ keyId }) => localKeyIds.includes(keyId))
  if (!wrap) {
    throw new PrivateKeyNotFoundError('No file key was wrapped for a locally held key')
  }
  return wrap
}

export const unwrapFileKey = async (wrap, privateKey) => {
  let symmetricKey
  try {
    symmetricKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      new Uint8Array(str2ab(wrap.encryptedSymmetricKey))
    )
  } catch {
    throw new DecryptionError('Failed to decrypt — private key may not match')
  }

  return crypto.subtle.importKey('raw', symmetricKey, 'AES-GCM', true, ['decrypt'])
}

export const decryptPayload = async (payload, fileKey) => {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: payload.slice(0, IV_LENGTH) },
    fileKey,
    payload.slice(IV_LENGTH)
  )
}
