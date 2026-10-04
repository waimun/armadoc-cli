import { arrayBufferToBase64 } from './encoding.js'

export const IV_LENGTH = 12

export const sealFile = async (bytes, targets) => {
  const symmetricKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt'
  ])

  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, symmetricKey, bytes)

  const exportedSymmetricKey = await crypto.subtle.exportKey('raw', symmetricKey)
  const wrappedKeys = await Promise.all(
    targets.map(async ({ keyId, publicKey }) => ({
      keyId,
      encryptedSymmetricKey: arrayBufferToBase64(
        await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, exportedSymmetricKey)
      )
    }))
  )

  const payload = new Uint8Array(IV_LENGTH + encryptedData.byteLength)
  payload.set(iv)
  payload.set(new Uint8Array(encryptedData), IV_LENGTH)

  return { payload, wrappedKeys }
}
