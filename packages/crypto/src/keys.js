import { arrayBufferToPem, pemToBase64, str2ab } from './encoding.js'

const RSA_OAEP = { name: 'RSA-OAEP', hash: 'SHA-256' }

export const generateKeyPair = async ({ extractable }) => {
  const keyPair = await crypto.subtle.generateKey(
    {
      ...RSA_OAEP,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1])
    },
    extractable,
    ['encrypt', 'decrypt']
  )

  const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey)

  return { publicKey: arrayBufferToPem(publicKey, 'PUBLIC KEY'), privateKey: keyPair.privateKey }
}

export const importPublicKey = (pem) =>
  crypto.subtle.importKey('spki', str2ab(pemToBase64(pem)), RSA_OAEP, true, ['encrypt'])
