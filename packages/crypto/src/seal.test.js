import { describe, expect, it } from 'vitest'
import { generateKeyPair, importPublicKey } from './keys.js'
import { decryptPayload, pickWrap, unwrapFileKey } from './open.js'
import { IV_LENGTH, sealFile } from './seal.js'

const GCM_TAG_LENGTH = 16

describe('sealFile', () => {
  it('seals a payload every target key can open', async () => {
    const holders = await Promise.all(
      ['laptop', 'phone'].map(async (keyId) => {
        const { publicKey, privateKey } = await generateKeyPair({ extractable: false })
        return { keyId, publicKey: await importPublicKey(publicKey), privateKey }
      })
    )
    const plaintext = crypto.getRandomValues(new Uint8Array(4096))

    const { payload, wrappedKeys } = await sealFile(plaintext, holders)

    expect(payload.byteLength).toBe(IV_LENGTH + plaintext.byteLength + GCM_TAG_LENGTH)
    expect(wrappedKeys.map(({ keyId }) => keyId)).toEqual(['laptop', 'phone'])
    for (const { keyId, privateKey } of holders) {
      const fileKey = await unwrapFileKey(pickWrap(wrappedKeys, [keyId]), privateKey)
      expect(new Uint8Array(await decryptPayload(payload, fileKey))).toEqual(plaintext)
    }
  })

  it('uses a fresh file key and IV per seal', async () => {
    const { publicKey } = await generateKeyPair({ extractable: false })
    const targets = [{ keyId: 'k', publicKey: await importPublicKey(publicKey) }]
    const plaintext = new Uint8Array(32)

    const first = await sealFile(plaintext, targets)
    const second = await sealFile(plaintext, targets)

    expect(first.payload.slice(0, IV_LENGTH)).not.toEqual(second.payload.slice(0, IV_LENGTH))
    expect(first.payload).not.toEqual(second.payload)
  })
})
