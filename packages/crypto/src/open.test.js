import { describe, expect, it } from 'vitest'
import { arrayBufferToBase64, str2ab } from './encoding.js'
import { DecryptionError, PrivateKeyNotFoundError } from './errors.js'
import fixture from './fixtures/browser.json'
import { decryptPayload, pickWrap, unwrapFileKey } from './open.js'

const importFixtureKey = (keyId) => {
  const { privateKeyPkcs8 } = fixture.keys.find((key) => key.keyId === keyId)
  return crypto.subtle.importKey(
    'pkcs8',
    str2ab(privateKeyPkcs8),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  )
}

describe('opening a payload sealed in the browser', () => {
  it('recovers the plaintext through the wrap made for the held key', async () => {
    const wrap = pickWrap(fixture.wrappedKeys, ['fixture-recipient'])
    const fileKey = await unwrapFileKey(wrap, await importFixtureKey('fixture-recipient'))
    const plaintext = await decryptPayload(str2ab(fixture.payload), fileKey)

    expect(arrayBufferToBase64(await crypto.subtle.exportKey('raw', fileKey))).toBe(
      fixture.symmetricKeyRaw
    )
    expect(arrayBufferToBase64(plaintext)).toBe(fixture.plaintext)
  })

  it('throws DecryptionError when the key does not match the wrap', async () => {
    const wrap = pickWrap(fixture.wrappedKeys, ['fixture-recipient'])

    await expect(unwrapFileKey(wrap, await importFixtureKey('fixture-decoy'))).rejects.toThrow(
      DecryptionError
    )
  })
})

describe('pickWrap', () => {
  const wrappedKeys = [
    { keyId: 'a', encryptedSymmetricKey: 'wrap-a' },
    { keyId: 'b', encryptedSymmetricKey: 'wrap-b' }
  ]

  it('picks the wrap whose key is held locally', () => {
    expect(pickWrap(wrappedKeys, ['b'])).toEqual(wrappedKeys[1])
  })

  it('picks the first wrap in send order when several keys are held', () => {
    expect(pickWrap(wrappedKeys, ['b', 'a'])).toEqual(wrappedKeys[0])
  })

  it('throws PrivateKeyNotFoundError when no wrap names a held key', () => {
    expect(() => pickWrap(wrappedKeys, ['c'])).toThrow(PrivateKeyNotFoundError)
    expect(() => pickWrap(wrappedKeys, [])).toThrow(PrivateKeyNotFoundError)
  })
})
