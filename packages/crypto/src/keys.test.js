import { describe, expect, it } from 'vitest'
import fixture from './fixtures/browser.json'
import { generateKeyPair, importPublicKey } from './keys.js'

const pemBodyLines = (pem) => pem.trim().split('\n').slice(1, -1)

describe('generateKeyPair', () => {
  it('exports the public half as SPKI PEM in the browser line layout', async () => {
    const { publicKey } = await generateKeyPair({ extractable: false })
    const browserPem = fixture.keys[0].publicKeyPem

    expect(publicKey).toMatch(/^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/)
    expect(pemBodyLines(publicKey).map((line) => line.length)).toEqual(
      pemBodyLines(browserPem).map((line) => line.length)
    )
    expect((await importPublicKey(publicKey)).algorithm).toMatchObject({
      name: 'RSA-OAEP',
      modulusLength: 2048,
      hash: { name: 'SHA-256' }
    })
  })

  it('sets extractability on the private half from the caller', async () => {
    expect((await generateKeyPair({ extractable: false })).privateKey.extractable).toBe(false)
    expect((await generateKeyPair({ extractable: true })).privateKey.extractable).toBe(true)
  })
})

describe('importPublicKey', () => {
  it('imports a public key the browser generated', async () => {
    const key = await importPublicKey(fixture.keys[0].publicKeyPem)

    expect(key.usages).toEqual(['encrypt'])
  })
})
