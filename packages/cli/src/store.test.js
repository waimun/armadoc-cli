import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  utimes,
  writeFile
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair, importPublicKey } from '@armadoc/crypto'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  clearStage,
  readCredentials,
  readPrivateKey,
  withRefreshLock,
  writeCredentials,
  writePrivateKey
} from './store.js'

const CREDENTIALS = { keyId: 'K1', refreshToken: 'R1', label: 'test', senderName: 'Ada' }

let root
let dir

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'armadoc-store-'))
  dir = join(root, 'prod')
})

afterEach(() => rm(root, { recursive: true, force: true }))

const mode = async (path) => (await stat(path)).mode & 0o777

describe('credentials', () => {
  it('reads as null before any are written', async () => {
    expect(await readCredentials(dir)).toBeNull()
  })

  it('round-trips, in a 0700 directory and a 0600 file', async () => {
    await writeCredentials(dir, CREDENTIALS)

    expect(await readCredentials(dir)).toEqual(CREDENTIALS)
    expect(await mode(dir)).toBe(0o700)
    expect(await mode(join(dir, 'credentials.json'))).toBe(0o600)
  })

  it('replaces the file whole and leaves no temp file', async () => {
    await writeCredentials(dir, CREDENTIALS)
    await writeCredentials(dir, { keyId: 'K2' })

    expect(await readCredentials(dir)).toEqual({ keyId: 'K2' })
    expect(await readdir(dir)).toEqual(['credentials.json'])
  })

  it('tightens an existing directory to 0700', async () => {
    await mkdir(dir, { mode: 0o755 })
    await chmod(dir, 0o755)
    await writeCredentials(dir, CREDENTIALS)

    expect(await mode(dir)).toBe(0o700)
  })
})

describe('private key', () => {
  it('reads as null before one is written', async () => {
    expect(await readPrivateKey(dir)).toBeNull()
  })

  it('round-trips as a 0600 PKCS#8 PEM that still opens what its public half sealed', async () => {
    const { publicKey, privateKey } = await generateKeyPair({ extractable: true })
    await writePrivateKey(dir, privateKey)

    const path = join(dir, 'private-key.pem')
    expect(await readFile(path, 'utf8')).toMatch(/^-----BEGIN PRIVATE KEY-----\n/)
    expect(await mode(path)).toBe(0o600)

    const sealed = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      await importPublicKey(publicKey),
      new TextEncoder().encode('hello')
    )
    const restored = await readPrivateKey(dir)
    const opened = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, restored, sealed)
    expect(new TextDecoder().decode(opened)).toBe('hello')
    expect(restored.extractable).toBe(false)
  })
})

describe('withRefreshLock', () => {
  it('hands over the credentials read after taking the lock, and releases it', async () => {
    await writeCredentials(dir, CREDENTIALS)

    const seen = await withRefreshLock(dir, (credentials) => credentials)

    expect(seen).toEqual(CREDENTIALS)
    expect(await readdir(dir)).toEqual(['credentials.json'])
  })

  it('serializes refreshes, so the second sees the token the first rotated in', async () => {
    await writeCredentials(dir, CREDENTIALS)
    const rotate = async (credentials) => {
      const next = { ...credentials, refreshToken: `${credentials.refreshToken}+` }
      await writeCredentials(dir, next)
      return credentials.refreshToken
    }

    const presented = await Promise.all([
      withRefreshLock(dir, rotate, { pollMs: 5 }),
      withRefreshLock(dir, rotate, { pollMs: 5 })
    ])

    expect(presented.sort()).toEqual(['R1', 'R1+'])
    expect((await readCredentials(dir)).refreshToken).toBe('R1++')
  })

  it('releases the lock when the refresh throws', async () => {
    await expect(
      withRefreshLock(dir, () => {
        throw new Error('network')
      })
    ).rejects.toThrow('network')

    expect(await readdir(dir)).toEqual([])
  })

  it('waits on a live lock', async () => {
    await mkdir(dir, { recursive: true })
    const lock = join(dir, 'refresh.lock')
    await writeFile(lock, 'another process')
    setTimeout(() => rm(lock), 50)

    const started = Date.now()
    await withRefreshLock(dir, () => {}, { pollMs: 5 })

    expect(Date.now() - started).toBeGreaterThanOrEqual(40)
  })

  it('breaks a lock older than 30s', async () => {
    await mkdir(dir, { recursive: true })
    const lock = join(dir, 'refresh.lock')
    await writeFile(lock, 'a crashed process')
    const past = new Date(Date.now() - 31_000)
    await utimes(lock, past, past)

    expect(await withRefreshLock(dir, () => 'refreshed')).toBe('refreshed')
  })

  it('leaves a lock that another process took over', async () => {
    const lock = join(dir, 'refresh.lock')

    await withRefreshLock(dir, () => writeFile(lock, 'another process'))

    expect(await readFile(lock, 'utf8')).toBe('another process')
  })
})

describe('clearStage', () => {
  it('removes the stage directory with every file in it', async () => {
    await writeCredentials(dir, CREDENTIALS)
    await writePrivateKey(dir, (await generateKeyPair({ extractable: true })).privateKey)
    await writeFile(join(dir, 'credentials.json.abc.tmp'), '')

    await clearStage(dir)

    expect(await readdir(root)).toEqual([])
  })

  it('leaves files that are not its own, and their directory', async () => {
    await writeCredentials(dir, CREDENTIALS)
    await writeFile(join(dir, 'notes.txt'), '')

    await clearStage(dir)

    expect(await readdir(dir)).toEqual(['notes.txt'])
  })

  it('does nothing for a stage never logged in to', async () => {
    await expect(clearStage(dir)).resolves.toBeUndefined()
  })
})
