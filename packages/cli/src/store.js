import { randomUUID } from 'node:crypto'
import {
  chmod,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  rmdir,
  stat,
  unlink
} from 'node:fs/promises'
import { join } from 'node:path'
import { arrayBufferToPem, pemToBase64, str2ab } from '@armadoc/crypto'

const CREDENTIALS = 'credentials.json'
const PRIVATE_KEY = 'private-key.pem'
const LOCK = 'refresh.lock'
const FILES = [CREDENTIALS, PRIVATE_KEY, LOCK]

const RSA_OAEP = { name: 'RSA-OAEP', hash: 'SHA-256' }
const STALE_LOCK_MS = 30_000
const LOCK_POLL_MS = 100

const ensureDir = async (dir) => {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  await chmod(dir, 0o700)
}

const readIfPresent = async (path) => {
  try {
    return await readFile(path, 'utf8')
  } catch (error) {
    if (error.code === 'ENOENT') return null
    throw error
  }
}

const unlinkIfPresent = async (path) => {
  try {
    await unlink(path)
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
}

const replaceFile = async (dir, name, data) => {
  await ensureDir(dir)
  const tmp = join(dir, `${name}.${randomUUID()}.tmp`)
  try {
    const file = await open(tmp, 'wx', 0o600)
    try {
      await file.writeFile(data)
      await file.sync()
    } finally {
      await file.close()
    }
    await rename(tmp, join(dir, name))
  } catch (error) {
    await unlinkIfPresent(tmp)
    throw error
  }
}

export const readCredentials = async (dir) => {
  const json = await readIfPresent(join(dir, CREDENTIALS))
  return json === null ? null : JSON.parse(json)
}

export const writeCredentials = (dir, credentials) =>
  replaceFile(dir, CREDENTIALS, `${JSON.stringify(credentials, null, 2)}\n`)

export const writePrivateKey = async (dir, privateKey) => {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey)
  await replaceFile(dir, PRIVATE_KEY, arrayBufferToPem(pkcs8, 'PRIVATE KEY'))
}

export const readPrivateKey = async (dir) => {
  const pem = await readIfPresent(join(dir, PRIVATE_KEY))
  if (pem === null) return null
  return crypto.subtle.importKey('pkcs8', str2ab(pemToBase64(pem)), RSA_OAEP, false, ['decrypt'])
}

export const clearStage = async (dir) => {
  let names
  try {
    names = await readdir(dir)
  } catch (error) {
    if (error.code === 'ENOENT') return
    throw error
  }

  const ours = (name) =>
    FILES.includes(name) ||
    FILES.some((file) => name.startsWith(`${file}.`) && name.endsWith('.tmp'))
  await Promise.all(names.filter(ours).map((name) => unlinkIfPresent(join(dir, name))))

  try {
    await rmdir(dir)
  } catch (error) {
    if (error.code !== 'ENOTEMPTY') throw error
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const lockAge = async (lock) => {
  try {
    return Date.now() - (await stat(lock)).mtimeMs
  } catch (error) {
    if (error.code === 'ENOENT') return Number.POSITIVE_INFINITY
    throw error
  }
}

const acquire = async (lock, token, { staleMs, pollMs }) => {
  for (;;) {
    try {
      const file = await open(lock, 'wx', 0o600)
      try {
        await file.writeFile(token)
      } finally {
        await file.close()
      }
      return
    } catch (error) {
      if (error.code !== 'EEXIST') throw error
    }

    if ((await lockAge(lock)) > staleMs) await unlinkIfPresent(lock)
    else await sleep(pollMs)
  }
}

const release = async (lock, token) => {
  if ((await readIfPresent(lock)) === token) await unlinkIfPresent(lock)
}

export const withRefreshLock = async (
  dir,
  refresh,
  { staleMs = STALE_LOCK_MS, pollMs = LOCK_POLL_MS } = {}
) => {
  await ensureDir(dir)
  const lock = join(dir, LOCK)
  const token = randomUUID()
  await acquire(lock, token, { staleMs, pollMs })
  try {
    return await refresh(await readCredentials(dir))
  } finally {
    await release(lock, token)
  }
}
