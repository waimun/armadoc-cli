import { mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import { basename, isAbsolute, join } from 'node:path'
import {
  DecryptionError,
  decryptPayload,
  importPublicKey,
  sealFile,
  unwrapFileKey
} from '@armadoc/crypto'
import { ApiError, fetchStep } from './api.js'
import { expandHome } from './config.js'

export const DEFAULT_EXPIRY_SECS = 864_000

const NAME_PATTERN = /^[A-Za-z\s'-]{2,50}$/
const FILE_NAME_MAX_LENGTH = 255

export class DocumentError extends Error {}

const deny = ({ reason }) => ({ ok: false, reason })

const isoTime = (secs) => new Date(secs * 1000).toISOString()

const withIsoExpiry = (rows) => rows.map((row) => ({ ...row, expiresAt: isoTime(row.expiresAt) }))

const half = (lists) =>
  Object.fromEntries(Object.entries(lists).map(([stage, rows]) => [stage, withIsoExpiry(rows)]))

export const listDocuments = async ({ client, direction }) => {
  const result = await client.get('/me/inventory')
  if (!result.ok) return deny(result)

  const directions = direction ? [direction] : ['inbound', 'outbound']
  return {
    ok: true,
    data: Object.fromEntries(directions.map((d) => [d, half(result.data[d])]))
  }
}

const safeFileName = (name) => {
  const base = basename(name)
  if (!base || base === '.' || base === '..') {
    throw new DocumentError(`Refusing to write a file named "${name}"`)
  }
  return base
}

const fetchLink = async (client, linkId) => {
  try {
    return await client.get('/link-info', { linkId })
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      throw new DocumentError(`No document ${linkId} was sent to you, or it has expired`)
    }
    throw error
  }
}

const download = async ({ client, fetch, linkId, url, name }) => {
  const k = url.split('/').pop()
  const signed = await client.get('/generate-download-url', { k, linkId })
  if (!signed.ok) return signed

  const step = `Downloading "${name}"`
  const response = await fetchStep(step, () => fetch(signed.data.url))
  if (!response.ok) throw new DocumentError(`Download failed (status ${response.status})`)
  return { ok: true, data: new Uint8Array(await fetchStep(step, () => response.arrayBuffer())) }
}

export const readDocument = async ({
  client,
  fetch,
  keyId,
  privateKey,
  linkId,
  directory,
  webOrigin
}) => {
  const link = await fetchLink(client, linkId)
  if (!link.ok) return deny(link)

  const files = link.data.files.map((file) => ({
    ...file,
    fileName: safeFileName(file.name),
    wrap: file.wrappedKeys.find((wrap) => wrap.keyId === keyId)
  }))

  if (files.some((file) => !file.wrap)) {
    throw new DocumentError(
      `Document ${linkId} was sent before this agent was paired, so its key cannot open it. Open it in the browser: ${webOrigin}/v/${linkId}`
    )
  }

  const names = files.map((file) => file.fileName)
  const duplicate = names.find((name, i) => names.indexOf(name) !== i)
  if (duplicate) throw new DocumentError(`Document ${linkId} has two files named "${duplicate}"`)

  await mkdir(directory, { recursive: true, mode: 0o700 })

  const written = []
  for (const file of files) {
    const path = join(directory, file.fileName)
    const fileKey = await unwrapFileKey(file.wrap, privateKey)

    const payload = await download({ client, fetch, linkId, url: file.url, name: file.fileName })
    if (!payload.ok) return deny(payload)

    let plaintext
    try {
      plaintext = new Uint8Array(await decryptPayload(payload.data, fileKey))
    } catch {
      throw new DecryptionError(`"${file.name}" failed to decrypt`)
    }

    try {
      await writeFile(path, plaintext, { flag: 'wx', mode: 0o600 })
    } catch (error) {
      if (error.code === 'EEXIST') {
        throw new DocumentError(`${path} already exists; pass another directory`)
      }
      throw error
    }

    written.push({
      name: file.fileName,
      ...(file.description ? { description: file.description } : {}),
      path,
      size: plaintext.byteLength
    })
  }

  return { ok: true, data: { linkId, directory, files: written } }
}

const checkFileName = (name) => {
  const control = [...name].some((char) => char.charCodeAt(0) < 32)
  if (name.length > FILE_NAME_MAX_LENGTH || control || /[<>]/.test(name)) {
    throw new DocumentError(
      `"${name}" cannot be sent: file names are at most ${FILE_NAME_MAX_LENGTH} characters, with no control characters or angle brackets`
    )
  }
}

const loadFile = async (given, home) => {
  const path = expandHome(given, home)
  if (!isAbsolute(path)) throw new DocumentError(`${path} is not an absolute path`)

  const info = await stat(path).catch(() => null)
  if (!info?.isFile()) throw new DocumentError(`${path} is not a file`)
  if (info.size === 0) throw new DocumentError(`${path} is empty`)

  const name = basename(path)
  checkFileName(name)
  return { name, bytes: await readFile(path) }
}

const upload = async ({ client, fetch, payload, name }) => {
  const policy = await client.get('/generate-upload-url')
  if (!policy.ok) return policy

  const { url, fields, key } = policy.data
  const form = new FormData()
  for (const [field, value] of Object.entries(fields)) form.append(field, value)
  form.append('file', new Blob([payload], { type: 'application/octet-stream' }))

  const response = await fetchStep(`Uploading "${name}"`, () =>
    fetch(url, { method: 'POST', body: form })
  )
  if (!response.ok) {
    const body = await response.text().catch(() => '')
    if (body.includes('EntityTooLarge')) {
      return { ok: false, reason: `"${name}" exceeds the maximum file size on your plan` }
    }
    throw new DocumentError(`Uploading "${name}" failed (status ${response.status})`)
  }

  return { ok: true, data: `${url.replace(/\/+$/, '')}/${key}` }
}

const quoteNames = (names) => names.map((name) => `"${name}"`).join(', ')

const sameNames = (expected, files) => {
  const a = [...expected].sort()
  const b = files.map((file) => file.name).sort()
  return a.length === b.length && a.every((name, i) => name === b[i])
}

const acceptedInvite = async (client, email) => {
  const inventory = await client.get('/me/inventory')
  if (!inventory.ok) return inventory
  const wanted = email.toLowerCase()
  const row = inventory.data.outbound.awaitingUpload.find(
    (invite) => invite.recipientEmail.toLowerCase() === wanted
  )
  return { ok: true, data: row ?? null }
}

const invite = async ({ client, senderName, files, recipient, expirySecs }) => {
  const created = await client.post('/create-invite', {
    sender: { name: senderName },
    recipient: { name: recipient.name, email: recipient.email },
    files: files.map((file) => ({ name: file.name })),
    expirySecs
  })
  if (!created.ok) return deny(created)

  return {
    ok: true,
    data: {
      status: 'invited',
      recipient,
      files: files.map((file) => file.name),
      next: `${recipient.email} has no Armadoc key yet, so they were emailed an invite instead. Nothing was uploaded. Once they accept, you will get an email; then send the same files again to complete the invite.`
    }
  }
}

export const sendDocument = async ({
  client,
  fetch,
  senderName,
  paths,
  recipient,
  expirySecs = DEFAULT_EXPIRY_SECS,
  home
}) => {
  if (!NAME_PATTERN.test(recipient.name)) {
    throw new DocumentError(
      "The recipient's name must be 2 to 50 characters: letters, spaces, ' and -"
    )
  }

  const files = []
  for (const path of paths) files.push(await loadFile(path, home))

  const lookup = await client.get('/public-key', { identifier: recipient.email })
  if (!lookup.ok) return deny(lookup)
  if (lookup.data.keys.length === 0)
    return invite({ client, senderName, files, recipient, expirySecs })

  const accepted = await acceptedInvite(client, recipient.email)
  if (!accepted.ok) return deny(accepted)
  const inviteId = accepted.data?.inviteId
  if (inviteId && !sameNames(accepted.data.fileNames, files)) {
    return deny({
      reason: `${recipient.email} accepted your invite for ${quoteNames(accepted.data.fileNames)}. Send files with exactly those names to complete it.`
    })
  }

  const targets = await Promise.all(
    lookup.data.keys.map(async ({ keyId, publicKey }) => ({
      keyId,
      publicKey: await importPublicKey(publicKey)
    }))
  )

  const sealed = []
  for (const file of files) {
    const { payload, wrappedKeys } = await sealFile(file.bytes, targets)
    const uploaded = await upload({ client, fetch, payload, name: file.name })
    if (!uploaded.ok) return deny(uploaded)
    sealed.push({ name: file.name, wrappedKeys, url: uploaded.data })
  }

  const stored = await client.post('/store-encrypted-key', {
    sender: { name: senderName },
    recipient: { name: recipient.name, email: recipient.email },
    files: sealed,
    ...(inviteId ? { inviteId } : { expirySecs })
  })
  if (!stored.ok) return deny(stored)

  return {
    ok: true,
    data: {
      status: 'sent',
      linkId: stored.data.linkId,
      recipient,
      files: files.map((file) => file.name),
      expiresAt: isoTime(stored.data.expiresAt),
      ...(inviteId ? { completedInvite: inviteId } : {})
    }
  }
}
