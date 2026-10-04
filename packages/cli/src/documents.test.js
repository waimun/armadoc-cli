import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair } from '@armadoc/crypto'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createClient } from './api.js'
import { DocumentError, listDocuments, readDocument, sendDocument } from './documents.js'

const API = 'https://api.example.test/v1'
const S3 = 'https://bucket.s3.example.test'
const WEB = 'https://armadoc.example.test'

let root

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'armadoc-documents-'))
})

afterEach(() => rm(root, { recursive: true, force: true }))

const json = (status, body) => new Response(JSON.stringify(body), { status })

const EMPTY = { awaitingAcceptance: [], awaitingUpload: [], active: [] }

const backend = ({ keys = [], store, upload, awaitingUpload = [], invite } = {}) => {
  const state = { objects: new Map(), links: new Map(), invites: [], requests: [], uploads: 0 }

  const fetch = async (url, init = {}) => {
    state.requests.push({ url, ...init })
    const { origin, pathname, searchParams } = new URL(url)

    if (origin === S3 && init.method === 'POST') {
      if (upload) return upload()
      const bytes = new Uint8Array(await init.body.get('file').arrayBuffer())
      state.objects.set(init.body.get('key'), bytes)
      return new Response(null, { status: 204 })
    }
    if (origin === S3) return new Response(state.objects.get(pathname.slice(1)))

    switch (pathname.replace('/v1', '')) {
      case '/public-key':
        return json(200, { keys })
      case '/generate-upload-url': {
        const key = `obj${++state.uploads}.enc`
        return json(200, { url: `${S3}/`, fields: { key, 'Content-Type': 'x' }, key })
      }
      case '/store-encrypted-key': {
        const body = JSON.parse(init.body)
        if (store) return store(body)
        state.links.set('L1', body)
        return json(200, { linkId: 'L1', expiresAt: 0 })
      }
      case '/me/inventory':
        return json(200, { inbound: EMPTY, outbound: { ...EMPTY, awaitingUpload } })
      case '/create-invite': {
        const body = JSON.parse(init.body)
        if (invite) return invite(body)
        state.invites.push(body)
        return json(200, { message: 'Invite created' })
      }
      case '/link-info': {
        const link = state.links.get(searchParams.get('linkId'))
        return link ? json(200, { linkId: 'L1', files: link.files }) : json(404, { linkId: null })
      }
      case '/generate-download-url':
        return json(200, { url: `${S3}/${searchParams.get('k')}?signed` })
      default:
        return json(404, {})
    }
  }

  const client = createClient({ apiBase: API, dir: join(root, 'state'), accessToken: 'A1', fetch })
  return { state, fetch, client }
}

const recipientKey = async () => {
  const { publicKey, privateKey } = await generateKeyPair({ extractable: false })
  return { keyId: 'K1', publicKey, privateKey }
}

const file = async (name, contents) => {
  const path = join(root, name)
  await writeFile(path, contents)
  return path
}

const send = (api, paths, extra = {}) =>
  sendDocument({
    client: api.client,
    fetch: api.fetch,
    senderName: 'Ada Lovelace',
    paths,
    recipient: { name: 'Grace Hopper', email: 'grace@example.test' },
    home: root,
    ...extra
  })

const read = (api, key, extra = {}) =>
  readDocument({
    client: api.client,
    fetch: api.fetch,
    keyId: key.keyId,
    privateKey: key.privateKey,
    linkId: 'L1',
    directory: join(root, 'out'),
    webOrigin: WEB,
    ...extra
  })

describe('send and read', () => {
  it('round-trips files through the server as ciphertext only', async () => {
    const key = await recipientKey()
    const api = backend({ keys: [{ keyId: key.keyId, publicKey: key.publicKey }] })
    const paths = [await file('a.pdf', 'first file'), await file('b.txt', 'second file')]

    const sent = await send(api, paths, { expirySecs: 3600 })

    expect(sent).toMatchObject({
      ok: true,
      data: {
        status: 'sent',
        linkId: 'L1',
        files: ['a.pdf', 'b.txt'],
        expiresAt: '1970-01-01T00:00:00.000Z'
      }
    })
    const stored = api.state.links.get('L1')
    expect(stored).toMatchObject({
      sender: { name: 'Ada Lovelace' },
      recipient: { name: 'Grace Hopper', email: 'grace@example.test' },
      expirySecs: 3600
    })
    expect(stored.files.map((f) => f.url)).toEqual([`${S3}/obj1.enc`, `${S3}/obj2.enc`])
    expect(stored.files[0].wrappedKeys.map((w) => w.keyId)).toEqual(['K1'])
    expect(new TextDecoder().decode(api.state.objects.get('obj1.enc'))).not.toMatch(/first/)

    const opened = await read(api, key)

    expect(opened.data.files).toEqual([
      { name: 'a.pdf', path: join(root, 'out', 'a.pdf'), size: 10 },
      { name: 'b.txt', path: join(root, 'out', 'b.txt'), size: 11 }
    ])
    expect(await readFile(join(root, 'out', 'a.pdf'), 'utf8')).toBe('first file')
    expect((await stat(join(root, 'out', 'b.txt'))).mode & 0o777).toBe(0o600)
    expect((await stat(join(root, 'out'))).mode & 0o777).toBe(0o700)
  })
})

describe('readDocument', () => {
  const seeded = async (files) => {
    const key = await recipientKey()
    const api = backend({ keys: [{ keyId: key.keyId, publicKey: key.publicKey }] })
    await send(api, [await file('a.pdf', 'contents')])
    const link = api.state.links.get('L1')
    link.files = files(link.files[0])
    return { api, key }
  }

  it('says to use the browser for a document sent before the agent was paired', async () => {
    const { api, key } = await seeded((f) => [
      { ...f, wrappedKeys: [{ ...f.wrappedKeys[0], keyId: 'K0' }] }
    ])

    await expect(read(api, key)).rejects.toThrow(`${WEB}/v/L1`)
    await expect(stat(join(root, 'out'))).rejects.toThrow()
  })

  it('never overwrites an existing file', async () => {
    const { api, key } = await seeded((f) => [f])
    await read(api, key)

    await expect(read(api, key)).rejects.toThrow(/a\.pdf already exists/)
  })

  it('keeps only the base name of a file', async () => {
    const { api, key } = await seeded((f) => [{ ...f, name: '../../escape.pdf' }])

    const opened = await read(api, key)

    expect(opened.data.files[0].path).toBe(join(root, 'out', 'escape.pdf'))
  })

  it('refuses a name with no base name, or two files with one name', async () => {
    const dots = await seeded((f) => [{ ...f, name: '..' }])
    await expect(read(dots.api, dots.key)).rejects.toThrow(DocumentError)

    const twins = await seeded((f) => [f, { ...f, name: 'x/a.pdf' }])
    await expect(read(twins.api, twins.key)).rejects.toThrow(/two files named "a\.pdf"/)
  })

  it('reports a link that is not there', async () => {
    const key = await recipientKey()

    await expect(read(backend(), key)).rejects.toThrow('No document L1 was sent to you')
  })
})

const recipient = { keyId: 'K1', publicKey: (await recipientKey()).publicKey }

describe('sendDocument', () => {
  it('invites a recipient with no key, uploading nothing', async () => {
    const api = backend()

    const result = await send(api, [await file('a.pdf', 'x')], { expirySecs: 3600 })

    expect(result).toMatchObject({ ok: true, data: { status: 'invited', files: ['a.pdf'] } })
    expect(api.state.invites).toEqual([
      {
        sender: { name: 'Ada Lovelace' },
        recipient: { name: 'Grace Hopper', email: 'grace@example.test' },
        files: [{ name: 'a.pdf' }],
        expirySecs: 3600
      }
    ])
    expect(api.state.uploads).toBe(0)
  })

  it("returns the server's deny of an invite", async () => {
    const api = backend({
      invite: () => json(403, { error: 'Invite already pending', code: 'INVITE_ALREADY_PENDING' })
    })

    expect(await send(api, [await file('a.pdf', 'x')])).toEqual({
      ok: false,
      reason: 'Invite already pending'
    })
  })

  it('completes an accepted invite with the same file names', async () => {
    const api = backend({
      keys: [recipient],
      awaitingUpload: [
        { inviteId: 'I1', recipientEmail: 'Grace@Example.test', fileNames: ['b.txt', 'a.pdf'] }
      ]
    })

    const result = await send(api, [await file('a.pdf', 'x'), await file('b.txt', 'y')])

    expect(result.data).toMatchObject({
      status: 'sent',
      linkId: 'L1',
      completedInvite: 'I1',
      expiresAt: '1970-01-01T00:00:00.000Z'
    })
    expect(api.state.links.get('L1').inviteId).toBe('I1')
    expect(api.state.links.get('L1').expirySecs).toBeUndefined()
  })

  it('refuses to complete an accepted invite with other file names', async () => {
    const api = backend({
      keys: [recipient],
      awaitingUpload: [
        { inviteId: 'I1', recipientEmail: 'grace@example.test', fileNames: ['a.pdf'] }
      ]
    })

    const result = await send(api, [await file('c.pdf', 'x')])

    expect(result).toEqual({
      ok: false,
      reason:
        'grace@example.test accepted your invite for "a.pdf". Send files with exactly those names to complete it.'
    })
    expect(api.state.uploads).toBe(0)
  })

  it('expands ~ and refuses a relative path, a missing file and an empty one', async () => {
    const api = backend({ keys: [recipient] })
    await file('a.pdf', 'x')
    await file('empty.pdf', '')

    expect((await send(api, ['~/a.pdf'])).ok).toBe(true)
    await expect(send(api, ['a.pdf'])).rejects.toThrow('a.pdf is not an absolute path')
    await expect(send(api, [join(root, 'nope.pdf')])).rejects.toThrow(/is not a file/)
    await expect(send(api, [join(root, 'empty.pdf')])).rejects.toThrow(/is empty/)
  })

  it('refuses a recipient name or file name the server would refuse', async () => {
    const api = backend({ keys: [recipient] })

    await expect(
      send(api, [await file('a.pdf', 'x')], { recipient: { name: 'G', email: 'g@example.test' } })
    ).rejects.toThrow(/recipient's name/)
    await expect(send(api, [await file('<b>.pdf', 'x')])).rejects.toThrow(/cannot be sent/)
    expect(api.state.uploads).toBe(0)
  })

  it("returns the server's deny with its reason", async () => {
    const api = backend({
      keys: [recipient],
      store: () => json(403, { error: 'Expiry exceeds your plan', code: 'EXPIRY', enforced: true })
    })

    expect(await send(api, [await file('a.pdf', 'x')])).toEqual({
      ok: false,
      reason: 'Expiry exceeds your plan'
    })
  })

  it('reports a file over the plan size as a deny', async () => {
    const api = backend({
      keys: [recipient],
      upload: () => new Response('<Code>EntityTooLarge</Code>', { status: 400 })
    })

    expect(await send(api, [await file('a.pdf', 'x')])).toEqual({
      ok: false,
      reason: '"a.pdf" exceeds the maximum file size on your plan'
    })
  })
})

describe('listDocuments', () => {
  const rows = { awaitingAcceptance: [], awaitingUpload: [], active: [{ expiresAt: 0 }] }

  it('filters to one direction and gives times in ISO 8601', async () => {
    const fetch = async () => json(200, { inbound: rows, outbound: rows })
    const client = createClient({ apiBase: API, dir: root, accessToken: 'A1', fetch })

    expect(await listDocuments({ client, direction: 'inbound' })).toEqual({
      ok: true,
      data: {
        inbound: { ...rows, active: [{ expiresAt: '1970-01-01T00:00:00.000Z' }] }
      }
    })
  })
})
