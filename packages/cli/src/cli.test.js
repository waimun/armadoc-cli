import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair } from '@armadoc/crypto'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import pkg from '../package.json' with { type: 'json' }
import { describeStatus, parseExpiry, parseLink, run } from './cli.js'
import { readCredentials, writeCredentials, writePrivateKey } from './store.js'

const API = 'https://api-dev.armadoc.link/v1'

let home
let dir

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), 'armadoc-cli-'))
  dir = join(home, '.config', 'armadoc', 'dev')
})

afterEach(() => rm(home, { recursive: true, force: true }))

const json = (status, body) => new Response(JSON.stringify(body), { status })

const context = ({ enroll = () => json(201, { keyId: 'K1' }), browser } = {}) => {
  const output = { out: [], err: [], opened: [], requests: [] }
  const ctx = {
    env: { ARMADOC_STAGE: 'dev' },
    home,
    cwd: home,
    hostname: 'mbp',
    interactive: true,
    prompt: async () => 'Ada Lovelace',
    pairingTimeoutMs: 2_000,
    out: (text) => output.out.push(text),
    err: (text) => output.err.push(text),
    openBrowser: (url) => {
      output.opened.push(url)
      const params = new URL(url).searchParams
      const answer = browser ?? ((state) => `code=C1&state=${state}`)
      fetch(`${params.get('redirect_uri')}?${answer(params.get('state'))}`)
    },
    fetch: async (url, init) => {
      output.requests.push({ url, ...init })
      if (url === `${API}/oauth/token`) {
        const grant = init.body.get('grant_type')
        return json(200, {
          access_token: grant === 'authorization_code' ? 'A1' : 'A2',
          refresh_token: grant === 'authorization_code' ? 'R1' : 'R2'
        })
      }
      if (url === `${API}/me/keys`) return enroll(JSON.parse(init.body))
      return json(404, {})
    }
  }
  return { ctx, output }
}

describe('login', () => {
  it('pairs, enrolls an agent key, and stores the key and credentials', async () => {
    const { ctx, output } = context()

    expect(await run(['login'], ctx)).toBe(0)

    const opened = new URL(output.opened[0])
    expect(opened.origin + opened.pathname).toBe('https://dev.armadoc.link/oauth/authorize/')
    expect(opened.searchParams.get('label')).toBe('armadoc CLI on mbp')

    const redeem = output.requests[0]
    expect(redeem.body.get('code')).toBe('C1')
    expect(redeem.body.get('redirect_uri')).toBe(opened.searchParams.get('redirect_uri'))

    const enroll = output.requests[1]
    expect(enroll.headers.Authorization).toBe('Bearer A1')
    expect(JSON.parse(enroll.body)).toMatchObject({
      label: 'armadoc CLI on mbp',
      holder: 'agent',
      publicKey: expect.stringMatching(/^-----BEGIN PUBLIC KEY-----/)
    })

    expect(await readCredentials(dir)).toMatchObject({
      label: 'armadoc CLI on mbp',
      senderName: 'Ada Lovelace',
      refreshToken: 'R1',
      keyId: 'K1'
    })
    expect(await readFile(join(dir, 'private-key.pem'), 'utf8')).toMatch(/BEGIN PRIVATE KEY/)
    expect(output.out.at(-1)).toMatch(/^Logged in to dev as "armadoc CLI on mbp"/)
  })

  it('names the CLI in the User-Agent of every request', async () => {
    const { ctx, output } = context()

    expect(await run(['login'], ctx)).toBe(0)

    expect(output.requests.map((request) => request.headers['User-Agent'])).toEqual([
      `armadoc-cli/${pkg.version} (cli)`,
      `armadoc-cli/${pkg.version} (cli)`
    ])
  })

  it('in a terminal, prints the URL and withdraws the prompt when another browser pairs', async () => {
    const { ctx, output } = context()
    let signal
    ctx.prompt = (_question, options) => {
      signal = options.signal
      const params = new URL(output.out[0].match(/https:\S+/)[0]).searchParams
      fetch(`${params.get('redirect_uri')}?code=C1&state=${params.get('state')}`)
      return new Promise((_resolve, reject) => signal.addEventListener('abort', reject))
    }

    expect(await run(['login', '--name', 'Ada'], ctx)).toBe(0)
    expect(output.out[0]).toMatch(/^Open this URL in a browser to pair:/)
    expect(signal.aborted).toBe(true)
    expect(output.opened).toHaveLength(0)
  })

  it('takes the label and name from flags', async () => {
    const { ctx, output } = context()
    ctx.interactive = false

    expect(await run(['login', '--label', ' Laptop ', '--name', 'Ada'], ctx)).toBe(0)

    expect(new URL(output.opened[0]).searchParams.get('label')).toBe('Laptop')
    expect(await readCredentials(dir)).toMatchObject({ label: 'Laptop', senderName: 'Ada' })
  })

  it('needs --name when it cannot ask', async () => {
    const { ctx, output } = context()
    ctx.interactive = false

    expect(await run(['login'], ctx)).toBe(1)
    expect(output.err[0]).toMatch(/--name/)
    expect(output.opened).toHaveLength(0)
  })

  it('refuses a name the server would refuse', async () => {
    const { ctx, output } = context()

    expect(await run(['login', '--name', 'A'], ctx)).toBe(1)
    expect(output.err[0]).toMatch(/--name must be/)
  })

  it('keeps the pairing when enrollment is denied, and resumes at enrollment', async () => {
    const denied = context({
      enroll: () => json(403, { error: 'Key limit reached', code: 'KEY_LIMIT', enforced: true })
    })

    expect(await run(['login'], denied.ctx)).toBe(1)
    expect(denied.output.err[0]).toMatch(/^Key limit reached\n/)
    expect(await readCredentials(dir)).toMatchObject({ refreshToken: 'R1' })
    expect((await readCredentials(dir)).keyId).toBeUndefined()

    const resumed = context()
    expect(await run(['login'], resumed.ctx)).toBe(0)
    expect(resumed.output.opened).toHaveLength(0)
    expect(resumed.output.requests.map((r) => r.url)).toEqual([
      `${API}/oauth/token`,
      `${API}/me/keys`
    ])
    expect(await readCredentials(dir)).toMatchObject({ refreshToken: 'R2', keyId: 'K1' })
  })

  it('writes nothing when the pairing is denied', async () => {
    const { ctx, output } = context({ browser: (state) => `error=access_denied&state=${state}` })

    expect(await run(['login'], ctx)).toBe(1)
    expect(output.err[0]).toBe('The pairing was denied in the browser')
    expect(await readCredentials(dir)).toBeNull()
  })

  it('says to run login again when the code expired before it was redeemed', async () => {
    const { ctx, output } = context()
    ctx.fetch = async () => json(400, { error: 'invalid_grant' })

    expect(await run(['login'], ctx)).toBe(1)
    expect(output.err[0]).toBe(
      'The pairing code expired before it reached this computer. Run `armadoc login` again.'
    )
    expect(await readCredentials(dir)).toBeNull()
  })

  it('refuses when already logged in', async () => {
    await writeCredentials(dir, { label: 'L', refreshToken: 'R1', keyId: 'K1' })
    await writePrivateKey(dir, (await generateKeyPair({ extractable: true })).privateKey)
    const { ctx, output } = context()

    expect(await run(['login'], ctx)).toBe(1)
    expect(output.err[0]).toMatch(/^Already logged in to dev/)
  })
})

describe('logout', () => {
  it('deletes the stage and says the agent stays on the account', async () => {
    await writeCredentials(dir, { label: 'Laptop', refreshToken: 'R1' })
    const { ctx, output } = context()

    expect(await run(['logout'], ctx)).toBe(0)
    expect(await readCredentials(dir)).toBeNull()
    expect(output.out[0]).toMatch(/"Laptop" stays on your account/)
    expect(output.out[0]).toMatch(/https:\/\/dev\.armadoc\.link\/settings\//)
  })
})

describe('status', () => {
  it('exits 1 when not logged in', async () => {
    const { ctx, output } = context()

    expect(await run(['status'], ctx)).toBe(1)
    expect(output.out[0]).toBe('Not logged in to dev. Run `armadoc login`.')
  })
})

describe('describeStatus', () => {
  const now = new Date('2026-10-03T00:00:00Z')
  const credentials = {
    label: 'Laptop',
    senderName: 'Ada',
    keyId: 'K1',
    refreshExpiresAt: '2026-11-02T00:00:00.000Z'
  }

  it('shows the agent, sender, key and when the pairing lapses', () => {
    expect(describeStatus({ stage: 'prod', credentials, hasKey: true, now })).toBe(
      [
        'Agent:  Laptop',
        'Sender: Ada',
        'Key:    enrolled',
        'Pairing lapses 2026-11-02 if unused'
      ].join('\n')
    )
  })

  it('names a stage other than prod', () => {
    expect(describeStatus({ stage: 'dev', credentials, hasKey: true, now })).toMatch(
      /^Stage: {2}dev\n/
    )
  })

  it('says when the key is missing or the pairing has lapsed', () => {
    const text = describeStatus({
      stage: 'prod',
      credentials,
      hasKey: false,
      now: new Date('2026-12-01T00:00:00Z')
    })

    expect(text).toMatch(/Key: {4}not enrolled/)
    expect(text).toMatch(/Pairing lapsed 2026-11-02/)
  })
})

describe('run', () => {
  it('prints the version', async () => {
    const { ctx, output } = context()

    expect(await run(['--version'], ctx)).toBe(0)
    expect(output.out).toEqual([pkg.version])
  })

  it('prints usage with no command', async () => {
    const { ctx, output } = context()

    expect(await run([], ctx)).toBe(1)
    expect(output.err[0]).toMatch(/^Usage:/)
  })

  it('prints usage for an unknown command', async () => {
    const { ctx, output } = context()

    expect(await run(['nope'], ctx)).toBe(1)
    expect(output.err[0]).toMatch(/^Usage:/)
  })
})

const S3 = 'https://bucket.s3.example.test'
const EMPTY = { awaitingAcceptance: [], awaitingUpload: [], active: [] }
const EXPIRES_AT = 1_792_245_900
const INBOUND = [{ linkId: 'L1', senderName: 'Ada', fileNames: ['a.txt'], expiresAt: EXPIRES_AT }]

const documents = async ({ store } = {}) => {
  const { publicKey, privateKey } = await generateKeyPair({ extractable: true })
  await writeCredentials(dir, {
    label: 'L',
    senderName: 'Ada Lovelace',
    refreshToken: 'R1',
    keyId: 'K1'
  })
  await writePrivateKey(dir, privateKey)

  const objects = new Map()
  let link = null
  const { ctx, output } = context()
  ctx.fetch = async (url, init = {}) => {
    output.requests.push({ url, ...init })
    const { origin, pathname, searchParams } = new URL(url)

    if (origin === S3 && init.method === 'POST') {
      objects.set(init.body.get('key'), new Uint8Array(await init.body.get('file').arrayBuffer()))
      return new Response(null, { status: 204 })
    }
    if (origin === S3) return new Response(objects.get(pathname.slice(1)))

    switch (pathname.replace('/v1', '')) {
      case '/oauth/token':
        return json(200, { access_token: 'A2', refresh_token: 'R2' })
      case '/me/inventory':
        return json(200, { inbound: { ...EMPTY, active: INBOUND }, outbound: EMPTY })
      case '/public-key':
        return json(200, { keys: [{ keyId: 'K1', publicKey }] })
      case '/generate-upload-url':
        return json(200, { url: `${S3}/`, fields: { key: 'obj1.enc' }, key: 'obj1.enc' })
      case '/store-encrypted-key':
        link = JSON.parse(init.body)
        return store ? store(link) : json(200, { linkId: 'L1', expiresAt: EXPIRES_AT })
      case '/link-info':
        return json(200, { linkId: 'L1', files: link.files })
      case '/generate-download-url':
        return json(200, { url: `${S3}/${searchParams.get('k')}` })
      default:
        return json(404, {})
    }
  }
  return { ctx, output, stored: () => link }
}

const SEND = ['send', 'a.txt', '--to', 'ada@example.test', '--to-name', 'Ada Lovelace']

describe('send and read', () => {
  it('sends a relative path and reads it back from a viewer link into a relative directory', async () => {
    await writeFile(join(home, 'a.txt'), 'hello')
    const { ctx, output, stored } = await documents()

    expect(await run([...SEND, '--expires', '3d'], ctx)).toBe(0)
    expect(stored().expirySecs).toBe(259_200)
    expect(output.out[0]).toBe(
      'Sent a.txt to Ada Lovelace <ada@example.test>, open until 2026-10-17 14:05 UTC.'
    )

    expect(await run(['read', 'https://dev.armadoc.link/v/L1', '--dir', 'out'], ctx)).toBe(0)
    expect(await readFile(join(home, 'out', 'a.txt'), 'utf8')).toBe('hello')
    expect(output.out[1]).toBe(`Saved to ${join(home, 'out')}:\n  a.txt (5 B)`)

    const api = output.requests.filter((request) => request.url.startsWith(API))
    expect(new Set(api.map((request) => request.headers['User-Agent']))).toEqual(
      new Set([`armadoc-cli/${pkg.version} (cli)`])
    )
  })

  it('prints a refusal on stderr and exits 1', async () => {
    await writeFile(join(home, 'a.txt'), 'hello')
    const { ctx, output } = await documents({
      store: () => json(403, { error: 'Expiry exceeds your plan', code: 'EXPIRY_EXCEEDED' })
    })

    expect(await run([...SEND, '--expires', '60d'], ctx)).toBe(1)
    expect(output.out).toEqual([])
    expect(output.err).toEqual(['Refused: Expiry exceeds your plan'])
  })

  it('prints the failed step and its cause', async () => {
    await writeFile(join(home, 'a.txt'), 'hello')
    const { ctx, output } = await documents()
    const respond = ctx.fetch
    ctx.fetch = (url, init) => {
      if (url.startsWith(S3)) {
        throw new TypeError('fetch failed', { cause: new Error('read ECONNRESET') })
      }
      return respond(url, init)
    }

    expect(await run(SEND, ctx)).toBe(1)
    expect(output.err).toEqual(['Uploading "a.txt" failed: read ECONNRESET'])
  })

  it('prints the result as JSON on request', async () => {
    await writeFile(join(home, 'a.txt'), 'hello')
    const { ctx, output } = await documents()

    expect(await run([...SEND, '--json'], ctx)).toBe(0)
    expect(JSON.parse(output.out[0])).toMatchObject({ status: 'sent', linkId: 'L1' })
  })

  it('needs the recipient', async () => {
    const { ctx, output } = context()

    expect(await run(['send', 'a.txt', '--to', 'ada@example.test'], ctx)).toBe(1)
    expect(output.err[0]).toMatch(/--to-name/)
  })

  it('prints usage for a read with no link or a send with no files', async () => {
    const { ctx, output } = context()

    expect(await run(['read'], ctx)).toBe(1)
    expect(await run(['read', 'L1', 'L2'], ctx)).toBe(1)
    expect(await run(['send', '--to', 'a@example.test', '--to-name', 'Ada'], ctx)).toBe(1)
    expect(output.err.every((text) => text.startsWith('Usage:'))).toBe(true)
  })
})

describe('list', () => {
  it('lists both directions, grouped by stage', async () => {
    const { ctx, output } = await documents()

    expect(await run(['list'], ctx)).toBe(0)
    expect(output.out[0]).toBe('Sent to you:\n  L1  from Ada: a.txt, until 2026-10-17 14:05 UTC')
  })

  it('answers to ls, and lists one direction as JSON', async () => {
    const { ctx, output } = await documents()

    expect(await run(['ls', '--inbound', '--json'], ctx)).toBe(0)
    expect(JSON.parse(output.out[0])).toEqual({
      inbound: {
        ...EMPTY,
        active: [{ ...INBOUND[0], expiresAt: '2026-10-17T14:05:00.000Z' }]
      }
    })
  })

  it('refuses a flag that belongs to another command', async () => {
    const { ctx, output } = context()

    expect(await run(['list', '--dir', 'out'], ctx)).toBe(1)
    expect(output.err[0]).toMatch(/--dir/)
  })
})

describe('parseLink', () => {
  const WEB = 'https://armadoc.link'

  it('takes a link id or a viewer link from this stage', () => {
    expect(parseLink('L1abc', WEB)).toBe('L1abc')
    expect(parseLink('https://armadoc.link/v/L1abc', WEB)).toBe('L1abc')
    expect(parseLink('https://armadoc.link/v/L1abc/', WEB)).toBe('L1abc')
    expect(parseLink('https://dev.armadoc.link/v/L1abc', 'https://dev.armadoc.link')).toBe('L1abc')
  })

  it('refuses a link from another stage or site, or to another page', () => {
    for (const link of [
      'https://dev.armadoc.link/v/L1abc',
      'https://example.test/v/L1abc',
      'https://armadoc.link/settings/',
      'https://armadoc.link/v/L1-abc',
      'L1/abc'
    ]) {
      expect(() => parseLink(link, WEB)).toThrow(
        /is not a document link from https:\/\/armadoc\.link/
      )
    }
  })
})

describe('parseExpiry', () => {
  it('reads days as seconds', () => {
    expect(parseExpiry('7d')).toBe(604_800)
    expect(parseExpiry('30d')).toBe(2_592_000)
    expect(parseExpiry(' 1d ')).toBe(86_400)
  })

  it('refuses anything else', () => {
    for (const value of ['0d', '1.5d', '7', '12h', '7w', '-1d', '']) {
      expect(() => parseExpiry(value)).toThrow(/--expires must be/)
    }
  })
})
