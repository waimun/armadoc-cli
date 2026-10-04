import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair } from '@armadoc/crypto'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import pkg from '../package.json' with { type: 'json' }
import { describeStatus, run } from './cli.js'
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
