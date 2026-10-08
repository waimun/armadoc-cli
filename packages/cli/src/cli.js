import { spawn } from 'node:child_process'
import { homedir, hostname } from 'node:os'
import { resolve } from 'node:path'
import { createInterface } from 'node:readline/promises'
import { parseArgs } from 'node:util'
import { generateKeyPair } from '@armadoc/crypto'
import pkg from '../package.json' with { type: 'json' }
import { CLI_USER_AGENT, createClient, PairingError, redeemCode, TokenError } from './api.js'
import { configDir, downloadDir, expandHome, onStage, resolveStage } from './config.js'
import { listDocuments, readDocument, sendDocument } from './documents.js'
import { describeList, describeRead, describeSend } from './format.js'
import {
  authorizeUrl,
  createPkce,
  createState,
  defaultLabel,
  listenForCallback,
  MAX_LABEL_LENGTH
} from './pairing.js'
import { serve } from './server.js'
import { createSession } from './session.js'
import {
  clearStage,
  readCredentials,
  readPrivateKey,
  withRefreshLock,
  writeCredentials,
  writePrivateKey
} from './store.js'

const NAME_PATTERN = /^[A-Za-z\s'-]{2,50}$/
const NAME_RULE = "2 to 50 characters: letters, spaces, ' and -"
const LINK_ID = /^[A-Za-z0-9]{1,64}$/
const VIEWER_PATH = /^\/v\/([A-Za-z0-9]{1,64})\/?$/
const EXPIRY = /^([1-9]\d*)d$/
const DAY_SECS = 86_400

const USAGE = `Usage:
  armadoc login [--label <label>] [--name <name>]  Pair this machine and enroll a key
  armadoc logout                                   Delete the local credentials
  armadoc status                                   Show the pairing
  armadoc list|ls [--inbound|--outbound] [--json]  List the documents still open
  armadoc read <link> [--dir <dir>] [--json]       Decrypt a document and save its files
  armadoc send <file>... --to <email> --to-name <name> [--expires <days>d] [--json]
                                                   Encrypt files and send them to one recipient
  armadoc mcp                                      Run the MCP server, for an MCP host to start`

export class UsageError extends Error {}

export const parseLink = (link, webOrigin) => {
  if (LINK_ID.test(link)) return link
  const url = URL.parse(link)
  const linkId = url?.origin === webOrigin ? url.pathname.match(VIEWER_PATH)?.[1] : undefined
  if (!linkId) throw new UsageError(`${link} is not a document link from ${webOrigin}`)
  return linkId
}

export const parseExpiry = (value) => {
  const match = EXPIRY.exec(value.trim())
  if (!match) throw new UsageError('--expires must be a number of days, like 7d')
  return Number(match[1]) * DAY_SECS
}

const checkLabel = (label) => {
  const trimmed = label.trim()
  if (!trimmed || trimmed.length > MAX_LABEL_LENGTH) {
    throw new UsageError(`--label must be 1 to ${MAX_LABEL_LENGTH} characters`)
  }
  return trimmed
}

const checkName = (name) => {
  const trimmed = name.trim()
  if (!NAME_PATTERN.test(trimmed)) throw new UsageError(`--name must be ${NAME_RULE}`)
  return trimmed
}

const askName = async (ctx) => {
  if (!ctx.interactive) throw new UsageError('Pass --name with the name recipients will see')
  for (;;) {
    const name = (await ctx.prompt('Your name, as recipients will see it: ')).trim()
    if (NAME_PATTERN.test(name)) return name
    ctx.err(`The name must be ${NAME_RULE}.`)
  }
}

const locate = (ctx) => {
  const { stage, apiBase, webOrigin } = resolveStage(ctx.env)
  return { stage, apiBase, webOrigin, dir: configDir(ctx.env, stage, ctx.home) }
}

const offerToOpen = (ctx, url, callbackCode) => {
  const abort = new AbortController()
  const withdraw = () => abort.abort()
  callbackCode.then(withdraw, withdraw)
  ctx.prompt('', { signal: abort.signal }).then(
    () => ctx.openBrowser(url),
    () => {}
  )
}

const pair = async (ctx, { apiBase, webOrigin, label }) => {
  const { verifier, challenge } = createPkce()
  const state = createState()
  const callback = await listenForCallback(state, { timeoutMs: ctx.pairingTimeoutMs })
  const url = authorizeUrl({
    webOrigin,
    redirectUri: callback.redirectUri,
    challenge,
    state,
    label
  })

  if (ctx.interactive) {
    ctx.out(
      `Open this URL in a browser to pair:\n\n  ${url}\n\nOr press Enter to open your default browser.`
    )
    offerToOpen(ctx, url, callback.code)
  } else {
    ctx.out(`Opening the browser to pair. If it does not open, visit:\n\n  ${url}\n`)
    ctx.openBrowser(url)
  }

  const code = await callback.code
  try {
    return await redeemCode({
      apiBase,
      code,
      verifier,
      redirectUri: callback.redirectUri,
      fetch: ctx.fetch,
      userAgent: CLI_USER_AGENT
    })
  } catch (error) {
    if (error instanceof TokenError && error.error === 'invalid_grant') {
      throw new PairingError(
        'The pairing code expired before it reached this computer. Run `armadoc login` again.'
      )
    }
    throw error
  }
}

const login = async (ctx, options) => {
  const { stage, apiBase, webOrigin, dir } = locate(ctx)
  let credentials = await readCredentials(dir)

  if (credentials?.keyId && (await readPrivateKey(dir))) {
    throw new UsageError(
      `Already logged in${onStage(stage, 'to')} as "${credentials.label}". Run \`armadoc logout\` first.`
    )
  }

  const label = options.label === undefined ? undefined : checkLabel(options.label)
  const senderName = options.name === undefined ? undefined : checkName(options.name)
  const { publicKey, privateKey } = await generateKeyPair({ extractable: true })
  let accessToken = null

  if (credentials?.refreshToken) {
    ctx.out(`Resuming "${credentials.label}" at key enrollment.`)
  } else {
    const agentLabel = label ?? defaultLabel(ctx.hostname)
    const name = senderName ?? (await askName(ctx))
    const tokens = await pair(ctx, { apiBase, webOrigin, label: agentLabel })
    credentials = {
      label: agentLabel,
      senderName: name,
      refreshToken: tokens.refreshToken,
      refreshExpiresAt: tokens.refreshExpiresAt
    }
    await writeCredentials(dir, credentials)
    accessToken = tokens.accessToken
  }

  const client = createClient({
    apiBase,
    dir,
    accessToken,
    fetch: ctx.fetch,
    userAgent: CLI_USER_AGENT
  })
  const enrolled = await client.post('/me/keys', {
    publicKey,
    label: credentials.label,
    holder: 'agent'
  })

  if (!enrolled.ok) {
    ctx.err(
      `${enrolled.reason}\nPaired, but no key was enrolled. Remove a key at ${webOrigin}/settings/, then run \`armadoc login\` again.`
    )
    return 1
  }

  await writePrivateKey(dir, privateKey)
  await withRefreshLock(dir, (current) =>
    writeCredentials(dir, {
      ...current,
      ...(senderName ? { senderName } : {}),
      keyId: enrolled.data.keyId
    })
  )

  ctx.out(
    `Logged in${onStage(stage, 'to')} as "${credentials.label}".\nThis key opens only what is sent to you from now on. Anything sent earlier still opens wherever you read it before.`
  )
  return 0
}

const logout = async (ctx) => {
  const { stage, webOrigin, dir } = locate(ctx)
  const credentials = await readCredentials(dir)
  await clearStage(dir)

  if (!credentials) {
    ctx.out(`Not logged in${onStage(stage, 'to')}.`)
    return 0
  }

  ctx.out(
    `Logged out${onStage(stage, 'of')}. "${credentials.label}" stays on your account until you remove it at ${webOrigin}/settings/.`
  )
  return 0
}

export const describeStatus = ({ stage, credentials, hasKey, now = new Date() }) => {
  if (!credentials) return `Not logged in${onStage(stage, 'to')}. Run \`armadoc login\`.`

  const lapses = credentials.refreshExpiresAt && new Date(credentials.refreshExpiresAt)
  const lines = [
    ...(stage === 'prod' ? [] : [`Stage:  ${stage}`]),
    `Agent:  ${credentials.label}`,
    `Sender: ${credentials.senderName ?? '(not set)'}`,
    `Key:    ${credentials.keyId && hasKey ? 'enrolled' : 'not enrolled; run `armadoc login` to finish'}`
  ]
  if (lapses) {
    const date = lapses.toISOString().slice(0, 10)
    lines.push(
      lapses > now
        ? `Pairing lapses ${date} if unused`
        : `Pairing lapsed ${date}; run \`armadoc logout\`, then \`armadoc login\``
    )
  }
  return lines.join('\n')
}

const status = async (ctx) => {
  const { stage, dir } = locate(ctx)
  const credentials = await readCredentials(dir)
  const hasKey = (await readPrivateKey(dir)) !== null
  ctx.out(describeStatus({ stage, credentials, hasKey }))
  return credentials ? 0 : 1
}

const connect = (ctx) => {
  const { stage, apiBase, webOrigin, dir } = locate(ctx)
  const session = createSession({
    apiBase,
    stage,
    dir,
    fetch: ctx.fetch,
    userAgent: () => CLI_USER_AGENT
  })
  return { webOrigin, session }
}

const report = (ctx, options, result, describe) => {
  if (!result.ok) {
    ctx.err(`Refused: ${result.reason}`)
    return 1
  }
  ctx.out(options.json ? JSON.stringify(result.data, null, 2) : describe(result.data))
  return 0
}

const fromCwd = (ctx, path) => resolve(ctx.cwd, expandHome(path, ctx.home))

const list = async (ctx, options) => {
  const chosen = ['inbound', 'outbound'].filter((direction) => options[direction])
  const direction = chosen.length === 1 ? chosen[0] : undefined
  const { session } = connect(ctx)
  const { client } = await session()
  return report(ctx, options, await listDocuments({ client, direction }), describeList)
}

const read = async (ctx, options, [link]) => {
  const { webOrigin, session } = connect(ctx)
  const linkId = parseLink(link, webOrigin)
  const directory = downloadDir(
    ctx.env,
    { linkId, directory: options.dir === undefined ? undefined : fromCwd(ctx, options.dir) },
    ctx.home
  )
  const { client, credentials, privateKey } = await session({ needsKey: true })
  const result = await readDocument({
    client,
    fetch: ctx.fetch,
    keyId: credentials.keyId,
    privateKey,
    linkId,
    directory,
    webOrigin
  })
  return report(ctx, options, result, describeRead)
}

const send = async (ctx, options, paths) => {
  if (!options.to || !options['to-name']) {
    throw new UsageError("Pass --to with the recipient's email and --to-name with their name")
  }
  const expirySecs = options.expires === undefined ? undefined : parseExpiry(options.expires)
  const { session } = connect(ctx)
  const { client, credentials } = await session()
  const result = await sendDocument({
    client,
    fetch: ctx.fetch,
    senderName: credentials.senderName,
    paths: paths.map((path) => fromCwd(ctx, path)),
    recipient: { name: options['to-name'].trim(), email: options.to.trim() },
    expirySecs,
    home: ctx.home
  })
  return report(ctx, options, result, describeSend)
}

const STRING = { type: 'string' }
const FLAG = { type: 'boolean' }

const LIST = { run: list, options: { inbound: FLAG, outbound: FLAG, json: FLAG } }

const COMMANDS = {
  login: { run: login, options: { label: STRING, name: STRING } },
  logout: { run: logout },
  status: { run: status },
  list: LIST,
  ls: LIST,
  read: { run: read, options: { dir: STRING, json: FLAG }, args: [1, 1] },
  send: {
    run: send,
    options: { to: STRING, 'to-name': STRING, expires: STRING, json: FLAG },
    args: [1, Number.POSITIVE_INFINITY]
  },
  mcp: { run: serve }
}

export const run = async (argv, ctx) => {
  try {
    const command = Object.hasOwn(COMMANDS, argv[0]) ? COMMANDS[argv[0]] : null
    const { values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        ...command?.options,
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' }
      }
    })

    if (values.version) {
      ctx.out(pkg.version)
      return 0
    }
    if (values.help) {
      ctx.out(USAGE)
      return 0
    }

    const args = positionals.slice(1)
    const [min, max] = command?.args ?? [0, 0]
    if (!command || args.length < min || args.length > max) {
      ctx.err(USAGE)
      return 1
    }

    return await command.run(ctx, values, args)
  } catch (error) {
    const cause = error.cause?.message
    ctx.err(cause ? `${error.message}: ${cause}` : error.message)
    return 1
  }
}

const openBrowser = (url) => {
  const opener = {
    darwin: ['open'],
    win32: ['rundll32', 'url.dll,FileProtocolHandler']
  }[process.platform] ?? ['xdg-open']
  const [command, ...args] = opener
  const child = spawn(command, [...args, url], { stdio: 'ignore', detached: true })
  child.on('error', () => {})
  child.unref()
}

const prompt = async (question, { signal } = {}) => {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  // readline swallows Ctrl-C while it reads.
  rl.on('SIGINT', () => {
    rl.close()
    process.kill(process.pid, 'SIGINT')
  })
  try {
    return await rl.question(question, { signal })
  } finally {
    rl.close()
  }
}

export const main = async () => {
  process.exitCode = await run(process.argv.slice(2), {
    env: process.env,
    home: homedir(),
    cwd: process.cwd(),
    hostname: hostname(),
    fetch: globalThis.fetch,
    interactive: Boolean(process.stdin.isTTY),
    prompt,
    openBrowser,
    out: (text) => process.stdout.write(`${text}\n`),
    err: (text) => process.stderr.write(`${text}\n`)
  })
}
