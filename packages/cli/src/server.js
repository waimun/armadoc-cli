import { fromJsonSchema, McpServer } from '@modelcontextprotocol/server'
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio'
import pkg from '../package.json' with { type: 'json' }
import { createClient, PairingError, userAgent } from './api.js'
import { configDir, downloadDir, onStage, resolveStage } from './config.js'
import { DEFAULT_EXPIRY_SECS, listDocuments, readDocument, sendDocument } from './documents.js'
import { readCredentials, readPrivateKey } from './store.js'

const LINK_ID = '^[A-Za-z0-9]{1,64}$'

const text = (value) => ({
  content: [
    { type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }
  ]
})

const outcome = (result) => (result.ok ? text(result.data) : text(`Refused: ${result.reason}`))

const failure = (error) => {
  const cause = error.cause?.message
  return { ...text(cause ? `${error.message}: ${cause}` : error.message), isError: true }
}

export const createServer = (ctx) => {
  const { apiBase, webOrigin, stage } = resolveStage(ctx.env)
  const dir = configDir(ctx.env, stage, ctx.home)
  let client = null

  const session = async ({ needsKey = false } = {}) => {
    const credentials = await readCredentials(dir)
    if (!credentials?.refreshToken) {
      throw new PairingError(`Not logged in${onStage(stage, 'to')}; run \`armadoc login\``)
    }

    let privateKey = null
    if (needsKey) {
      privateKey = credentials.keyId ? await readPrivateKey(dir) : null
      if (!privateKey) throw new PairingError('No key is enrolled; run `armadoc login` to finish')
    }

    client ??= createClient({
      apiBase,
      dir,
      fetch: ctx.fetch,
      userAgent: userAgent(server.server.getClientVersion())
    })
    return { client, credentials, privateKey }
  }

  const handle = (operation) => async (args) => {
    try {
      return outcome(await operation(args))
    } catch (error) {
      return failure(error)
    }
  }

  const server = new McpServer({ name: 'armadoc', version: pkg.version })

  server.registerTool(
    'list_documents',
    {
      title: 'List documents',
      description:
        'Lists the Armadoc documents and invites still open on your account: inbound (sent to you) and outbound (sent by you). Times are ISO 8601.',
      inputSchema: fromJsonSchema({
        type: 'object',
        properties: {
          direction: {
            type: 'string',
            enum: ['inbound', 'outbound'],
            description: 'Only this direction; both when omitted'
          }
        }
      }),
      annotations: { readOnlyHint: true, openWorldHint: true }
    },
    handle(async ({ direction }) => {
      const { client } = await session()
      return listDocuments({ client, direction })
    })
  )

  server.registerTool(
    'read_document',
    {
      title: 'Read a document',
      description:
        'Decrypts a document sent to you and saves its files to disk. Returns the paths, names and sizes of the saved files, not their contents; read them from disk if needed. Never overwrites an existing file.',
      inputSchema: fromJsonSchema({
        type: 'object',
        properties: {
          linkId: {
            type: 'string',
            pattern: LINK_ID,
            description: 'The link id, the last segment of an armadoc.link/v/ URL'
          },
          directory: {
            type: 'string',
            description:
              'Absolute directory to save into; defaults to a per-link Armadoc download folder'
          }
        },
        required: ['linkId']
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }
    },
    handle(async ({ linkId, directory }) => {
      const target = downloadDir(ctx.env, { linkId, directory }, ctx.home)
      const { client, credentials, privateKey } = await session({ needsKey: true })
      return readDocument({
        client,
        fetch: ctx.fetch,
        keyId: credentials.keyId,
        privateKey,
        linkId,
        directory: target,
        webOrigin
      })
    })
  )

  server.registerTool(
    'send_document',
    {
      title: 'Send a document',
      description:
        'Encrypts local files on this machine and sends them to one recipient, as you. The recipient gets an email with a link. A recipient with no Armadoc key is emailed an invite instead and nothing is uploaded; once they accept, call this again with the same files to complete it.',
      inputSchema: fromJsonSchema({
        type: 'object',
        properties: {
          paths: {
            type: 'array',
            items: { type: 'string' },
            minItems: 1,
            description: 'Absolute paths of the files to send'
          },
          recipientName: { type: 'string', description: "The recipient's name" },
          recipientEmail: { type: 'string', description: "The recipient's email address" },
          expirySecs: {
            type: 'integer',
            exclusiveMinimum: 0,
            description: `How long the link stays open, in seconds; default ${DEFAULT_EXPIRY_SECS}`
          }
        },
        required: ['paths', 'recipientName', 'recipientEmail']
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }
    },
    handle(async ({ paths, recipientName, recipientEmail, expirySecs }) => {
      const { client, credentials } = await session()
      return sendDocument({
        client,
        fetch: ctx.fetch,
        senderName: credentials.senderName,
        paths,
        recipient: { name: recipientName.trim(), email: recipientEmail.trim() },
        expirySecs,
        home: ctx.home
      })
    })
  )

  return server
}

export const serve = async (ctx) => {
  await createServer(ctx).connect(new StdioServerTransport())
  return 0
}
