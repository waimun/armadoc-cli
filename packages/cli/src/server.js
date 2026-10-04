import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import pkg from '../package.json' with { type: 'json' }
import { createClient, PairingError, userAgent } from './api.js'
import { configDir, downloadDir, onStage, resolveStage } from './config.js'
import { DEFAULT_EXPIRY_SECS, listDocuments, readDocument, sendDocument } from './documents.js'
import { readCredentials, readPrivateKey } from './store.js'

const LINK_ID = /^[A-Za-z0-9]{1,64}$/

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
      inputSchema: {
        direction: z
          .enum(['inbound', 'outbound'])
          .optional()
          .describe('Only this direction; both when omitted')
      },
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
      inputSchema: {
        linkId: z
          .string()
          .regex(LINK_ID)
          .describe('The link id, the last segment of an armadoc.link/v/ URL'),
        directory: z
          .string()
          .optional()
          .describe(
            'Absolute directory to save into; defaults to a per-link Armadoc download folder'
          )
      },
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
      inputSchema: {
        paths: z.array(z.string()).min(1).describe('Absolute paths of the files to send'),
        recipientName: z.string().describe("The recipient's name"),
        recipientEmail: z.string().describe("The recipient's email address"),
        expirySecs: z
          .number()
          .int()
          .positive()
          .optional()
          .describe(`How long the link stays open, in seconds; default ${DEFAULT_EXPIRY_SECS}`)
      },
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
