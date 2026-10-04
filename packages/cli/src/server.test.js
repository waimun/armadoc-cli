import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { afterEach, beforeEach, expect, it } from 'vitest'
import pkg from '../package.json' with { type: 'json' }
import { createServer } from './server.js'
import { writeCredentials } from './store.js'

const API = 'https://api-dev.armadoc.link/v1'

let home
let dir

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), 'armadoc-server-'))
  dir = join(home, '.config', 'armadoc', 'dev')
})

afterEach(() => rm(home, { recursive: true, force: true }))

const json = (status, body) => new Response(JSON.stringify(body), { status })

const connect = async (fetch = async () => json(404, {})) => {
  const server = createServer({ env: { ARMADOC_STAGE: 'dev' }, home, fetch })
  const client = new Client({ name: 'test', version: '0' })
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverSide), client.connect(clientSide)])
  return client
}

const textOf = (result) => result.content[0].text

it('offers the three document tools', async () => {
  const client = await connect()

  const { tools } = await client.listTools()

  expect(tools.map((tool) => tool.name)).toEqual([
    'list_documents',
    'read_document',
    'send_document'
  ])
})

it('says to log in when there are no credentials', async () => {
  const client = await connect()

  const result = await client.callTool({ name: 'list_documents', arguments: {} })

  expect(result.isError).toBe(true)
  expect(textOf(result)).toBe('Not logged in to dev; run `armadoc login`')
})

it('says to finish login when reading without an enrolled key', async () => {
  await writeCredentials(dir, { label: 'L', refreshToken: 'R1' })
  const client = await connect()

  const result = await client.callTool({ name: 'read_document', arguments: { linkId: 'L1' } })

  expect(result.isError).toBe(true)
  expect(textOf(result)).toMatch(/No key is enrolled/)
})

it('refreshes, then answers with the result', async () => {
  await writeCredentials(dir, { label: 'L', refreshToken: 'R1' })
  const empty = { awaitingAcceptance: [], awaitingUpload: [], active: [] }
  const client = await connect(async (url) =>
    url === `${API}/oauth/token`
      ? json(200, { access_token: 'A2', refresh_token: 'R2' })
      : json(200, { inbound: empty, outbound: empty })
  )

  const result = await client.callTool({
    name: 'list_documents',
    arguments: { direction: 'outbound' }
  })

  expect(result.isError).toBeFalsy()
  expect(JSON.parse(textOf(result))).toEqual({ outbound: empty })
})

it('returns a deny as a result, not an error', async () => {
  await writeCredentials(dir, { label: 'L', refreshToken: 'R1' })
  const client = await connect(async (url) =>
    url === `${API}/oauth/token`
      ? json(200, { access_token: 'A2', refresh_token: 'R2' })
      : json(403, { error: 'Not allowed', code: 'NOPE', enforced: true })
  )

  const result = await client.callTool({ name: 'list_documents', arguments: {} })

  expect(result.isError).toBeFalsy()
  expect(textOf(result)).toBe('Refused: Not allowed')
})

it('names the MCP host in the User-Agent of every request', async () => {
  await writeCredentials(dir, { label: 'L', refreshToken: 'R1' })
  const agents = []
  const empty = { awaitingAcceptance: [], awaitingUpload: [], active: [] }
  const client = await connect(async (url, init) => {
    agents.push(init.headers['User-Agent'])
    return url === `${API}/oauth/token`
      ? json(200, { access_token: 'A2', refresh_token: 'R2' })
      : json(200, { inbound: empty, outbound: empty })
  })

  await client.callTool({ name: 'list_documents', arguments: {} })

  expect(agents).toEqual([
    `armadoc-cli/${pkg.version} (mcp; test/0)`,
    `armadoc-cli/${pkg.version} (mcp; test/0)`
  ])
})
