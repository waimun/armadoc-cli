# armadoc

The `armadoc` CLI and a local stdio MCP server for [Armadoc](https://armadoc.link) end-to-end
encrypted document sharing. Your agent sends and reads documents as you; the private key and the
plaintext never leave your machine.

## Install

```sh
npm install -g armadoc
```

Node 24 or later, and an MCP host to run it. On its own, the CLI only pairs this machine; to send
and read documents yourself, use [armadoc.link](https://armadoc.link).

## Pair

```sh
armadoc login
```

This pairs this machine with your Armadoc account in a browser and enrolls a key for it. The key
opens only what is sent to you after pairing; anything sent earlier still opens wherever you read
it before.

`armadoc status` shows the pairing.

## Add to an MCP host

Claude Code:

```sh
claude mcp add --scope user armadoc -- armadoc mcp
```

Codex:

```sh
codex mcp add armadoc -- armadoc mcp
```

Any other host: the server is `armadoc mcp`, over stdio. Restart or reconnect the host to load it.

Requests from the server include the name and version your MCP host reports for itself, so Armadoc
can see which hosts are in use.

The server has to run on your own computer, next to your MCP host. It won't work in cloud-hosted
agents, because `armadoc login` needs a browser on the same machine. Even if it could pair there,
your private key and the documents you read would sit on the provider's machines, possibly after
the session ends.

## Tools

| Tool             | Does                                                                           |
|------------------|--------------------------------------------------------------------------------|
| `list_documents` | Lists documents sent to you and by you                                         |
| `read_document`  | Decrypts a document's files to disk, by default `~/Downloads/armadoc/<linkId>` |
| `send_document`  | Encrypts local files and sends them, or invites a recipient with no key yet    |

`read_document` returns file paths, not contents: what a document says enters the agent's context
only if the agent opens the file.

## Uninstall

```sh
armadoc logout
npm uninstall -g armadoc
```

`armadoc logout` deletes the private key and credentials in `~/.config/armadoc`. The agent stays on
your account until you remove it in settings, and documents it read stay in `~/Downloads/armadoc`.
