# armadoc

The `armadoc` CLI and a local stdio MCP server for [Armadoc](https://armadoc.link) end-to-end
encrypted document sharing. Send and read documents from a terminal, or let your agent do it as
you; the private key and the plaintext never leave your machine.

## Install

```sh
npm install -g armadoc
```

Node 24 or later. Or, without a global install, prefix each command with `npx`.

## Pair

```sh
armadoc login
```

This pairs this machine with your Armadoc account in a browser and enrolls a key for it. The key
opens only what is sent to you after pairing; anything sent earlier still opens wherever you read
it before.

`armadoc status` shows the pairing.

## Send and read

```sh
armadoc send report.pdf notes.txt --to dustin@example.com --to-name "Dustin Burrows"
armadoc ls
armadoc read https://armadoc.link/v/<linkId>
```

`send` encrypts the files on this machine and sends them to one recipient, under the name you gave
at login. A recipient with no Armadoc key yet is emailed an invite instead and nothing is uploaded;
once they accept, run the same `send` again to complete it. `--expires 7d` sets how many days the
link stays open, within your plan.

`ls`, or `list`, shows what is still open in both directions; `--inbound` or `--outbound` narrows
it. `read` takes the link from the email or just its id, and saves the files to
`~/Downloads/armadoc/<linkId>`, or to `--dir`. It never overwrites a file.

`list`, `read` and `send` take `--json` for output a script can parse. A refusal, such as a plan
limit, goes to stderr with exit code 1.

## Use from an agent

Claude Code:

```sh
claude mcp add --scope user armadoc -- armadoc mcp
```

Codex:

```sh
codex mcp add armadoc -- armadoc mcp
```

Any other host: the server is `armadoc mcp`, over stdio. Restart or reconnect the host to load it.

Requests say whether a command or the MCP server made them, and the server's include the name and
version your MCP host reports for itself, so Armadoc can see how the client is used.

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
