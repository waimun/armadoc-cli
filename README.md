# armadoc-cli

The local client for [Armadoc](https://armadoc.link) end-to-end encrypted document sharing: an
`armadoc` CLI and a stdio MCP server that send and read documents as you, from a terminal or an AI
agent on your machine. Decryption needs the private key and encryption needs the plaintext, so both
stay on your machine; the server only ever sees ciphertext.

| Package                              | Contents                                            |
|--------------------------------------|-----------------------------------------------------|
| [`armadoc`](packages/cli)            | The CLI and MCP server                              |
| [`@armadoc/crypto`](packages/crypto) | The encryption core, shared with the web app        |

The canonical package is `armadoc`. Every release is published from this repository's
`publish.yml` workflow with npm provenance.
