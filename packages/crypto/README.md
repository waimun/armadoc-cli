# @armadoc/crypto

The end-to-end encryption core of [Armadoc](https://armadoc.link), shared by the web app
and [`armadoc`](https://www.npmjs.com/package/armadoc). Runs anywhere `globalThis.crypto`
does: modern browsers and Node 24+.

- Each file is sealed under a fresh AES-256-GCM key; the payload is the 12-byte IV followed by the
  ciphertext.
- That key is wrapped with RSA-OAEP (SHA-256, 2048-bit) once per key the recipient has enrolled,
  and each wrap names its key.
- Opening picks the wrap made for a locally held key. A file sent before that key was enrolled has
  no such wrap, which reads as `PrivateKeyNotFoundError`, distinct from a `DecryptionError`.

The core holds no keys and does no I/O; storage and the network belong to the client.

```js
import {
  decryptPayload,
  generateKeyPair,
  importPublicKey,
  pickWrap,
  sealFile,
  unwrapFileKey
} from '@armadoc/crypto'
```
