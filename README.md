# xmip-core-identify-certificate

Identify by certificate: reads the peer certificate's subject and issuer off the connection, unverified, with the chain riding as proof for the second gate. A technology of [xmip-core-identify](https://github.com/IlleNilsson/xmip-core-identify).

Where the transport's handshake proved the peer's chain (`tls.peer.verified`)
the claim is `mutual-tls`, proven by that word. Where the certificate merely
arrived the claim is `certificate`, and a chain alone proves nobody:
`authenticate/certificate` proves it only with the sender's signature over
this arrival, which no `tls.peer.*` property carries, so every
`certificate` claim read here is refused there until a transport reports
that possession (ADR-0019, amendment 2026-11-11).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
