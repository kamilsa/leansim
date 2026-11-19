## leansim changes

Vendored from sigp/waggle PR #2 at 3b031d0.

- Ported to libp2p 0.54 (crates.io) from sigp/rust-libp2p `accba72`
  (libp2p 0.57): `listen_protocol` returns
  `SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo>`, and
  `fetch_update` replaces `AtomicUsize::try_update`, which is unstable on Rust
  1.94. `prost-codec` 0.4.0 comes from crates.io.
- `build.rs` and its build dependencies are dropped; `src/waggle.pb.rs` is kept
  as generated from `src/waggle.proto`. The dev-dependency `rand` is 0.8, the
  version leansim already locks.

## 0.1.0 [2026-xx-xx]

- Initial protocol implementation.
