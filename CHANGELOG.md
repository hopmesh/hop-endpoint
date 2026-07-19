# Changelog

Notable changes, generated from [conventional commits](https://www.conventionalcommits.org) by
git-cliff. Do not edit by hand.
## Unreleased

### Bug Fixes
- well-known reach record was born expired (issued_at=0) (#141) (e0fb4db)
- close F-18d, HpsRekey fails safe under a mid-arm panic (#104) (879019b)
- cover Destination::Vaccine in every workspace crate (relay/relayd/hop-sim) + workspace fmt/clippy (e611c4d)

### CI
- bump create-github-app-token to v3.2.0 across all mirrored components (efc9f6c)

### Chore
- drop the root license, license per-component (FSL-1.1-ALv2) (#146) (be2a5a7)

### Dependencies
- land the grouped rust-dependencies bump (sha2, ed25519/x25519-dalek, chacha20poly1305, snow, rusqlite, p256, uniffi, tungstenite) (#89) (2038ce9)

### Documentation
- branded, marketable READMEs for every sub-repo (9c2a477)

### Features
- phase 3 hold-until-coordinated quorum (CP; never double-process) (#159) (ab0f376)
- self-clustering endpoints (phase 1 dedup) as a hop-endpoint-core layer over the mesh (#153) (487e4d2)

### Other
- CLA gate on contributions (preserve commercial relicensing of core) (5a9aa7d)
- SECURITY.md per component + enable-security in the bootstrap script (a1492e9)
- copyright holder is Hop Mesh, LLC (7d8c514)
- fill the Apache-2.0 copyright placeholder (2026 Jason Waldrip) (2fb7d1c)
- Apache-2.0 for everything except core/ (only the protocol stays FSL) (0fe9439)
- CHANGE_REQUEST sync-back + document merge/conversation + confidentiality (9e1dec2)
- make the TLS-served reach record the only name path (drop DNSSEC-over-DoH) (#139) (8998288)
- close the two capping defects in Endpoint and the Kotlin SDK (#74) (aa338be)

### Testing
- raise line coverage 39.4% -> 80.9% (#61) (1510b15)

