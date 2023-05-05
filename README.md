# webauthn-halo2

Proving and verifying WebAuthn with Halo2.

The repository is structured into three main directories:
- `halo2-circuits/`, which contains the Halo2 circuit for P-256 ECDSA, ES256, and WebAuthn
- `proving-server/`, which is the Rust webserver for generating proofs
- `contracts/`, which includes the on-chain verifier and associated ERC-4337 contracts
