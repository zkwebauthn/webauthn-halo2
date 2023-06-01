# webauthn-halo2

Proving and verifying WebAuthn with Halo2.

The repository is structured into three main directories:

- `halo2-circuits/`, which contains the Halo2 circuit for P-256 ECDSA, ES256, and WebAuthn
- `proving-server/`, which is the Rust webserver for generating proofs
- `contracts/`, which includes the on-chain verifier and associated ERC-4337 contracts

## Proving Server

The proving server API has a few endpoints for proving, verifying, and other relevant functions.

- `POST /setup` - set up proving / verifying keys and srs params
- `POST /prove` - generate a proof using the the Blake2b transcript
- `POST /prove_evm` - generate a proof using the the EVM transcript
- `POST /verify` - generate a proof using the the Blake2b transcript
- `POST /verify_evm` - generate a proof using the the EVM transcript
- `POST /generate_evm_verifier` - generate an EVM verifier and save to raw bytecode and Solidity

## Testing & Benchmarks

```bash
# Test P-256 circuit correctness
cargo test -- --nocapture test_secp256r1_ecdsa
# Benchmarks for P-256 proving and verification
cargo test -- --nocapture bench_secp256r1_ecdsa
```
