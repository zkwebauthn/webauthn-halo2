# webauthn-halo2

Proving and verifying WebAuthn with Halo2, specifically the [ES256 algorithm variant](https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier) with the [P-256 curve](https://neuromancer.sk/std/secg/secp256r1), which is present on Apple's [Face/Touch ID devices](https://developer.apple.com/documentation/cryptokit/p256/signing/ecdsasignature), Intel [secure enclaves](https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf), Yubikey [authenticators](https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html), and more.

## File Structure

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

## P-256 Wallet

The primary application of this project is to implement a [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) "smart contract wallet" that verifies WebAuthn signatures. No wallet extensions or wallet apps are needed – users could send stablecoins, mint POAPs, or sign any other transactions purely within their browser. This is especially powerful for mobile devices with fingerprint / facial scans, where users can sign transactions within a mobile browser like Safari or Chrome.

![image](https://github.com/zkwebauthn/webauthn-halo2/assets/36896271/b4dfd3ea-7293-4ed5-a511-32dd9567f19a)

