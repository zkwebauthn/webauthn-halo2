## Install

Using yarn

```sh
yarn add @knownothing/browser
```

Using npm

```sh
npm install --save @knownothing/browser
```

##

Typescript:

```typescript
import { ZKPasskeyManager, Chain, Wallet, Passkey } from "zk-passkeys";

/** Register a new passkey and set a recovery method */
const zkPasskeyManager = new ZKPasskeyManager({
  apiKey: "your-api-key-here",
});
// Signs the WebAuthn challenge and generates a proof
const passkey = await zkPasskeyManager.registerNewPasskey({
  challenge: "my-expected-challenge-here",
});
console.log(passkey.publicKey); // save the public key in your application's DB, browser storage, or smart contract

/** Recover their account */
const passkey = zkPasskeyManager.fromPublicKey(publicKey);
const proof = await passkey.signRecoveryChallenge("my-expected-challenge-here");
// Submit proof and expectedChallenge to social recovery wallet function
// ...
```

Example social recovery wallet

```solidity
contract ISocialRecoveryWallet {
	function owner() external view returns (address);

	// This calls Verifier.verifyPasskeySignature(owner, proof), and if verified,
	// sets owner equal to newOwner
	function recoverAccount(address newOwner, bytes calldata proof);
}
```

SDK smart contract

```solidity
contract PasskeyVerifier {
	function expectedChallenge() external view returns (bytes);

	// Stores the public key for an account
	function registerNewPasskey(address account, bytes proof, bytes expectedChallenge)

	// Makes a call to Verifier checking the proof vs the account's public key
	function verifyPasskeySignature(address account, bytes proof) external returns(bool);
}
```
