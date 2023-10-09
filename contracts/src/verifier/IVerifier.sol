// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * Each account has a public key stored on chain.
 * This contract is used to verify the signature of the passkey for an account via a zk proof.
 * The zk proof states that the account's public key signed a specific piece of challenge data.
 *
 * @title Verifier
 * @author Know Nothing Labs
 */
interface IVerifier {
    /**
     *
     * @param account Address of the account to register the public key for
     * @param publicKey Public Key of he account
     */
	function registerNewPasskey(address account, bytes calldata publicKey) external;

    /**
     * @dev Verifies a passkey signature for an account - return true if the verification is successful
     * @param account Address of the account to verify the passkey signature for
     * @param proof Zk proof of the passkey signature
     */
	function verifyPasskeySignature(address account, bytes memory proof, bytes memory challenge) external returns(bool);
}
