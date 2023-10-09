// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./P256Account.sol";
import "./verifier/IVerifier.sol";

/**
 * Account that validates P-256 signature for UserOperations and features social recovery.
 */
contract SocialRecoveryAccount is P256Account {

    // Contract variables
    IVerifier public verifier;
    address[] recoveryGroup;
    uint256 public threshold;

    // Recovery variables
    bytes public challenge;
    uint256 public challengePeriodEndTime;
    bytes public newPublicKey;

    uint256 public constant CHALLENGE_PERIOD = 7 days;

    constructor(IEntryPoint _newEntryPoint, IVerifier _verifier, address[] memory _recoveryGroup, uint256 _threshold) P256Account(_newEntryPoint) {
        require(_recoveryGroup.length >= threshold, "Threshold too high");
        verifier = _verifier;
        recoveryGroup = _recoveryGroup;
        threshold = _threshold;
    }

    /**
     * @dev Sets the recovery group and threshold for the account. This should be called upon account initialization.
     * @param _recoveryGroup The list of addresses that have the ability to recover the account
     * @param _threshold The number of signatures from the recovery group required to recover the account
     */
    function setRecoveryGroup(address[] memory _recoveryGroup, uint256 _threshold) public {
        _requireFromEntryPoint();
        require(_recoveryGroup.length >= threshold, "Threshold too high");
        recoveryGroup = _recoveryGroup;
        threshold = _threshold;
    }

    /**
     * @dev Start the recovery process for the account. This method can be called by anyone, since
     * the owner would have lost their private key
     * @param _publicKey The public key of the account
     */
    function startRecover(bytes calldata _publicKey) external {
        challenge = abi.encode(blockhash(block.number), _publicKey);
        challengePeriodEndTime = block.timestamp + CHALLENGE_PERIOD;
    }

    /**
     * @dev Finish the recovery process for the account. This method can be called by anyone.
     * @param proofs The list of proofs from the recovery group members.
     */
    function finishRecover(bytes[] memory proofs) external {
        require(block.timestamp > challengePeriodEndTime, "Recovery period ended");
        uint256 successfulSignatures = 0;
        for (uint256 i = 0; i < recoveryGroup.length; i++) {
            if(verifier.verifyPasskeySignature(recoveryGroup[i], proofs[i], challenge)) {
                successfulSignatures++;
            }
        }
        require(successfulSignatures >= threshold, "Not enough signatures");
        setPublicKey(newPublicKey);
    }

    /**
     * @dev This is to prevent a hostile takeover of the account by recovery group members.
     * The contract owner can call this method to end the recovery process.
     */
    function endRecovery() external{
        _requireFromEntryPoint();
        challengePeriodEndTime = type(uint256).max;
    }
}
