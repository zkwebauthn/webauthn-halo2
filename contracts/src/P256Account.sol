// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import "openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./SimpleAccount.sol";
import "./core/BaseAccount.sol";
import "./callback/TokenCallbackHandler.sol";

/**
 * Account that validates P-256 signature for UserOperations.
 */
contract P256Account is Initializable, SimpleAccount {
    using ECDSA for bytes32;

    address public verifier;
    IEntryPoint public _entryPoint;
    bytes public publicKey;
    address public snarkVerifier;
    uint256 InactiveTimeLimit;
    address inheritor;
    uint256 lastActiveTime;

    constructor(IEntryPoint _newEntryPoint) SimpleAccount(_newEntryPoint) {}

    function initialize(
        IEntryPoint _newEntryPoint,
        bytes memory _publicKey,
        address _snarkVerifier
    ) public initializer {
        _entryPoint = _newEntryPoint;
        publicKey = _publicKey;
        snarkVerifier = _snarkVerifier;
        InactiveTimeLimit = 0;
        inheritor = address(0);
        lastActiveTime = block.timestamp;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function setPublicKey(bytes calldata _publicKey) external {
        _requireFromEntryPoint();
        publicKey = _publicKey;
    }

    function setInactiveTimeLimit(uint256 _InactiveTimeLimit) external {
        _requireFromEntryPoint();
        InactiveTimeLimit = _InactiveTimeLimit;
    }

    function setInheritor(address _inheritor) external {
        _requireFromEntryPoint();
        inheritor = _inheritor;
    }

    function inherit() external {
        require(inheritor == msg.sender, "not inheritor");
        require(
            block.timestamp - lastActiveTime > InactiveTimeLimit,
            "not inactive"
        );
        payable(inheritor).transfer(address(this).balance);
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        // TODO: public inputs with useropHash
        (bool success,) = snarkVerifier.call(userOp.signature);
        if (!success) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }
}