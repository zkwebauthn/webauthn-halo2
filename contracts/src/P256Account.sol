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
contract P256Account is SimpleAccount {
    using ECDSA for bytes32;

    address public verifier;

    IEntryPoint private immutable _entryPoint;

    event P256AccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of P256Account must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner, address aVerifier) public virtual initializer {
        _initialize(anOwner, aVerifier);
    }

    function _initialize(address anOwner, address aVerifier) internal virtual {
        owner = anOwner;
        verifier = aVerifier;
        emit P256AccountInitialized(_entryPoint, owner);
    }

    /// verify P-256 snark
    function _verifyRaw(bytes memory proof) private returns (bool) {
        // TODO: update for public inputs (signature, public key, hashed message)
        uint256[] memory publicInputs = new uint256[](0);
        (bool success,) = verifier.call(abi.encodePacked(publicInputs, proof));
        return success;
    }

    /// Validate WebAuthn P-256 signature
    function _validateSignature(UserOperation calldata userOp, bytes32)
    internal override virtual returns (uint256 validationData) {
        // TODO: Replace with webauthn verification
        if (!_verifyRaw(userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }
}

