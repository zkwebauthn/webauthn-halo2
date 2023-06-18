// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "./core/BaseAccount.sol";
import "./samples/SimpleAccount.sol";

contract P256Account is SimpleAccount {
    IEntryPoint internal immutable entryPoint;
    uint256 private _nonce;
    bytes public publicKey;
    uint256 public InactiveTimeLimit;
    uint256 public lastActiveTime;
    address public inheritor;

    modifier updateLastActive() {
        _;
        lastActiveTime = block.timestamp;
    }

    constructor(
        IEntryPoint _entryPoint,
        bytes memory _publicKey
    ) SimpleAccount(_entryPoint) {
        entryPoint = _entryPoint;
        publicKey = _publicKey;
    }

    receive() external payable override {}

    function nonce() public view virtual returns (uint256) {
        return _nonce;
    }

    function setPublicKey(bytes calldata _publicKey) external updateLastActive {
        _requireFromEntryPoint();
        publicKey = _publicKey;
    }

    function setInactiveTimeLimit(
        uint256 _InactiveTimeLimit
    ) external updateLastActive {
        _requireFromEntryPoint();
        InactiveTimeLimit = _InactiveTimeLimit;
    }

    function setInheritor(address _inheritor) external updateLastActive {
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
    ) internal view override returns (uint256 validationData) {
        // TODO
    }

    function _validateAndUpdateNonce(UserOperation calldata userOp) internal {
        require(_nonce++ == userOp.nonce, "account: invalid nonce");
    }
}
