// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

contract P256AccountFactory {
    function create(uint256 salt, bytes calldata initializationCode) public returns (address deploymentAddress) {
        bytes memory initCode = initializationCode;

        // using inline assembly: load data and length of data, then call CREATE2.
        assembly {
            // solhint-disable-line
            let encoded_data := add(0x20, initCode) // load initialization code.
            let encoded_size := mload(initCode) // load the init code's length.
            deploymentAddress :=
                create2( // call CREATE2 with 4 arguments.
                    0,
                    encoded_data, // pass in initialization code.
                    encoded_size, // pass in init code's length.
                    salt // pass in the salt value.
                )
        }
    }

    function findCreate2Address(uint256 salt, bytes calldata initCode)
        external
        view
        returns (address deploymentAddress)
    {
        // determine the address where the contract will be deployed.
        deploymentAddress = address(
            uint160( // downcast to match the address type.
                uint256( // convert to uint to truncate upper digits.
                    keccak256( // compute the CREATE2 hash using 4 inputs.
                        abi.encodePacked( // pack all inputs to the hash together.
                            hex"ff", // start with 0xff to distinguish from RLP.
                            address(this), // this contract will be the caller.
                            salt, // pass in the supplied salt value.
                            keccak256( // pass in the hash of initialization code.
                            abi.encodePacked(initCode))
                        )
                    )
                )
            )
        );
    }
}
