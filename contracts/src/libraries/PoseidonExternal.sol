// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PoseidonT3External
 * @notice Wrapper for the standard circomlib-compatible PoseidonT3 library
 * @dev Calls a constructor-injected PoseidonT3 deployment after validating its known test vector.
 *
 *      This library was deployed using poseidon-solidity (iden3) and provides
 *      circomlib-compatible Poseidon hashing for BN254.
 *
 *      Verification: Poseidon(0, 0) = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864
 */

interface IPoseidonT3 {
    function hash(uint256[2] memory input) external pure returns (uint256);
}

library PoseidonT3External {
    uint256 internal constant ZERO_ZERO_HASH = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;

    error InvalidPoseidonT3();
    error PoseidonHashFailed();

    function validate(address poseidonT3) internal view {
        if (poseidonT3 == address(0) || poseidonT3.code.length == 0) revert InvalidPoseidonT3();

        uint256[2] memory input;
        uint256 result = hash(poseidonT3, input);
        if (result != ZERO_ZERO_HASH) revert InvalidPoseidonT3();
    }

    /// @notice Hash 2 field elements using Poseidon
    /// @param poseidonT3 Validated PoseidonT3 deployment
    /// @param input Array of 2 uint256 values
    /// @return The Poseidon hash as uint256
    function hash(address poseidonT3, uint256[2] memory input) internal view returns (uint256) {
        (bool success, bytes memory result) =
            poseidonT3.staticcall(abi.encodeWithSelector(IPoseidonT3.hash.selector, input));
        if (!success || result.length != 32) revert PoseidonHashFailed();
        return abi.decode(result, (uint256));
    }
}
