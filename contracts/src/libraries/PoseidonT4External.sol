// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @notice Calls a pinned Poseidon(3) implementation behind a dual hasher.
 * @dev The same BN254/circomlib profile as PoseidonT4.hash, verified by
 *      representative vectors in the V3 real-EVM and parity suites.
 */
library PoseidonT4External {
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant ZERO_ZERO_ZERO =
        5317387130258456662214331362918410991734007599705406860481038345552731150762;
    uint256 private constant ONE_TWO_THREE =
        6542985608222806190361240322586112750744169038454362455181422643027100751666;

    error InvalidPoseidonT4();
    error PoseidonT4HashFailed();

    function validate(address hasher) internal view {
        if (hasher == address(0) || hasher.code.length == 0)
            revert InvalidPoseidonT4();
        if (hash(hasher, [uint256(0), 0, 0]) != ZERO_ZERO_ZERO ||
            hash(hasher, [uint256(1), 2, 3]) != ONE_TWO_THREE)
            revert InvalidPoseidonT4();
    }

    function hash(address hasher, uint256[3] memory input)
        internal view returns (uint256 digest)
    {
        for (uint256 i; i < 3; ++i) {
            if (input[i] >= FR) revert InvalidPoseidonT4();
        }
        (bool ok, bytes memory data) = hasher.staticcall(
            abi.encodeWithSignature("hash(uint256[3])", input)
        );
        if (!ok || data.length != 32) revert PoseidonT4HashFailed();
        digest = abi.decode(data, (uint256));
        if (digest >= FR) revert PoseidonT4HashFailed();
    }
}
