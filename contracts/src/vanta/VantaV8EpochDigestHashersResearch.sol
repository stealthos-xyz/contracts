// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaPoseidonV8Sparse} from "./VantaPoseidonV8Sparse.sol";
import {VantaPoseidonV832Sparse} from "./VantaPoseidonV832Sparse.sol";

/// @notice Deployable, immutable Poseidon statement hashers for V8 epoch digests.
/// @dev Delegates to the frozen sparse Poseidon libraries without changing any
/// statement input or field encoding. Separate runtime code avoids EIP-170.
contract VantaV8EpochPoseidon40Research {
    function digest40(uint256[40] memory fields) external pure returns (uint256) {
        return VantaPoseidonV8Sparse.digest40(fields);
    }
}

contract VantaV8EpochPoseidon64Research {
    function digest64(uint256[64] memory fields) external pure returns (uint256) {
        return VantaPoseidonV832Sparse.digest64(fields);
    }
}
