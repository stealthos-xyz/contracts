// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Frozen Base network allowlist for the unaudited V8 research stack.
/// @dev Both deployments use the same source. Chain IDs, signing domains,
///      token hashes and pool addresses remain bound to the actual chain.
library VantaBaseChainPolicy {
    uint64 internal constant MAINNET = 8_453;
    uint64 internal constant SEPOLIA = 84_532;

    error UnsupportedBaseChain(uint256 chainId);

    function isSupported(uint256 chainId) internal pure returns (bool) {
        return chainId == SEPOLIA || chainId == MAINNET;
    }

    function requireCurrent() internal view returns (uint64 chainId) {
        if (!isSupported(block.chainid))
            revert UnsupportedBaseChain(block.chainid);
        return uint64(block.chainid);
    }
}
