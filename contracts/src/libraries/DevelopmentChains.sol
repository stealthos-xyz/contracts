// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DevelopmentChains
 * @notice Chain gate for trusted-setup provenance, enumerated deny-by-default.
 * @dev The earlier gate allowlisted the two chains a development key must NOT
 *      reach (Base and Ethereum mainnet), so a development-marked verifying key
 *      deployed freely on every other value-bearing chain — an OP/Arbitrum/
 *      Polygon deployment, or any L2 added after the guard was written. The set
 *      that is safe to enumerate is the throwaway one, so that is the set this
 *      library holds: anything not listed here is treated as carrying real
 *      value and rejects development keys.
 */
library DevelopmentChains {
    uint256 internal constant ANVIL = 31337;
    uint256 internal constant LOCAL_LEGACY = 1337;
    uint256 internal constant BASE_SEPOLIA = 84532;
    uint256 internal constant ETHEREUM_SEPOLIA = 11155111;
    /// @dev DogeOS Chikyu testnet (Scroll-SDK zkEVM settling to Dogecoin).
    ///      Only the testnet is enumerated; the DogeOS mainnet id is never
    ///      added here, so a development key cannot reach it by construction.
    ///      See DOGEOS_MYDOGE_JOINSPLIT_PLAN.md, decision D5.
    uint256 internal constant DOGEOS_CHIKYU = 6281971;

    /// @notice True only on chains whose assets are worthless, where a
    ///         development-setup verifying key is acceptable.
    function allowsDevelopmentSetup(uint256 chainId) internal pure returns (bool) {
        return chainId == ANVIL || chainId == LOCAL_LEGACY || chainId == BASE_SEPOLIA || chainId == ETHEREUM_SEPOLIA
            || chainId == DOGEOS_CHIKYU;
    }
}
