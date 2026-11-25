// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Canonical v0 fungible token-domain (native ETH uses address(0)), shared by deposit and
///         settlement statement builders. Research only.
library VantaTokenHash {
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 internal constant DOMAIN = keccak256("STEALTHOS_VANTA_TOKEN_HASH_V0");

    /// @dev Exactly Solidity abi.encode(7 full words), NOT abi.encodePacked.
    ///      The Rust companion is vanta_evm_wire::token_hash_v0.
    function compute(uint256 chainId, address pool, address token)
        internal pure returns (uint256)
    {
        return uint256(keccak256(abi.encode(
            DOMAIN, chainId, pool, uint64(0), token, uint8(0), uint256(0)
        ))) % FR;
    }
}

contract VantaTokenHashHarness {
    function canonical(uint256 chainId, address pool, address token)
        external pure returns (uint256)
    {
        return VantaTokenHash.compute(chainId, pool, token);
    }
}
