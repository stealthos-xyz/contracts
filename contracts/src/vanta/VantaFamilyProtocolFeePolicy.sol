// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";

/// @notice Versioned protocol rates. Partner policies remain owner-controlled
/// in their separate KZG registry. This contract never owns or transfers funds.
contract VantaFamilyProtocolFeePolicy is VantaFamilyReleaseBinding {
    address public immutable administrator;
    bytes32 public immutable basePolicyHash;
    uint64 public revision;
    mapping(uint64 => uint16[6]) private rates;
    mapping(uint64 => bytes32) public policyHashAt;
    error Unauthorized();
    error InvalidRates();
    error RevisionChanged();
    event ProtocolFeesUpdated(uint64 indexed revision, bytes32 indexed policyHash, uint16[6] rates);

    constructor(address administrator_, bytes32 baseHash, uint16[6] memory initialRates,
        bytes32 setupId, bytes32 generationId, bytes32 familyTag, uint256 chainId)
        VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId)
    {
        if (administrator_ == address(0) || baseHash == bytes32(0)) revert InvalidRates();
        administrator = administrator_; basePolicyHash = baseHash;
        _write(initialRates);
    }
    function rate(uint8 operation) external view returns (uint16) {
        if (operation > 5) revert InvalidRates();
        return rates[revision][operation];
    }
    function ratesAt(uint64 version) external view returns (uint16[6] memory) {
        if (version == 0 || version > revision) revert InvalidRates();
        return rates[version];
    }
    function policyHash() external view returns (bytes32) { return policyHashAt[revision]; }
    function updateRates(uint64 expectedRevision, uint16[6] calldata next) external onlyReleaseChain {
        if (msg.sender != administrator) revert Unauthorized();
        if (expectedRevision != revision) revert RevisionChanged();
        _write(next);
    }
    function _write(uint16[6] memory next) private {
        // Protocol deposits remain free. A full-exit policy must never charge
        // 100% of the withdrawal. Emergency exit rates remain deployment-pinned.
        if (next[2] != 0) revert InvalidRates();
        for (uint256 i; i < 6; ++i) if (next[i] >= 10_000) revert InvalidRates();
        ++revision; rates[revision] = next;
        bytes32 digest = keccak256(abi.encode("STEALTHOS_PROTOCOL_FEE_POLICY_V1",
            block.chainid, address(this), releaseSetupId, releaseGenerationId,
            basePolicyHash, revision, next));
        policyHashAt[revision] = digest;
        emit ProtocolFeesUpdated(revision, digest, next);
    }
}
