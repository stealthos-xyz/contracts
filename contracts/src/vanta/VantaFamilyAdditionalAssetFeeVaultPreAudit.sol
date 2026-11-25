// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IVantaFamilyVaultRegistrar} from "./VantaFamilyPublicFeeVaultPreAudit.sol";

interface IVantaFamilyAdditionalVaultRegistrar is IVantaFamilyVaultRegistrar {
    function approvedAssetCodehash(address token) external view returns (bytes32);
}

/// @notice The same registrar-only public exit-fee custody for a pinned additional
/// ERC-20. Existing native and canonical-token vault bytecode stays unchanged.
/// @dev Additional assets must already be frozen into the generation's registrar.
/// Only the registrar's existing genuine handle-owner proof can release funds.
contract VantaFamilyAdditionalAssetFeeVaultPreAudit {
    using SafeERC20 for IERC20;
    address public immutable registrar;
    bytes32 public immutable registrarCodehash;
    address public immutable asset;
    bytes32 public immutable assetCodehash;
    uint8 public immutable role;
    bytes32 public immutable releaseSetupId;
    bytes32 public immutable releaseGenerationId;
    bytes32 public immutable releaseFamilyTag;
    uint256 public immutable releaseChainId;
    bytes32 public immutable releaseGenesisHash;
    error Unauthorized();
    error InvalidPayout();

    constructor(address registrar_, address asset_, uint8 role_) {
        if (registrar_.code.length == 0 || role_ != 0 || asset_ == address(0) ||
            asset_.code.length == 0) revert Unauthorized();
        IVantaFamilyAdditionalVaultRegistrar r = IVantaFamilyAdditionalVaultRegistrar(registrar_);
        uint256 chain = r.releaseChainId();
        if (chain == 0 || block.chainid != chain || r.releaseSetupId() == bytes32(0) ||
            r.releaseGenerationId() == bytes32(0) || r.releaseFamilyTag() == bytes32(0) ||
            r.releaseGenesisHash() == bytes32(0) || r.canonicalToken() == asset_ ||
            r.approvedAssetCodehash(asset_) != asset_.codehash) revert Unauthorized();
        registrar = registrar_;
        registrarCodehash = registrar_.codehash;
        asset = asset_;
        assetCodehash = asset_.codehash;
        role = role_;
        releaseSetupId = r.releaseSetupId();
        releaseGenerationId = r.releaseGenerationId();
        releaseFamilyTag = r.releaseFamilyTag();
        releaseChainId = chain;
        releaseGenesisHash = r.releaseGenesisHash();
    }

    function release(address payable recipient, uint256 amount) external {
        if (msg.sender != registrar || registrar.codehash != registrarCodehash ||
            block.chainid != releaseChainId) revert Unauthorized();
        if (recipient == address(0) || recipient == address(this) || amount == 0 ||
            asset.codehash != assetCodehash) revert InvalidPayout();
        IERC20 token = IERC20(asset);
        uint256 beforeRecipient = token.balanceOf(recipient);
        uint256 beforeVault = token.balanceOf(address(this));
        token.safeTransfer(recipient, amount);
        if (token.balanceOf(recipient) != beforeRecipient + amount ||
            token.balanceOf(address(this)) + amount != beforeVault) revert InvalidPayout();
    }
}
