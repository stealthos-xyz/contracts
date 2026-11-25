// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {VantaFamilyReleaseBinding} from "./VantaFamilyReleaseBinding.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool} from "./VantaFamilyUnifiedPoolPreAudit.sol";

/// @dev Each withdrawal pays a fresh minimal proxy at an address committed to
/// its ordered recipient list. Only its factory can distribute the payout.
contract VantaFamilyBatchEscrow {
    using SafeERC20 for IERC20;

    address private immutable factory = msg.sender;
    error InvalidPayout();

    receive() external payable {}

    function distribute(address asset, address[] calldata recipients, uint128[] calldata amounts) external {
        if (msg.sender != factory) revert InvalidPayout();
        for (uint256 i; i < recipients.length; ++i) {
            address recipient = recipients[i];
            uint128 amount = amounts[i];
            if (asset == address(0)) {
                uint256 beforeBalance = address(this).balance;
                (bool ok,) = payable(recipient).call{value: amount}("");
                if (!ok || address(this).balance != beforeBalance - amount) revert InvalidPayout();
            } else {
                IERC20 token = IERC20(asset);
                uint256 beforeBalance = token.balanceOf(address(this));
                uint256 recipientBefore = token.balanceOf(recipient);
                token.safeTransfer(recipient, amount);
                if (token.balanceOf(address(this)) != beforeBalance - amount ||
                    token.balanceOf(recipient) != recipientBefore + amount) revert InvalidPayout();
            }
        }
    }
}

/// @notice One mode-0 withdrawal followed by an atomic distribution.
/// @dev The existing pool binds both the escrow address and this gateway to its
/// signed quote and proof. The gateway has no administrator or arbitrary calls.
contract VantaFamilyBatchPayout is VantaFamilyReleaseBinding, ReentrancyGuard {
    bytes32 private constant BATCH_DOMAIN = keccak256("STEALTHOS_FAMILY_BATCH_PAYOUT_V1");
    uint8 public constant MAX_RECIPIENTS = 32;
    address public immutable escrowImplementation;
    mapping(address => bytes32) public poolCodeHash;

    struct Batch {
        address[] recipients;
        uint128[] amounts;
    }

    error InvalidBatch();
    event BatchPaid(bytes32 indexed quoteNonce, bytes32 indexed batchHash, address indexed pool, uint128 total);

    constructor(address[] memory pools, bytes32 setupId, bytes32 generationId, bytes32 familyTag, uint256 chainId)
        VantaFamilyReleaseBinding(setupId, generationId, familyTag, chainId)
    {
        if (pools.length == 0 || pools.length > MAX_RECIPIENTS) revert InvalidBatch();
        for (uint256 i; i < pools.length; ++i) {
            address pool = pools[i];
            Pool source = Pool(payable(pool));
            if (pool.code.length == 0 || poolCodeHash[pool] != bytes32(0) ||
                source.releaseSetupId() != setupId || source.releaseGenerationId() != generationId ||
                source.releaseFamilyTag() != familyTag || source.releaseChainId() != chainId) revert InvalidBatch();
            poolCodeHash[pool] = pool.codehash;
        }
        escrowImplementation = address(new VantaFamilyBatchEscrow());
    }

    function batchHash(address pool, address asset, bytes32 nonce, Batch calldata batch) public view returns (bytes32) {
        return keccak256(abi.encode(BATCH_DOMAIN, block.chainid, address(this), pool, asset, nonce, batch));
    }

    function predictEscrow(address pool, address asset, bytes32 nonce, Batch calldata batch) external view returns (address) {
        return _predict(batchHash(pool, asset, nonce, batch));
    }
    function _init() private view returns(bytes memory) {
        return abi.encodePacked(hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",escrowImplementation,hex"5af43d82803e903d91602b57fd5bf3");
    }
    function _predict(bytes32 salt) private view returns(address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff),address(this),salt,keccak256(_init()))))));
    }

    function execute8(
        Pool.NormalEpochQuote calldata quote, Pool.EpochSpend8 calldata proof, bytes calldata feeSignature, Batch calldata batch
    ) external nonReentrant onlyReleaseChain {
        (address escrow, bytes32 hash, uint256 beforeBalance) = _prepare(quote, batch, 8);
        Pool(payable(quote.pool)).settleNormalEpoch8(quote, proof, feeSignature);
        _distribute(quote, batch, escrow, hash, beforeBalance);
    }

    function execute32(
        Pool.NormalEpochQuote calldata quote, Pool.EpochSpend32 calldata proof, bytes calldata feeSignature, Batch calldata batch
    ) external nonReentrant onlyReleaseChain {
        (address escrow, bytes32 hash, uint256 beforeBalance) = _prepare(quote, batch, 32);
        Pool(payable(quote.pool)).settleNormalEpoch32(quote, proof, feeSignature);
        _distribute(quote, batch, escrow, hash, beforeBalance);
    }

    function _prepare(Pool.NormalEpochQuote calldata quote, Batch calldata batch, uint8 width)
        private returns (address escrow, bytes32 hash, uint256 beforeBalance)
    {
        uint256 count = batch.recipients.length;
        bytes32 pinnedCode = poolCodeHash[quote.pool];
        if (quote.chainId != block.chainid || quote.mode != 0 || quote.width != width ||
            quote.relayer != address(this) || quote.nonce == bytes32(0) || quote.deadline < block.timestamp ||
            pinnedCode == bytes32(0) || quote.pool.codehash != pinnedCode ||
            address(Pool(payable(quote.pool)).asset()) != quote.asset ||
            count < 2 || count > MAX_RECIPIENTS || batch.amounts.length != count) revert InvalidBatch();
        hash = batchHash(quote.pool, quote.asset, quote.nonce, batch);
        escrow = _predict(hash);
        if (escrow != quote.recipient || escrow.code.length != 0) revert InvalidBatch();
        uint256 total;
        for (uint256 i; i < count; ++i) {
            address recipient = batch.recipients[i];
            if (recipient == address(0) || recipient == address(this) || recipient == quote.pool ||
                recipient == escrow || batch.amounts[i] == 0) revert InvalidBatch();
            total += batch.amounts[i];
        }
        if (total != quote.payout) revert InvalidBatch();
        bytes memory init=_init();address created;
        assembly("memory-safe"){created:=create2(0,add(init,32),mload(init),hash)}
        if(created!=escrow)revert InvalidBatch();
        beforeBalance = _balance(quote.asset, escrow);
    }

    function _distribute(
        Pool.NormalEpochQuote calldata quote, Batch calldata batch, address escrow, bytes32 hash, uint256 beforeBalance
    ) private {
        if (_balance(quote.asset, escrow) != beforeBalance + quote.payout) revert InvalidBatch();
        VantaFamilyBatchEscrow(payable(escrow)).distribute(quote.asset, batch.recipients, batch.amounts);
        if (_balance(quote.asset, escrow) != beforeBalance) revert InvalidBatch();
        emit BatchPaid(quote.nonce, hash, quote.pool, quote.payout);
    }

    function _balance(address asset, address escrow) private view returns (uint256) {
        return asset == address(0) ? escrow.balance : IERC20(asset).balanceOf(escrow);
    }
}
