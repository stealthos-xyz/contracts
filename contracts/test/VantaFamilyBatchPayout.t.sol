// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {VantaFamilyReleaseBinding} from "../src/vanta/VantaFamilyReleaseBinding.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool} from "../src/vanta/VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaFamilyBatchPayout, VantaFamilyBatchEscrow} from "../src/vanta/VantaFamilyBatchPayout.sol";

contract BatchPayoutToken is ERC20 {
    constructor() ERC20("Batch fixture", "FIX") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract BatchPayoutPool is VantaFamilyReleaseBinding {
    address public immutable asset;
    uint256 public withdrawals;

    constructor(address asset_) VantaFamilyReleaseBinding(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), block.chainid) {
        asset = asset_;
    }

    function settleNormalEpoch8(Pool.NormalEpochQuote calldata quote, Pool.EpochSpend8 calldata, bytes calldata) external {
        _settle(quote);
    }

    function settleNormalEpoch32(Pool.NormalEpochQuote calldata quote, Pool.EpochSpend32 calldata, bytes calldata) external {
        _settle(quote);
    }

    function _settle(Pool.NormalEpochQuote calldata quote) private {
        require(quote.mode == 0 && msg.sender == quote.relayer);
        ++withdrawals;
        if (asset == address(0)) {
            (bool ok,) = payable(quote.recipient).call{value: quote.payout}("");
            require(ok);
        } else {
            require(BatchPayoutToken(asset).transfer(quote.recipient, quote.payout));
        }
    }
}

contract RejectBatchPayout {
    receive() external payable { revert(); }
}

contract VantaFamilyBatchPayoutTest is Test {
    VantaFamilyBatchPayout private gateway;
    BatchPayoutPool private nativePool;
    BatchPayoutPool private tokenPool;
    BatchPayoutToken private token;

    function setUp() public {
        vm.chainId(6281971);
        token = new BatchPayoutToken();
        nativePool = new BatchPayoutPool(address(0));
        tokenPool = new BatchPayoutPool(address(token));
        vm.deal(address(nativePool), 30 ether);
        token.mint(address(tokenPool), 30 ether);
        address[] memory pools = new address[](2);
        pools[0] = address(nativePool);
        pools[1] = address(tokenPool);
        gateway = new VantaFamilyBatchPayout(pools, bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), block.chainid);
    }

    function _batch() private pure returns (VantaFamilyBatchPayout.Batch memory batch) {
        batch.recipients = new address[](3);
        batch.amounts = new uint128[](3);
        for (uint256 i; i < 3; ++i) {
            batch.recipients[i] = address(uint160(100 + i));
            batch.amounts[i] = uint128((i + 1) * 1 ether);
        }
    }

    function _quote(BatchPayoutPool pool, uint8 width, VantaFamilyBatchPayout.Batch memory batch)
        private view returns (Pool.NormalEpochQuote memory quote)
    {
        quote.chainId = uint64(block.chainid);
        quote.pool = address(pool);
        quote.asset = pool.asset();
        quote.width = width;
        quote.relayer = address(gateway);
        quote.payout = 6 ether;
        quote.deadline = uint64(block.timestamp + 600);
        quote.nonce = bytes32(uint256(8));
        quote.recipient = gateway.predictEscrow(quote.pool, quote.asset, quote.nonce, batch);
    }

    function testPaysThreeRecipientsWithOneNormalWithdrawal() public {
        VantaFamilyBatchPayout.Batch memory batch = _batch();
        Pool.NormalEpochQuote memory quote = _quote(nativePool, 8, batch);
        Pool.EpochSpend8 memory proof;
        uint256 poolBalance = address(nativePool).balance;
        gateway.execute8(quote, proof, "", batch);
        assertEq(nativePool.withdrawals(), 1);
        assertEq(address(nativePool).balance, poolBalance - 6 ether);
        for (uint256 i; i < 3; ++i) assertEq(batch.recipients[i].balance, batch.amounts[i]);
        assertEq(quote.recipient.balance, 0);
        vm.expectRevert();
        gateway.execute8(quote, proof, "", batch);
        assertEq(nativePool.withdrawals(), 1);
    }

    function testTokenAndWidth32UseTheSamePayout() public {
        VantaFamilyBatchPayout.Batch memory batch = _batch();
        Pool.NormalEpochQuote memory quote = _quote(tokenPool, 32, batch);
        Pool.EpochSpend32 memory proof;
        gateway.execute32(quote, proof, "", batch);
        assertEq(tokenPool.withdrawals(), 1);
        for (uint256 i; i < 3; ++i) assertEq(token.balanceOf(batch.recipients[i]), batch.amounts[i]);
        assertEq(token.balanceOf(quote.recipient), 0);
    }

    function testChangingRecipientOrAmountInvalidatesTheSignedEscrow() public {
        VantaFamilyBatchPayout.Batch memory batch = _batch();
        Pool.NormalEpochQuote memory quote = _quote(nativePool, 8, batch);
        Pool.EpochSpend8 memory proof;
        batch.amounts[0] += 1;
        batch.amounts[1] -= 1;
        vm.expectRevert(VantaFamilyBatchPayout.InvalidBatch.selector);
        gateway.execute8(quote, proof, "", batch);
        batch = _batch();
        batch.recipients[0] = address(9898);
        vm.expectRevert(VantaFamilyBatchPayout.InvalidBatch.selector);
        gateway.execute8(quote, proof, "", batch);
        assertEq(nativePool.withdrawals(), 0);
    }

    function testRecipientRevertRollsBackPoolSpendAndEarlierRecipients() public {
        VantaFamilyBatchPayout.Batch memory batch = _batch();
        batch.recipients[2] = address(new RejectBatchPayout());
        Pool.NormalEpochQuote memory quote = _quote(nativePool, 8, batch);
        Pool.EpochSpend8 memory proof;
        vm.expectRevert(VantaFamilyBatchEscrow.InvalidPayout.selector);
        gateway.execute8(quote, proof, "", batch);
        assertEq(nativePool.withdrawals(), 0);
        assertEq(batch.recipients[0].balance, 0);
        assertEq(batch.recipients[1].balance, 0);
        assertEq(quote.recipient.code.length, 0);
    }

    function testPrefundedAddressCannotChangePayouts() public {
        VantaFamilyBatchPayout.Batch memory batch = _batch();
        Pool.NormalEpochQuote memory quote = _quote(nativePool, 8, batch);
        Pool.EpochSpend8 memory proof;
        vm.deal(quote.recipient, 1 ether);
        gateway.execute8(quote, proof, "", batch);
        assertEq(quote.recipient.balance, 1 ether);
        vm.expectRevert(VantaFamilyBatchEscrow.InvalidPayout.selector);
        VantaFamilyBatchEscrow(payable(quote.recipient)).distribute(address(0), batch.recipients, batch.amounts);
    }
}
