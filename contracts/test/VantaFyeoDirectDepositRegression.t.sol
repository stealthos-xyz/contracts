// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {PoseidonT4} from "../src/libraries/PoseidonT4.sol";
import {VantaTokenHash} from "../src/vanta/VantaTokenHash.sol";
import {VantaFamilyReleaseBinding} from "../src/vanta/VantaFamilyReleaseBinding.sol";
import {VantaFamilyProtocolFeePolicy as Policy} from "../src/vanta/VantaFamilyProtocolFeePolicy.sol";
import {VantaFamilyNoAppendExitCustodyPreAudit as ExitPool} from "../src/vanta/VantaFamilyNoAppendExitCustodyPreAudit.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool,VantaV8UnifiedNormalSpendLogic as Logic} from "../src/vanta/VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaFamilyEnhancedPoolPreAudit as Enhanced} from "../src/vanta/VantaFamilyEnhancedPoolPreAudit.sol";
import {VantaFamilyDirectDepositPoolPreAudit as Direct} from "../src/vanta/VantaFamilyDirectDepositPoolPreAudit.sol";
import {VantaV8FiveRowKzgResearch as Kzg} from "../src/vanta/VantaV8FiveRowKzgResearch.sol";
import {RoutedProofMock,RoutedCombinedMock,RoutedKzgMock} from "./VantaFamilyRoutedSettlement.t.sol";
import {VantaFamilyFullBundleVerifierPreAudit as Bundle} from "../src/vanta/VantaFamilyFullBundleVerifierPreAudit.sol";
import {VantaFamilyAggregateGroth16PreAudit as Agg} from "../src/vanta/VantaFamilyAggregateGroth16PreAudit.sol";
import {VantaV8StatementResearch as S8} from "../src/vanta/VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as S32} from "../src/vanta/VantaV8Statement32Research.sol";

// Synthetic verification fixtures isolate the actual pool's custody and nonce
// mechanics. They are NOT cryptographic or screening qualification artifacts.
contract FyeoExitVerifierFixture is VantaFamilyReleaseBinding {
    constructor()
        VantaFamilyReleaseBinding(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid) {}
    function verifyExit8(S8.LegPublic calldata,uint64,uint128,uint128,
        Bundle.V8Gate0Data calldata,Bundle.Gate1Data calldata,Bundle.LinkData calldata,
        uint64,uint256,uint256) external pure returns (bool) { return true; }
    function verifyExit32(S32.LegPublic calldata,uint64,uint128,uint128,
        Bundle.V8Gate0Data calldata,Bundle.Gate1Data calldata,Bundle.LinkData calldata,
        uint64,uint256,uint256) external pure returns (bool) { return true; }
    function verifyPayout(Agg.VerifyingKey calldata,Agg.Proof calldata,uint256[11] calldata,
        uint256,uint256,uint256) external pure returns (bool) { return true; }
}
contract FyeoEnhancedFeeFixture is VantaFamilyReleaseBinding {
    address public immutable asset;
    Policy public immutable protocolFeePolicy;
    uint128 public constant minimumFee = 0;
    bytes32 public constant releaseGenesisHash = bytes32(uint256(4));
    constructor(address a,Policy p)
        VantaFamilyReleaseBinding(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid)
    { asset = a; protocolFeePolicy = p; }
    function policyHash() external view returns (bytes32) { return protocolFeePolicy.policyHash(); }
}
contract FyeoClearanceFixture is VantaFamilyReleaseBinding {
    address public immutable administrator;
    address private swapPayer;
    address private swapPool;
    bytes32 private swapHash;
    function allowSwap(address payer,address pool,bytes32 dataHash) external {
        require(msg.sender == administrator);
        swapPayer = payer; swapPool = pool; swapHash = dataHash;
    }
    function isSwapIngress(address payer,address pool,bytes32 dataHash) external view returns (bool) {
        return msg.sender == pool && pool == swapPool && payer == swapPayer && dataHash == swapHash;
    }
    constructor(address admin)
        VantaFamilyReleaseBinding(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid)
    { administrator = admin; }
    function requireClearance(address payer,bytes calldata clearance) external pure {
        require(payer != address(0) && clearance.length == 0);
    }
}
contract FyeoTreeHasherFixture {
    function hash(uint256[2] calldata) external pure returns (uint256) {
        return 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;
    }
}
contract FyeoTokenFixture is ERC20 {
    bool public shortTransfer;
    constructor() ERC20("Test custody token","TEST") { _mint(msg.sender,10000); }
    function setShortTransfer(bool value) external { shortTransfer = value; }
    function _update(address from,address to,uint256 value) internal override {
        if (shortTransfer && from != address(0) && to != address(0)) {
            super._update(from,to,value-1);
            super._update(from,address(0),1);
        } else super._update(from,to,value);
    }
}

contract VantaFyeoDirectDepositRegressionTest is Test {
    address private constant PROTOCOL = address(0xA11);
    address private constant RECIPIENT = address(0xB22);
    bytes32 private constant NONCE = bytes32(uint256(999));
    FyeoClearanceFixture private clearanceFixture;
    function setUp() public { vm.chainId(6281971); vm.warp(1000); vm.deal(address(this),10 ether); }

    function _pool(address asset) private returns (Direct pool) {
        Enhanced.BaseConfiguration memory b;
        b.setupId=bytes32(uint256(1)); b.generationId=bytes32(uint256(2));
        b.familyTag=bytes32(uint256(3)); b.chainId=block.chainid;
        b.asset=asset; b.initialX=1; b.initialY=2;
        b.feeSigner=address(0xD44); b.protocolRecipient=PROTOCOL;
        b.retirementAuthority=address(this); b.policyHash=bytes32(uint256(7));
        b.exitFeeRates=[uint16(15),uint16(0)];
        Policy policy=new Policy(address(this),b.policyHash,
            [uint16(15),uint16(15),uint16(0),uint16(15),uint16(15),uint16(15)],
            b.setupId,b.generationId,b.familyTag,b.chainId);
        b.protocolFeePolicy=address(policy);
        b.exitVerifier=address(new FyeoExitVerifierFixture());
        b.normalVerifier=address(new RoutedProofMock());
        b.combinedFeeVerifier=address(new RoutedCombinedMock(policy));
        b.kzg=address(new RoutedKzgMock());
        Enhanced.EnhancedConfiguration memory e;
        e.genesisHash=bytes32(uint256(4)); e.maximumWindowEpochs=10;
        e.minimumDelayEpochs=2; e.maximumAuthorizationAgeEpochs=1;
        e.authorizationVerifier=address(new RoutedProofMock());
        e.claimVerifier=address(new RoutedProofMock());
        e.feeVerifier=address(new FyeoEnhancedFeeFixture(asset,policy));
        e.poseidon=address(new FyeoTreeHasherFixture());
        clearanceFixture = new FyeoClearanceFixture(address(this));
        pool=new Direct(b,e,address(clearanceFixture));
    }

    function _packet(Direct pool,bytes32 nonce,uint256 first) private view returns (bytes memory) {
        Pool.PrivateFeeDepositQuote memory q;
        (q.epoch,,,,q.checkpoint)=pool.currentSource();
        q.chainId=uint64(block.chainid); q.pool=address(pool); q.asset=address(pool.asset());
        q.payer=address(this); q.count=3; q.gross=1000; q.protocolRecipient=PROTOCOL;
        q.feeTermsHash=11; q.partnerRegistryRoot=12; q.nonce=nonce;
        q.deadline=uint64(block.timestamp+600); q.feePolicyHash=pool.feePolicyHash();
        uint256[5] memory outputs; bytes[5] memory envelopes; bytes32[5] memory hashes;
        for(uint256 i;i<3;++i) {
            outputs[i]=first+i; envelopes[i]=new bytes(96);
            envelopes[i][0]=0x01; hashes[i]=keccak256(envelopes[i]);
        }
        uint8[2] memory slots=[uint8(1),uint8(2)]; Kzg.RowKey[5] memory rows;
        q.outputsHash=keccak256(abi.encode(outputs)); q.envelopesHash=keccak256(abi.encode(hashes));
        q.feeSlotsHash=keccak256(abi.encode(slots));
        return abi.encodeCall(Pool.depositWithPrivateFeeNotes,(q,outputs,envelopes,rows,slots,hex"",hex""));
    }

    function _swapPacket(Direct pool,bytes32 creditId,uint256 npk) private view returns (bytes memory packet,uint256 commitment) {
        Pool.PrivateFeeDepositQuote memory q;
        (q.epoch,,,,q.checkpoint)=pool.currentSource();
        q.chainId=uint64(block.chainid); q.pool=address(pool); q.asset=address(pool.asset());
        q.payer=address(this); q.count=1; q.gross=1000; q.nonce=creditId;
        q.deadline=uint64(block.timestamp+600); q.feePolicyHash=pool.feePolicyHash();
        commitment=PoseidonT4.hash([npk,VantaTokenHash.compute(block.chainid,address(pool),q.asset),uint256(q.gross)]);
        uint256[5] memory outputs; outputs[0]=commitment;
        bytes[5] memory envelopes; envelopes[0]=new bytes(829); envelopes[0][0]=0x01;
        bytes32[5] memory hashes; hashes[0]=keccak256(envelopes[0]);
        uint8[2] memory slots; Kzg.RowKey[5] memory rows;
        q.outputsHash=keccak256(abi.encode(outputs)); q.envelopesHash=keccak256(abi.encode(hashes));
        q.feeSlotsHash=keccak256(abi.encode(slots));
        packet=abi.encodeCall(Pool.depositWithPrivateFeeNotes,(q,outputs,envelopes,rows,slots,abi.encode(npk),hex""));
    }

    function testOrdinaryDepositCannotConsumeSwapCreditNonce() public {
        Direct pool=_pool(address(0));
        (bool ok,)=address(pool).call{value:1000}(_packet(pool,NONCE,101)); assertTrue(ok);
        assertTrue(pool.usedDepositNonce(NONCE)); assertFalse(pool.usedSwapCreditNonce(NONCE));
        (bytes memory packet,uint256 commitment)=_swapPacket(pool,NONCE,123);
        // The ordinary lane cannot select the one-note registry without admission.
        (ok,)=address(pool).call{value:1000}(packet); assertFalse(ok);
        assertFalse(pool.usedSwapCreditNonce(NONCE)); assertFalse(pool.commitmentSeen(commitment));
        clearanceFixture.allowSwap(address(this),address(pool),keccak256(packet));
        (ok,)=address(pool).call{value:999}(packet); assertFalse(ok);
        assertFalse(pool.usedSwapCreditNonce(NONCE)); assertFalse(pool.commitmentSeen(commitment));
        assertEq(pool.accountedLiability(),1000); assertEq(pool.nextRow(),35);
        (ok,)=address(pool).call{value:1000}(packet); assertTrue(ok);
        assertTrue(pool.usedSwapCreditNonce(NONCE)); assertTrue(pool.commitmentSeen(commitment));
        assertFalse(pool.usedNonce(NONCE)); assertEq(pool.accountedLiability(),2000); assertEq(pool.nextRow(),36);
        // Fresh checkpoint and distinct commitment cannot replay a consumed credit.
        (packet,commitment)=_swapPacket(pool,NONCE,124);
        clearanceFixture.allowSwap(address(this),address(pool),keccak256(packet));
        (ok,)=address(pool).call{value:1000}(packet); assertFalse(ok);
        assertFalse(pool.commitmentSeen(commitment)); assertEq(pool.accountedLiability(),2000);
    }

    function testSwapCreditCannotConsumeOrdinaryDepositNonce() public {
        Direct pool=_pool(address(0));
        (bytes memory packet,)=_swapPacket(pool,NONCE,123);
        clearanceFixture.allowSwap(address(this),address(pool),keccak256(packet));
        (bool ok,)=address(pool).call{value:1000}(packet); assertTrue(ok);
        assertTrue(pool.usedSwapCreditNonce(NONCE)); assertFalse(pool.usedDepositNonce(NONCE));
        (ok,)=address(pool).call{value:1000}(_packet(pool,NONCE,201)); assertTrue(ok);
        assertTrue(pool.usedDepositNonce(NONCE)); assertFalse(pool.usedNonce(NONCE));
        assertEq(pool.accountedLiability(),2000); assertEq(pool.nextRow(),36);
    }

    function _exit(Direct pool,bytes32 nonce) private {
        ExitPool.ExitQuote memory q; ExitPool.Exit8 memory p;
        (uint64 epoch,uint64 rows,uint256 x,uint256 y,uint256 checkpoint)=pool.currentSource();
        q.chainId=uint64(block.chainid); q.pool=address(pool); q.asset=address(pool.asset());
        q.width=8; q.sourceEpoch=epoch; q.sourceCheckpoint=checkpoint; q.recipient=RECIPIENT;
        q.payout=998; q.protocolFee=2; q.protocolFeeCap=2; q.protocolRecipient=PROTOCOL;
        q.saltedAmountHash=778; q.nonce=nonce; q.deadline=uint64(block.timestamp+600);
        q.feePolicyHash=pool.exitFeePolicyHash();
        p.action.pool=address(pool); p.action.token=address(pool.asset());
        p.action.recipient=RECIPIENT; p.action.protocolFeeRecipient=PROTOCOL;
        p.action.sourceSlotCount=rows; p.action.checkpointX=x; p.action.checkpointY=y;
        p.action.legCount=1; p.action.protocolFeeCap=2; p.action.saltedAmountHash=q.saltedAmountHash;
        for(uint256 i;i<8;++i) p.action.nullifiers[i]=1000+i;
        q.nullifiersHash=keccak256(abi.encode(p.action.nullifiers));
        q.outputsHash=keccak256(abi.encode(p.action.outputs));
        (p.action.feeQuoteDigestField,p.action.batchDigestField)=pool.exitDigestFields(q);
        pool.settleNoAppendExit8(q,p,"");
    }

    function testDepositAndExitCanUseSameNonceButDepositCannotReplay() public {
        Direct pool=_pool(address(0)); bytes memory packet=_packet(pool,NONCE,101);
        (bool ok,)=address(pool).call{value:1000}(packet); assertTrue(ok);
        assertTrue(pool.usedDepositNonce(NONCE)); assertFalse(pool.usedNonce(NONCE));
        assertEq(pool.accountedLiability(),1000); assertEq(pool.nextRow(),35);
        (ok,)=address(pool).call{value:1000}(packet); assertFalse(ok);
        _exit(pool,NONCE);
        assertTrue(pool.usedNonce(NONCE)); assertTrue(pool.usedDepositNonce(NONCE));
        assertEq(pool.accountedLiability(),0); assertEq(address(pool).balance,0);
        assertEq(RECIPIENT.balance,998); assertEq(PROTOCOL.balance,2);
    }

    function testExitNonceCannotBlockSubsequentDeposit() public {
        Direct pool=_pool(address(0));
        (bool ok,)=address(pool).call{value:1000}(_packet(pool,bytes32(uint256(998)),101)); assertTrue(ok);
        _exit(pool,NONCE);
        assertTrue(pool.usedNonce(NONCE)); assertFalse(pool.usedDepositNonce(NONCE));
        (ok,)=address(pool).call{value:1000}(_packet(pool,NONCE,201)); assertTrue(ok);
        assertTrue(pool.usedDepositNonce(NONCE)); assertEq(pool.accountedLiability(),1000);
    }

    function testNativeUnderpaymentRollsBackEntireDeposit() public {
        Direct pool=_pool(address(0)); bytes memory packet=_packet(pool,NONCE,101);
        (bool ok,bytes memory reason)=address(pool).call{value:999}(packet);
        assertFalse(ok); assertEq(bytes4(reason),Logic.AssetTransferMismatch.selector);
        assertFalse(pool.usedDepositNonce(NONCE)); assertFalse(pool.commitmentSeen(101));
        assertEq(pool.accountedLiability(),0); assertEq(address(pool).balance,0); assertEq(pool.nextRow(),32);
        (ok,)=address(pool).call{value:1000}(packet); assertTrue(ok);
        assertEq(pool.accountedLiability(),1000); assertEq(address(pool).balance,1000);
    }

    function testTokenShortReceiptAndAttachedValueRollBackThenExactReceiptSucceeds() public {
        FyeoTokenFixture token=new FyeoTokenFixture(); Direct pool=_pool(address(token));
        token.approve(address(pool),1000); bytes memory packet=_packet(pool,NONCE,101);
        (bool ok,bytes memory reason)=address(pool).call{value:1}(packet);
        assertFalse(ok); assertEq(bytes4(reason),Logic.AssetTransferMismatch.selector);
        token.setShortTransfer(true);
        (ok,reason)=address(pool).call(packet);
        assertFalse(ok); assertEq(bytes4(reason),Logic.AssetTransferMismatch.selector);
        assertFalse(pool.usedDepositNonce(NONCE)); assertFalse(pool.commitmentSeen(101));
        assertEq(pool.accountedLiability(),0); assertEq(pool.nextRow(),32);
        assertEq(token.balanceOf(address(pool)),0); assertEq(token.balanceOf(address(this)),10000);
        assertEq(token.allowance(address(this),address(pool)),1000);
        token.setShortTransfer(false);
        (ok,)=address(pool).call(packet); assertTrue(ok);
        assertTrue(pool.usedDepositNonce(NONCE)); assertFalse(pool.usedNonce(NONCE));
        assertEq(pool.accountedLiability(),1000); assertEq(token.balanceOf(address(pool)),1000);
    }
}
