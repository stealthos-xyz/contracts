// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool} from "../src/vanta/VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaFamilyReleaseBinding} from "../src/vanta/VantaFamilyReleaseBinding.sol";
import {VantaFamilyProtocolFeePolicy as Policy} from "../src/vanta/VantaFamilyProtocolFeePolicy.sol";
import {VantaFamilyCombinedFeePartnerAdapterPreAudit as Combined} from "../src/vanta/VantaFamilyCombinedFeePartnerAdapterPreAudit.sol";
import {VantaFamilyFullBundleVerifierPreAudit as Bundle} from "../src/vanta/VantaFamilyFullBundleVerifierPreAudit.sol";
import {VantaFamilyAggregateGroth16PreAudit as Agg} from "../src/vanta/VantaFamilyAggregateGroth16PreAudit.sol";
import {VantaV8StatementResearch as S8} from "../src/vanta/VantaV8StatementResearch.sol";
import {VantaV8Statement32Research as S32} from "../src/vanta/VantaV8Statement32Research.sol";
import {VantaV8FiveRowKzgResearch as Kzg} from "../src/vanta/VantaV8FiveRowKzgResearch.sol";
import {VantaEpochCheckpointRef as Ref} from "../src/vanta/VantaEpochCheckpointRef.sol";

// Deliberately unsound proof mocks isolate contract admission and atomicity.
// They are not artifacts for a ceremony, deployment or funded proof test.
contract RoutedProofMock is VantaFamilyReleaseBinding {
 bool public gate=true;bool public payout=true;
 constructor() VantaFamilyReleaseBinding(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid) {}
 function CHAIN_ID() external view returns(uint64){return uint64(block.chainid);}
 function setAllowed(bool g,bool a) external {gate=g;payout=a;}
 function verifyEpoch8(S8.LegPublic calldata,Bundle.V8Gate0Data calldata,Bundle.Gate1Data calldata,Bundle.LinkData calldata,bool,uint64,uint64,uint64,uint256,uint256) external view returns(bool){return gate;}
 function verifyEpoch32(S32.LegPublic calldata,Bundle.V8Gate0Data calldata,Bundle.Gate1Data calldata,Bundle.LinkData calldata,bool,uint64,uint64,uint64,uint256,uint256) external view returns(bool){return gate;}
 function verifyPayout(Agg.VerifyingKey calldata,Agg.Proof calldata,uint256[11] calldata input,uint256 batch,uint256 hidden,uint256 amount) external view returns(bool){
  if(!payout||input[0]!=batch||input[1]!=1||input[2]!=amount||input[3]!=hidden)return false;
  for(uint256 i=4;i<11;i++)if(input[i]!=0)return false;return true;
 }
}
contract RoutedCombinedMock is VantaFamilyReleaseBinding {
 Policy public immutable policy;bool public allowed=true;
 constructor(Policy p) VantaFamilyReleaseBinding(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid){policy=p;}
 function protocolBpsFor(uint8 op) external view returns(uint16){return policy.rate(op);}
 function setAllowed(bool a) external {allowed=a;}
 function verifyCombined(Combined.CanonicalQuote calldata q,bytes calldata) external view returns(bool){return allowed&&q.mode<=5;}
}
contract RoutedKzgMock {
 function verifyEpochRows(uint64 epoch,uint64 row,uint256 x,uint256 y,uint8 count,uint256[5] calldata,Kzg.RowKey[5] calldata) external pure returns(uint256,uint256,uint256,uint256){
  return(Ref.compute(epoch,row,x,y),Ref.compute(epoch,row+count,x,y),x,y);
 }
}
contract RoutedPoolHarness is Pool {
 constructor(address exit_,address normal_,address combined_,address kzg_,address signer_,address protocol_,address policy_)
  Pool(address(0),exit_,normal_,combined_,kzg_,1,2,signer_,protocol_,address(0),0,0,bytes32(uint256(7)),
   [uint16(15),uint16(0)],bytes32(uint256(2)),protocol_,bytes32(uint256(1)),bytes32(uint256(3)),block.chainid,policy_){}
 function seed() external {accountedLiability=2000;}
}
contract VantaFamilyRoutedSettlementTest is Test {
 uint256 constant KEY=0xA111CE;address constant USER=address(0x1234);
 RoutedPoolHarness pool;RoutedProofMock normal;RoutedCombinedMock combined;Policy policy;
 function setUp() public {
  vm.chainId(6281971);
  policy=new Policy(address(this),bytes32(uint256(7)),[uint16(15),uint16(20),uint16(0),uint16(30),uint16(40),uint16(70)],
   bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid);
  normal=new RoutedProofMock();combined=new RoutedCombinedMock(policy);
  pool=new RoutedPoolHarness(address(new RoutedProofMock()),address(normal),address(combined),address(new RoutedKzgMock()),vm.addr(KEY),address(this),address(policy));
  vm.deal(address(pool),2000);pool.seed();
 }
 function sign(bytes32 digest) private pure returns(bytes memory){(uint8 v,bytes32 r,bytes32 s)=vm.sign(KEY,digest);return abi.encodePacked(r,s,v);}
 function prepare(uint8 mode) private view returns(Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p){
  (uint64 epoch,uint64 rows,uint256 x,uint256 y,uint256 checkpoint)=pool.currentSource();
  q.chainId=uint64(block.chainid);q.pool=address(pool);q.asset=address(0);q.width=8;q.mode=mode;
  q.sourceEpoch=epoch;q.targetEpoch=epoch;q.sourceCheckpoint=checkpoint;q.targetCheckpoint=checkpoint;
  q.recipient=USER;q.payout=1000;q.protocolFeeCap=uint128((uint256(1000)*policy.rate(mode)+9999)/10000);q.partnerFeeCap=7;
  q.protocolRecipient=address(this);q.partnerRecipient=address(0);q.relayer=address(this);q.saltedAmountHash=701;
  q.feeTermsHash=702;q.partnerRegistryRoot=703;q.nonce=bytes32(uint256(704));q.deadline=uint64(block.timestamp+600);q.feePolicyHash=pool.feePolicyHash();
  p.action.pool=address(pool);p.action.token=address(0);p.action.recipient=USER;p.action.protocolFeeRecipient=address(this);
  p.action.sourceSlotCount=rows;p.action.checkpointX=x;p.action.checkpointY=y;p.action.legCount=1;
  p.action.protocolFeeCap=q.protocolFeeCap;p.action.partnerFeeCap=q.partnerFeeCap;p.action.saltedAmountHash=q.saltedAmountHash;
  bytes32[5] memory hashes;
  for(uint256 i;i<8;i++)p.action.nullifiers[i]=800+i;
  for(uint256 i;i<5;i++){p.action.outputs[i]=900+i;p.encryptedOutputs[i]=new bytes(96);p.encryptedOutputs[i][0]=0x01;hashes[i]=keccak256(p.encryptedOutputs[i]);}
  p.feeSlots=[uint8(1),uint8(2),uint8(3)];q.feeSlotsHash=keccak256(abi.encode(p.feeSlots));
  q.nullifiersHash=keccak256(abi.encode(p.action.nullifiers));q.outputsHash=keccak256(abi.encode(p.action.outputs));q.envelopesHash=keccak256(abi.encode(hashes));
  (p.action.feeQuoteDigestField,p.action.batchDigestField)=pool.normalDigestFields(q);
  p.aggregateInputs[0]=p.action.batchDigestField;p.aggregateInputs[1]=1;p.aggregateInputs[2]=q.payout;p.aggregateInputs[3]=q.saltedAmountHash;
 }
 function assertUntouched(Pool.NormalEpochQuote memory q) private view {assertFalse(pool.usedNonce(q.nonce));assertFalse(pool.nullifierSpent(800));assertEq(pool.accountedLiability(),2000);assertEq(USER.balance,0);}
 function testSwapUsesSwapRateAndAggregateOnce() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p)=prepare(4);assertEq(q.protocolFeeCap,4);
  vm.expectCall(address(normal),abi.encodeWithSelector(RoutedProofMock.verifyPayout.selector,p.aggregateVk,p.aggregateProof,p.aggregateInputs,p.action.batchDigestField,q.saltedAmountHash,uint256(q.payout)),1);
  pool.settleNormalEpoch8(q,p,sign(pool.normalQuoteDigest(q)));assertEq(USER.balance,1000);assertTrue(pool.usedNonce(q.nonce));assertTrue(pool.nullifierSpent(800));
 }
 function testBridgeUsesBridgeRate() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p)=prepare(5);assertEq(q.protocolFeeCap,7);
  pool.settleNormalEpoch8(q,p,sign(pool.normalQuoteDigest(q)));assertEq(USER.balance,1000);
 }
 function testSwapCannotUseWithdrawalRateEvenWithValidSigner() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p)=prepare(4);q.protocolFeeCap=2;p.action.protocolFeeCap=2;
  (p.action.feeQuoteDigestField,p.action.batchDigestField)=pool.normalDigestFields(q);
  bytes memory sig=sign(pool.normalQuoteDigest(q));vm.expectRevert(Pool.InvalidNormalFeeProof.selector);pool.settleNormalEpoch8(q,p,sig);assertUntouched(q);
 }
 function testInvalidAggregateCannotConsumeInputs() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p)=prepare(5);normal.setAllowed(true,false);
  bytes memory sig=sign(pool.normalQuoteDigest(q));vm.expectRevert(Pool.InvalidNormalProof.selector);pool.settleNormalEpoch8(q,p,sig);assertUntouched(q);
 }
 function testSplicedAmountCannotConsumeInputs() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p)=prepare(4);p.aggregateInputs[2]=999;
  bytes memory sig=sign(pool.normalQuoteDigest(q));vm.expectRevert(Pool.InvalidNormalProof.selector);pool.settleNormalEpoch8(q,p,sig);assertUntouched(q);
 }
 function testInvalidPartnerProofStillBlocksRoutedPayout() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p)=prepare(5);combined.setAllowed(false);
  bytes memory sig=sign(pool.normalQuoteDigest(q));vm.expectRevert(Pool.InvalidNormalFeeProof.selector);pool.settleNormalEpoch8(q,p,sig);assertUntouched(q);
 }
 function testUnsupportedModeIsRejectedBeforePayout() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p)=prepare(3);
  bytes memory sig=sign(pool.normalQuoteDigest(q));vm.expectRevert(Pool.InvalidNormalSpend.selector);pool.settleNormalEpoch8(q,p,sig);assertUntouched(q);
 }
 function testSingleWithdrawalDoesNotRunRoutedAggregateAgain() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory p)=prepare(0);normal.setAllowed(true,false);
  pool.settleNormalEpoch8(q,p,sign(pool.normalQuoteDigest(q)));assertEq(USER.balance,1000);
 }
 function testBridgeThirtyTwoKeepsPayoutBinding() public {
  (Pool.NormalEpochQuote memory q,Pool.EpochSpend8 memory small)=prepare(5);q.width=32;Pool.EpochSpend32 memory p;
  p.action.pool=small.action.pool;p.action.token=small.action.token;p.action.recipient=small.action.recipient;
  p.action.protocolFeeRecipient=small.action.protocolFeeRecipient;p.action.sourceSlotCount=small.action.sourceSlotCount;
  p.action.checkpointX=small.action.checkpointX;p.action.checkpointY=small.action.checkpointY;p.action.legCount=1;
  p.action.protocolFeeCap=q.protocolFeeCap;p.action.partnerFeeCap=q.partnerFeeCap;p.action.saltedAmountHash=q.saltedAmountHash;
  p.action.outputs=small.action.outputs;p.encryptedOutputs=small.encryptedOutputs;p.feeSlots=small.feeSlots;
  for(uint256 i;i<32;i++)p.action.nullifiers[i]=800+i;q.nullifiersHash=keccak256(abi.encode(p.action.nullifiers));
  (p.action.feeQuoteDigestField,p.action.batchDigestField)=pool.normalDigestFields(q);
  p.aggregateInputs[0]=p.action.batchDigestField;p.aggregateInputs[1]=1;p.aggregateInputs[2]=q.payout;p.aggregateInputs[3]=q.saltedAmountHash;
  pool.settleNormalEpoch32(q,p,sign(pool.normalQuoteDigest(q)));assertEq(USER.balance,1000);assertTrue(pool.nullifierSpent(831));
 }
}
