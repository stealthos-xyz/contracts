// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {VantaFamilyUnifiedPoolPreAudit as Pool,VantaV8UnifiedNormalSpendLogic as Logic} from "../src/vanta/VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaEpochStateV1 as State} from "../src/vanta/VantaEpochStateV1.sol";
import {VantaEpochCheckpointRef} from "../src/vanta/VantaEpochCheckpointRef.sol";
import {VantaV8FiveRowKzgResearch as Kzg} from "../src/vanta/VantaV8FiveRowKzgResearch.sol";
import {VantaFamilyFiveRowKzgPreAudit as FamilyKzg} from "../src/vanta/VantaFamilyFiveRowKzgPreAudit.sol";
import {VantaTokenHash} from "../src/vanta/VantaTokenHash.sol";
import {PoseidonT4} from "../src/libraries/PoseidonT4.sol";
contract SwapAdmissionFixture {
 bytes32 public allowed;bool public active;
 function allow(bytes32 h,bool a)external{allowed=h;active=a;}
 error ScreeningUnavailable();
 function requireClearance(address,bytes calldata encoded)external view{if(!active||encoded.length!=0)revert ScreeningUnavailable();}
 function isSwapIngress(address,address pool,bytes32 h)external view returns(bool){return active&&msg.sender==pool&&allowed==h;}
}
contract SwapIngressHarness {
 using State for State.State;State.State state;mapping(bytes32=>bool)public used;mapping(uint256=>bool)public seen;
 address immutable updater;address immutable gate;
 constructor(address u,address g,uint256 x,uint256 y){updater=u;gate=g;state.initialize(x,y);
  state.epochs[0].slotCount=33;state.epochs[0].currentRef=VantaEpochCheckpointRef.compute(0,33,x,y);}
 function checkpoint()external view returns(uint256){return state.epochs[0].currentRef;}
 function rows()external view returns(uint64){return state.epochs[0].slotCount;}
 function depositWithPrivateFeeNotes(Pool.PrivateFeeDepositQuote calldata q,uint256[5] calldata outputs,bytes[5] calldata env,
  Kzg.RowKey[5] calldata keys,uint8[2] calldata slots,bytes calldata opening,bytes calldata clearance)external payable returns(uint256){
  Logic.Pins memory pins;pins.kzgUpdater=updater;pins.feePolicyHash=bytes32(uint256(8));
  return Logic.directDeposit(state,used,seen,q,outputs,env,keys,slots,opening,bytes32(0),pins,gate,clearance);
 }
}
/// The row key and starting point below come from the existing deployed
/// ceremony and canonical Chikyu fixture at block 9574142. Its SHA-256 path was
/// independently matched to approvedKzgUpdater.keys.acceptedResearchRoot.
/// This exercises REAL Poseidon and REAL authenticated KZG EVM arithmetic;
/// only screening/admission is an explicit boundary fixture.
contract VantaFamilySwapIngressTest is Test {
 SwapAdmissionFixture gate;SwapIngressHarness pool;FamilyKzg updater;
 function setUp()public{vm.chainId(6281971);vm.warp(1000);gate=new SwapAdmissionFixture();
  updater=new FamilyKzg(0xd0acb3cf558621a2ca09fb448c31b9048c3fff4887ba1ddd9c25f83dad213cb8,bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),6281971);
  vm.deal(address(this),100 ether);
  pool=new SwapIngressHarness(address(updater),address(gate),18748594744334721918775612369910432214884311383548206814505943691586936577870,20251746168959964454885615267872739662636101328900774802651254122346874777268);
 }
 function _keys()internal pure returns(Kzg.RowKey[5]memory keys){
 keys[0].a.x=1509130004300454342997199873132217012442945213271993944249797828592111006010;keys[0].a.y=3476282622677076233517372428786810033639456145667388761406356295146676253584;
 keys[0].u.x=10040315652302213512548472275476920196233535144181192431685649052036489374084;keys[0].u.y=15625519610777887785204653332128199767082824850715293951770608498246456691683;
 keys[0].aCompressed=0x3a31b1b7eb105f8453e665dab1da991bef0ca24d6a261c49c965fef026235603;keys[0].uCompressed=0x8469a5e9bea69f0d7afd0dec7baf5f6f988d24b050bb7b72f2863fb9059e3296;
 keys[0].siblings[0]=0x23976119eb469061ae4e219a4b8681a707fb6dfdb751caee6ecb83f5dec03c01;
 keys[0].siblings[1]=0x6412f24d948c74788d216f619ebe1f6aac09d854eeb1aa171551644b578b59ed;
 keys[0].siblings[2]=0x6afd68de47edfbf1491214b120bace37953b5be84fe2c81e9f90589457491760;
 keys[0].siblings[3]=0x13a3a96b071380bc871efeabc3242568a4cfb79022703519230cce795371701e;
 keys[0].siblings[4]=0x3b6fe2e7f562f87e1025c6170707860db1e225ef26cdc11ff73b49814a0ae418;
 keys[0].siblings[5]=0x67460b36dccfcf52e3acb99a3871f6bed26f9d48f352dc0b56abcdbfda825bc6;
 keys[0].siblings[6]=0xa22f87ea59b94620bd38f57662873ba387c82d91f9d15d99d2e45a5fcc19bb1e;
 keys[0].siblings[7]=0xbdd4be885790fea658e9a17143388ae367e93a8dc93838822da0322e38f6b21f;
 keys[0].siblings[8]=0x1bdcea0796eb1db07f226b201146392796218020c45a7b3ee5299c981ec9f8da;
 keys[0].siblings[9]=0xdfe46f8d4b3d5dab5264026225a0d55f13b8b05b46d551d4e9c0b6a284366f05;
 keys[0].siblings[10]=0x2fb757ff8a5d199fd87edb6d84890220f63bdd7b95bbc71ee09bb0e6df458244;
 keys[0].siblings[11]=0xb1bc2018460c1e6f8064e911a4276d97b7edb68d5eba59d3cb0503c654e10b2e;
 keys[0].siblings[12]=0xd5b95c91e638a482c4a494a82cc3b126e21cadb78b180a05eba29b8e8d940d4e;
 keys[0].siblings[13]=0xef27f2f51f50dde59915986dc677376d42f5fd503ed5b1c585f30fea2e356d7b;
 keys[0].siblings[14]=0xc96742cab403775b2b45bff9f4d3136e9000c2d563c6048b730e8814760ab67f;
 keys[0].siblings[15]=0xa77539b3e5bdc29e34ecd3ddd43dd7aaacaffe8e637839ed57978a6fb13a6500;
 }
 function _data(uint128 value,uint256 committedValue)internal view returns(bytes memory data){return _dataForCount(value,committedValue,1,hex"");}
 function _dataForCount(uint128 value,uint256 committedValue,uint8 count,bytes memory clearance)internal view returns(bytes memory data){
  uint256 npk=123;uint256 cm=PoseidonT4.hash([npk,VantaTokenHash.compute(block.chainid,address(pool),address(0)),committedValue]);
  Pool.PrivateFeeDepositQuote memory q;q.chainId=6281971;q.pool=address(pool);q.epoch=0;q.checkpoint=pool.checkpoint();q.payer=address(this);
  q.count=count;q.gross=value;q.nonce=bytes32(uint256(999));q.deadline=1500;q.feePolicyHash=bytes32(uint256(8));
  uint256[5]memory outputs;outputs[0]=cm;bytes[5]memory env;env[0]=new bytes(829);env[0][0]=0x01;
  bytes32[5]memory hashes;hashes[0]=keccak256(env[0]);uint8[2]memory slots;
  q.outputsHash=keccak256(abi.encode(outputs));q.envelopesHash=keccak256(abi.encode(hashes));q.feeSlotsHash=keccak256(abi.encode(slots));
  return abi.encodeCall(SwapIngressHarness.depositWithPrivateFeeNotes,(q,outputs,env,_keys(),slots,abi.encode(npk),clearance));
 }
 function _run(bytes memory data)internal returns(bool,bytes memory){gate.allow(keccak256(data),true);return address(pool).call{value:20 ether}(data);}
 function testRealCeremonyKzgKeyAppendsExactPoseidonValue()public{bytes memory data=_data(20 ether,20 ether);gate.allow(keccak256(data),true);
  uint256 beforeGas=gasleft();(bool ok,bytes memory result)=address(pool).call{value:20 ether}(data);emit log_named_uint("real single-row ingress gas",beforeGas-gasleft());
  assertTrue(ok);assertEq(result.length,32);assertEq(pool.rows(),34);assertTrue(pool.used(bytes32(uint256(999))));assertEq(address(pool).balance,20 ether);
  (ok,)=address(pool).call{value:20 ether}(data);assertFalse(ok);assertEq(pool.rows(),34);assertEq(address(pool).balance,20 ether);
 }
 function testIncorrectValueRollsBackVerifiedKzgAppendAndNonce()public{
  bytes memory data=_data(20 ether,20 ether);gate.allow(keccak256(data),true);
  uint256 beforeRef=pool.checkpoint();
  (bool ok,bytes memory reason)=address(pool).call{value:19 ether}(data);
  assertFalse(ok);assertEq(bytes4(reason),Logic.AssetTransferMismatch.selector);
  assertEq(pool.checkpoint(),beforeRef);assertEq(pool.rows(),33);
  assertFalse(pool.used(bytes32(uint256(999))));assertEq(address(pool).balance,0);
  (ok,)=address(pool).call{value:20 ether}(data);
  assertTrue(ok);assertEq(pool.rows(),34);assertEq(address(pool).balance,20 ether);
 }
 function testValueInflationCannotBypassFeesOrConservation()public{bytes memory data=_data(20 ether,21 ether);(bool ok,)=_run(data);assertFalse(ok);assertEq(pool.rows(),33);assertFalse(pool.used(bytes32(uint256(999))));}
 function testOrdinaryDepositCannotUseOneNoteExemption()public{bytes memory data=_data(20 ether,20 ether);gate.allow(keccak256(data),false);(bool ok,)=address(pool).call(data);assertFalse(ok);assertEq(pool.rows(),33);}
 function testExternalIngressStillRequiresScreening()public{bytes memory data=_dataForCount(20 ether,20 ether,3,hex"");gate.allow(keccak256(data),false);(bool ok,bytes memory reason)=address(pool).call(data);assertFalse(ok);assertEq(bytes4(reason),SwapAdmissionFixture.ScreeningUnavailable.selector);assertEq(pool.rows(),33);}
 function testInternalIngressRejectsUnexpectedClearanceBytes()public{bytes memory data=_dataForCount(20 ether,20 ether,1,hex"01");(bool ok,)=_run(data);assertFalse(ok);assertEq(pool.rows(),33);}
 function testChangingCalldataBreaksGatewayProvenance()public{bytes memory data=_data(20 ether,20 ether);gate.allow(bytes32(uint256(1)),true);(bool ok,)=address(pool).call(data);assertFalse(ok);}
 function testUnauthenticatedKzgKeyCannotCreateNote()public{bytes memory data=_data(20 ether,20 ether);
  // First row-key a.x is a static word after q(20) + outputs(5) + env-offset.
  // Corrupt the entire wire at the authenticated point, preserving all note
  // hashes; the genuine KZG updater rejects it before any state change.
  assembly("memory-safe"){mstore(add(data,add(36,mul(26,32))),123)}
  (bool ok,)=_run(data);assertFalse(ok);assertEq(pool.rows(),33);
 }
}
