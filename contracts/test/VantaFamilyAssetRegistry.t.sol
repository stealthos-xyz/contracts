// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {PoseidonT3RealLib as PoseidonT3} from "./generated/PoseidonT3Real.sol";
import {PoseidonT4} from "../src/libraries/PoseidonT4.sol";
import {VantaFamilyReleaseBinding} from "../src/vanta/VantaFamilyReleaseBinding.sol";
import {VantaFamilyPartnerKzgRegistrarPreAudit as Registrar} from "../src/vanta/VantaFamilyPartnerKzgRegistrarPreAudit.sol";

contract AssetRegistryHasher {
 function hash(uint256[2] memory input) external pure returns(uint256){return PoseidonT3.hash(input);}
 function hash(uint256[3] memory input) external pure returns(uint256){return PoseidonT4.hash(input);}
}
// Identity/read-surface fixtures only. These are not custody or proof verifiers.
contract AssetRegistryHandle { function chainId() external view returns(uint256){return block.chainid;} }
contract AssetRegistryOwner {}
contract AssetRegistryToken { uint256 public fixture; }
contract AssetRegistryPool is VantaFamilyReleaseBinding {
 address public immutable asset;
 bytes32 public constant releaseGenesisHash=bytes32(uint256(99));
 constructor(address token) VantaFamilyReleaseBinding(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid){asset=token;}
}
contract VantaFamilyAssetRegistryTest is Test {
 Registrar reg;address usd1;address usdc;address bnm;address hasher;address handles;address owner;
 function fresh() private returns(Registrar){return new Registrar(hasher,bytes32(uint256(4)),handles,owner,usd1,
  bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),block.chainid,bytes32(uint256(99)));}
 function setUp() public {
  vm.chainId(6281971);hasher=address(new AssetRegistryHasher());handles=address(new AssetRegistryHandle());owner=address(new AssetRegistryOwner());
  usd1=address(new AssetRegistryToken());usdc=address(new AssetRegistryToken());bnm=address(new AssetRegistryToken());reg=fresh();
 }
 function additions() private view returns(address[] memory assets,bytes32[] memory hashes){
  assets=new address[](2);hashes=new bytes32[](2);assets[0]=usdc;assets[1]=bnm;hashes[0]=usdc.codehash;hashes[1]=bnm.codehash;
 }
 function registerAll() private returns(address[] memory pools){
  (address[] memory assets,bytes32[] memory hashes)=additions();reg.configureAdditionalAssets(assets,hashes);
  address[] memory tokens=reg.canonicalAssets();pools=new address[](tokens.length);
  for(uint256 i;i<tokens.length;i++){pools[i]=address(new AssetRegistryPool(tokens[i]));reg.registerCanonicalPool(pools[i],tokens[i]);}
 }
 function testEveryConfiguredAssetHasOneExactPool() public {
  address[] memory pools=registerAll();address[] memory assets=reg.canonicalAssets();assertEq(assets.length,4);
  assertEq(assets[0],address(0));assertEq(assets[1],usd1);assertEq(assets[2],usdc);assertEq(assets[3],bnm);
  for(uint256 i;i<4;i++)assertEq(reg.registry().activePoolForAsset(assets[i]),pools[i]);
 }
 function testAssetConfigurationCannotChangeAfterPoolRegistration() public {
  reg.registerCanonicalPool(address(new AssetRegistryPool(address(0))),address(0));
  (address[] memory assets,bytes32[] memory hashes)=additions();vm.expectRevert(Registrar.InvalidAuthorization.selector);reg.configureAdditionalAssets(assets,hashes);
  assertEq(reg.canonicalAssets().length,2);
 }
 function testOnlyBootstrapDeployerCanConfigureAssets() public {
  (address[] memory assets,bytes32[] memory hashes)=additions();vm.prank(address(0x1234));vm.expectRevert(Registrar.InvalidAuthorization.selector);reg.configureAdditionalAssets(assets,hashes);
  assertEq(reg.canonicalAssets().length,2);
 }
 function testDuplicateOrUnpinnedAssetConfigurationRollsBackAtomically() public {
  (address[] memory assets,bytes32[] memory hashes)=additions();assets[1]=assets[0];
  vm.expectRevert(Registrar.PoolUnavailable.selector);reg.configureAdditionalAssets(assets,hashes);assertEq(reg.canonicalAssets().length,2);
  assets[1]=bnm;hashes[1]=bytes32(uint256(1));vm.expectRevert(Registrar.PoolUnavailable.selector);reg.configureAdditionalAssets(assets,hashes);
  hashes[1]=bnm.codehash;reg.configureAdditionalAssets(assets,hashes);assertEq(reg.canonicalAssets().length,4);
 }
 function testChangingTokenCodeBlocksItsPool() public {
  (address[] memory assets,bytes32[] memory hashes)=additions();reg.configureAdditionalAssets(assets,hashes);
  address pool=address(new AssetRegistryPool(usdc));vm.etch(usdc,hex"60006000fd");
  vm.expectRevert(Registrar.PoolUnavailable.selector);reg.registerCanonicalPool(pool,usdc);
  assertEq(reg.registry().activePoolForAsset(usdc),address(0));
 }
 function testUnconfiguredAssetCannotAcquirePool() public {
  address pool=address(new AssetRegistryPool(usdc));vm.expectRevert(Registrar.PoolUnavailable.selector);reg.registerCanonicalPool(pool,usdc);
 }
 function testOwnerActionBindsEveryPoolCheckpointAndCannotOmitBridgeAsset() public {
  registerAll();uint256[] memory checkpoints=new uint256[](4);for(uint256 i;i<4;i++)checkpoints[i]=i+10;
  bytes32 handle=bytes32(uint256(50));uint64 deadline=uint64(block.timestamp+600);
  uint256 digest=reg.updateActionDigest(handle,51,bytes32(uint256(52)),1,checkpoints,deadline);
  checkpoints[3]++;assertTrue(digest!=reg.updateActionDigest(handle,51,bytes32(uint256(52)),1,checkpoints,deadline));
  uint256[] memory omitted=new uint256[](2);omitted[0]=10;omitted[1]=11;
  vm.expectRevert(Registrar.InvalidAuthorization.selector);reg.updateActionDigest(handle,51,bytes32(uint256(52)),1,omitted,deadline);
 }
}
