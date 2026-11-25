// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {VantaNativeWalletClearance} from "./VantaNativeWalletClearance.sol";
interface IFamilySwapIngressGateway {
    function isActiveIngress(address escrow,address pool,bytes32 calldataHash) external view returns(bool);
}
/// Native screening plus a separate immutable internal-swap provenance gate.
/// Screening signer rotation cannot grant this permission or change its target.
contract VantaNativeSwapWalletClearance is VantaNativeWalletClearance {
    address public immutable privateSwapGateway;
    constructor(address administrator_,address signer_,bytes32 policyHash_,bytes32 setupId,
        bytes32 generationId,bytes32 familyTag,uint256 chainId,address gateway)
        VantaNativeWalletClearance(administrator_,signer_,policyHash_,setupId,generationId,familyTag,chainId) {
        if(gateway==address(0))revert InvalidClearance();
        privateSwapGateway=gateway;
    }
    function isSwapIngress(address escrow,address pool,bytes32 dataHash) external view onlyReleaseChain returns(bool) {
        return msg.sender==pool && privateSwapGateway.code.length!=0 &&
            IFamilySwapIngressGateway(privateSwapGateway).isActiveIngress(escrow,pool,dataHash);
    }
}
