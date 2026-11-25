// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyGate0CcGroth16PreAudit} from "./VantaFamilyGate0CcGroth16PreAudit.sol";
import {VantaCaulkPlusGate1Research} from "./VantaCaulkPlusGate1Research.sol";
import {VantaCpLinkPairingResearch} from "./VantaCpLinkPairingResearch.sol";

/// @notice Genuine Gate0+Gate1+CP_link EVM verification in ONE research call.
/// @dev NO FUNDS, NO SETTLEMENT, NO CHECKPOINT AUTHORIZATION.
///      This accepts caller-supplied RESEARCH keys, table and context. It
///      proves only the three native cryptographic equations compose on EVM.
///      A real pool MUST immutably pin reviewed verifier keys and authenticate
///      the checkpoint and canonical action statement before atomic settlement.
contract VantaFamilyFullBundleVerifierPreAudit {
    VantaFamilyGate0CcGroth16PreAudit public immutable gate0Verifier;
    VantaCaulkPlusGate1Research public immutable gate1Verifier;
    VantaCpLinkPairingResearch public immutable linkVerifier;

    struct Gate0Data {
        VantaFamilyGate0CcGroth16PreAudit.VerifyingKey vk;
        VantaFamilyGate0CcGroth16PreAudit.Proof proof;
        uint256 statement;
    }

    struct V8Gate0Data {
        VantaFamilyGate0CcGroth16PreAudit.V8VerifyingKey vk;
        VantaFamilyGate0CcGroth16PreAudit.Proof proof;
        // [public statement, protocol fee cap, partner fee cap, amount hash]
        uint256[6] publicInputs;
    }

    struct Gate1Data {
        VantaCaulkPlusGate1Research.Table table;
        VantaCaulkPlusGate1Research.Srs srs;
        VantaCaulkPlusGate1Research.Proof proof;
        bytes context;
    }

    struct LinkData {
        VantaCpLinkPairingResearch.G1 pi;
        VantaCpLinkPairingResearch.G2 a2;
        VantaCpLinkPairingResearch.G2 c1;
        VantaCpLinkPairingResearch.G2 c2;
    }

    constructor(address gate0, address gate1, address link) {
        require(gate0.code.length != 0 && gate1.code.length != 0 &&
            link.code.length != 0, "Vanta research verifier missing");
        gate0Verifier = VantaFamilyGate0CcGroth16PreAudit(gate0);
        gate1Verifier = VantaCaulkPlusGate1Research(gate1);
        linkVerifier = VantaCpLinkPairingResearch(link);
    }

    /// @notice Rejects unless ALL THREE genuine verifier equations pass.
    /// @dev CP_link D/E derive from the exact Gate0 and Gate1 proof objects,
    ///      preventing an independently chosen link commitment substitution.
    function verifyResearchBundle(
        Gate0Data calldata g0, Gate1Data calldata g1, LinkData calldata link
    ) external view returns (bool) {
        return _verifyResearchBundle(32, g0, g1, link);
    }

    /// @notice The caller must supply the exact proof-family arity.
    /// @dev Both families still accept research keys and authenticate NO
    /// checkpoint or funds. This is not a pool admission API.
    function verifyResearchBundleForArity(
        uint8 arity, Gate0Data calldata g0,
        Gate1Data calldata g1, LinkData calldata link
    ) external view returns (bool) {
        return _verifyResearchBundle(arity, g0, g1, link);
    }

    /// @notice Native V8 research full-bundle parity: actual six-input
    /// Gate0 ccGroth16, Caulk+ of the same arity and CP_link of exact D/E.
    /// @dev The VK, SRS and table are CALLER-SUPPLIED in this experiment.
    /// The output cannot authorize assets until immutable reviewed key and
    /// checkpoint pins, public statement reconstruction and KZG updates exist.
    function verifyV8ResearchBundle(
        uint8 arity, V8Gate0Data calldata g0,
        Gate1Data calldata g1, LinkData calldata link
    ) external view returns (bool) {
        if ((arity != 8 && arity != 32) || g1.table.n != 65_536) return false;
        if (!gate0Verifier.verifyFamily(
            g0.vk, g0.proof, g0.publicInputs
        )) return false;
        if (!gate1Verifier.verifyResearchForArity(
            arity, g1.table, g1.srs, g1.proof, g1.context
        )) return false;
        // Cross-gate equality uses proof D and the authentic Gate1 query
        // point, never separately caller-provided D/E substitutions.
        VantaCpLinkPairingResearch.G1 memory d =
            VantaCpLinkPairingResearch.G1(g0.proof.d.x, g0.proof.d.y);
        VantaCpLinkPairingResearch.G1 memory e =
            VantaCpLinkPairingResearch.G1(g1.table.query.x, g1.table.query.y);
        return linkVerifier.verifyResearch(
            link.pi, d, e, link.a2, link.c1, link.c2
        );
    }

    function _verifyResearchBundle(
        uint8 arity, Gate0Data calldata g0,
        Gate1Data calldata g1, LinkData calldata link
    ) private view returns (bool) {
        if ((arity != 8 && arity != 32) || g1.table.n != 65_536) return false;
        if (!gate0Verifier.verifyResearch(g0.vk, g0.proof, g0.statement)) return false;
        if (!gate1Verifier.verifyResearchForArity(
            arity, g1.table, g1.srs, g1.proof, g1.context
        )) return false;

        VantaCpLinkPairingResearch.G1 memory d =
            VantaCpLinkPairingResearch.G1(g0.proof.d.x, g0.proof.d.y);
        VantaCpLinkPairingResearch.G1 memory e =
            VantaCpLinkPairingResearch.G1(g1.table.query.x, g1.table.query.y);
        return linkVerifier.verifyResearch(
            link.pi, d, e, link.a2, link.c1, link.c2
        );
    }
}

