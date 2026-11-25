// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {VantaFamilyEnhancedPoolPreAudit} from "./VantaFamilyEnhancedPoolPreAudit.sol";
import {VantaV8UnifiedNormalSpendLogic} from "./VantaFamilyUnifiedPoolPreAudit.sol";
import {VantaV8FiveRowKzgResearch as Kzg} from "./VantaV8FiveRowKzgResearch.sol";
import {VantaNativeWalletClearance} from "./VantaNativeWalletClearance.sol";

/// @notice Direct browser ingress using the unchanged combined KZG fee proof.
/// This revision needs a new deployment; it never changes an existing pool.
contract VantaFamilyDirectDepositPoolPreAudit is VantaFamilyEnhancedPoolPreAudit {
    VantaNativeWalletClearance private immutable nativeWalletClearance;
    // Untrusted deposit nonces never share the signer/exit replay namespace.
    mapping(bytes32 => bool) public usedDepositNonce;

    constructor(BaseConfiguration memory b, EnhancedConfiguration memory e, address clearance)
        VantaFamilyEnhancedPoolPreAudit(b, e)
    {
        VantaNativeWalletClearance gate = VantaNativeWalletClearance(clearance);
        if (clearance.code.length == 0 || gate.releaseSetupId() != b.setupId ||
            gate.releaseGenerationId() != b.generationId || gate.releaseFamilyTag() != b.familyTag ||
            gate.releaseChainId() != b.chainId || gate.administrator() != b.retirementAuthority)
            revert InvalidReleaseGeneration();
        nativeWalletClearance = gate;
    }

    /// @dev Same ABI/proof/public inputs. The last bytes carry reusable wallet
    /// clearance, not a per-deposit signature. Quote fields are built locally.
    function depositWithPrivateFeeNotes(
        PrivateFeeDepositQuote calldata q, uint256[5] calldata outputs,
        bytes[5] calldata encryptedOutputs, Kzg.RowKey[5] calldata rowKeys,
        uint8[2] calldata feeSlots, bytes calldata combinedProof, bytes calldata clearance
    ) external payable override noReentry returns (uint256 nextCheckpoint) {
        // Ordinary ingress has 3..5 notes; the authenticated internal lane has
        // one. The library independently rejects zero or two-note packets.
        // Read the static uint8 quote field without another ABI cleanup branch.
        // This exact guard keeps the inherited custody runtime within EIP-170.
        bytes4 retiredSelector = GenerationExitOnly.selector;
        assembly ("memory-safe") {
            let retired := and(shr(mul(plannedExitOnlyAt.offset, 8), sload(plannedExitOnlyAt.slot)), 0xffffffffffffffff)
            if and(gt(calldataload(add(q, 192)), 1), iszero(iszero(retired))) {
                mstore(0, retiredSelector)
                revert(0, 4)
            }
        }
        _requireNormalProofSetup();
        nextCheckpoint = VantaV8UnifiedNormalSpendLogic.directDeposit(
            epochState, usedDepositNonce, commitmentSeen, q, outputs, encryptedOutputs,
            rowKeys, feeSlots, combinedProof, domainSeparator(), _normalPins(),
            address(nativeWalletClearance), clearance
        );
        _receiveExact(q.gross);
        accountedLiability += q.gross;
    }
}
