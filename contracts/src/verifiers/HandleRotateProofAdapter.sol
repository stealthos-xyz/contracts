// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AnonymousHandleVerifier} from "./AnonymousHandleVerifier.sol";
import {HandleRotateVerifier} from "./HandleRotateVerifier.sol";

contract HandleRotateProofAdapter is AnonymousHandleVerifier {
    /// @inheritdoc AnonymousHandleVerifier
    address public immutable override verifier;

    error InvalidVerifier();

    constructor(address verifier_) {
        if (verifier_ == address(0) || verifier_.code.length == 0) revert InvalidVerifier();
        verifier = verifier_;
    }

    function isDevelopmentSetup() external view override returns (bool) {
        return HandleRotateVerifier(verifier).isDevelopmentSetup();
    }

    function verifyProof(
        uint256[8] calldata proof,
        bytes32 handleId,
        bytes32 recordCommitment,
        bytes32 ownerCommitment,
        bytes32 nullifier,
        uint64 epoch,
        uint256 chainId,
        uint8 actionTag
    ) external view override returns (bool) {
        uint256[2] memory pA = [proof[0], proof[1]];
        uint256[2][2] memory pB = [[proof[2], proof[3]], [proof[4], proof[5]]];
        uint256[2] memory pC = [proof[6], proof[7]];
        uint256[7] memory pubSignals = [
            uint256(handleId),
            uint256(recordCommitment),
            uint256(ownerCommitment),
            uint256(epoch),
            uint256(nullifier),
            chainId,
            uint256(actionTag)
        ];
        return HandleRotateVerifier(verifier).verifyProof(pA, pB, pC, pubSignals);
    }
}
