// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Exact native Caulk+ *published-orientation* Gate 1 verifier (research).
/// @dev Never authorize funds using this standalone adapter: its table, context
///      and SRS are caller-supplied. Final settlement requires fixed reviewed
///      verifier keys and an authenticated accepted checkpoint, plus Gate 0 and
///      CP_link verification against the same transaction statement.
contract VantaCaulkPlusGate1Research {
    uint256 internal constant FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant FQ =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint8 internal constant DEFAULT_QUERY_COUNT = 32;
    error InvalidQueryArity();
    uint256 internal constant TABLE_N = 65_536;
    string internal constant TRANSCRIPT_DOMAIN = "STEALTHOS_VANTA_CAULK_PLUS_V1";

    // xIm,xRe,yIm,yRe matches the EIP-197 pairing precompile order.
    struct G1 { uint256 x; uint256 y; }
    struct G2 { uint256 xIm; uint256 xRe; uint256 yIm; uint256 yRe; }
    struct Table {
        uint256 n;
        G1 commitment;
        G1 zH;
        G1 query;
    }
    struct Srs {
        G1 g1;
        G2 g20;
        G2 g21;
    }
    struct Proof {
        G1 zI;
        G1 cI;
        G1 u;
        G2 w;
        G1 h;
        uint256 v1;
        uint256 v2;
        G1 pi1;
        G1 pi2;
        G1 pi3;
    }

    /// @notice Recompute Arkworks 0.5 Fiat-Shamir challenges from canonical points.
    /// @dev No chi1/chi2/alpha is accepted as calldata. Reproduces the native
    ///      transcript byte-for-byte, including little-endian Ark point format.
    function deriveChallenges(Table calldata t, Proof calldata p, bytes calldata context)
        public pure returns (uint256 chi1, uint256 chi2, uint256 alpha)
    {
        return _deriveChallenges(t, p, context, DEFAULT_QUERY_COUNT);
    }

    /// @notice Eight-slot and historical 32-slot Fiat-Shamir transcripts.
    /// @dev The native prover rejects alpha values satisfying alpha^m == 1,
    /// where m is the exact query arity. Never reuse the 32-slot exponent for
    /// an 8-slot proof or silently reinterpret the proving parameters.
    function deriveChallengesForArity(
        uint8 arity, Table calldata t, Proof calldata p, bytes calldata context
    ) external pure returns (uint256 chi1, uint256 chi2, uint256 alpha) {
        if (arity != 8 && arity != 32) revert InvalidQueryArity();
        return _deriveChallenges(t, p, context, arity);
    }

    /// @notice Dedicated one-policy transcript. Existing 8/32 APIs keep their
    /// original arity guards; policy callers must explicitly select this path.
    function deriveSingletonChallenges(Table calldata t, Proof calldata p, bytes calldata context)
        external pure returns (uint256 chi1, uint256 chi2, uint256 alpha)
    {
        return _deriveChallenges(t, p, context, 1);
    }

    function _deriveChallenges(
        Table calldata t, Proof calldata p, bytes calldata context, uint8 arity
    ) private pure returns (uint256 chi1, uint256 chi2, uint256 alpha) {
        bytes memory t1 = abi.encodePacked(
            TRANSCRIPT_DOMAIN,
            uint64(context.length), context, uint64(t.n),
            _arkG1(t.commitment), _arkG1(t.zH),
            _arkG1(t.query), _arkG1(p.zI), _arkG1(p.cI), _arkG1(p.u)
        );
        chi1 = _challenge(t1, "chi1", 0);
        chi2 = _challenge(t1, "chi2", 0);
        bytes memory t2 = bytes.concat(t1, _arkG2(p.w), _arkG1(p.h));
        alpha = _challenge(t2, "alpha", arity);
    }

    /// @notice All four equations verified via real EIP-196/197 precompiles.
    /// @dev Uses the point/query proof and *verifier-derived* FS transcript.
    ///      The SRS/checkpoint/context are intentionally untrusted research inputs,
    ///      so this function must never grant settlement authority.
    function verifyResearch(Table calldata t, Srs calldata s, Proof calldata p, bytes calldata context)
        external view returns (bool)
    {
        return _verifyResearch(t, s, p, context, DEFAULT_QUERY_COUNT);
    }

    /// @notice Genuine 8x5 and 32x5 Caulk+ verifier equations, research only.
    /// @dev The SRS/table remain caller-supplied and are NOT custody-pinned.
    function verifyResearchForArity(
        uint8 arity, Table calldata t, Srs calldata s,
        Proof calldata p, bytes calldata context
    ) external view returns (bool) {
        if (arity != 8 && arity != 32) return false;
        return _verifyResearch(t, s, p, context, arity);
    }

    /// @notice One hidden policy query using the same published Caulk+ equations.
    /// @dev A fee adapter must pin the SRS, current table, domain-separated
    /// statement and corresponding ccGroth16/CP_link keys before admitting it.
    /// This public arithmetic view grants no policy or custody authorization.
    function verifySingletonResearch(Table calldata t, Srs calldata s,
        Proof calldata p, bytes calldata context) external view returns (bool)
    {
        return _verifyResearch(t, s, p, context, 1);
    }

    function _verifyResearch(
        Table calldata t, Srs calldata s, Proof calldata p,
        bytes calldata context, uint8 arity
    ) private view returns (bool) {
        if ((arity != 1 && arity != 8 && arity != 32) || t.n != TABLE_N ||
            context.length > 4096 || p.v1 >= FR || p.v2 >= FR) return false;
        if (s.g1.x != 1 || s.g1.y != 2) return false;
        if (!_validG1(t.commitment) || !_validG1(t.zH) || !_validG1(t.query) ||
            !_validG1(p.zI) || !_validG1(p.cI) || !_validG1(p.u) ||
            !_validG1(p.h) || !_validG1(p.pi1) || !_validG1(p.pi2) ||
            !_validG1(p.pi3) || !_validG2(s.g20) || !_validG2(s.g21) ||
            !_validG2(p.w)) return false;
        if (_isInfinity(t.commitment) || _isInfinity(t.query)) return false;
        (uint256 chi1, uint256 chi2, uint256 alpha) = _deriveChallenges(t, p, context, arity);

        // (1) e(U-v1*G1, G20) = e(pi1, G21-alpha*G20).
        if (!_kzg(s, p.u, alpha, p.v1, p.pi1)) return false;

        // (2) e((Zi+chi1*Ci)-v2*G1, G20)
        //       = e(pi2, G21-v1*G20).
        (bool ok, G1 memory p1) = _mul(p.cI, chi1);
        if (!ok) return false;
        (ok, p1) = _add(p.zI, p1);
        if (!ok || !_kzg(s, p1, p.v1, p.v2, p.pi2)) return false;

        // (3) e(v2*G1-chi1*E-(alpha^m-1)*H, G20)
        //       = e(pi3, G21-alpha*G20).
        (ok, p1) = _mul(s.g1, p.v2);
        if (!ok) return false;
        (bool mulOk, G1 memory qScaled) = _mul(t.query, chi1);
        if (!mulOk) return false;
        (ok, p1) = _add(p1, _neg(qScaled));
        if (!ok) return false;
        (mulOk, qScaled) = _mul(p.h, addmod(_powerForArity(alpha, arity), FR - 1, FR));
        if (!mulOk) return false;
        (ok, p1) = _add(p1, _neg(qScaled));
        if (!ok || !_kzg(s, p1, alpha, 0, p.pi3)) return false;

        // (4) e(C-Ci+chi2*ZH, G20) = e(Zi,W).
        (ok, p1) = _add(t.commitment, _neg(p.cI));
        if (!ok) return false;
        (mulOk, qScaled) = _mul(t.zH, chi2);
        if (!mulOk) return false;
        (ok, p1) = _add(p1, qScaled);
        return ok && _pairEq(p1, s.g20, p.zI, p.w);
    }

    function _kzg(Srs calldata s, G1 memory commitment, uint256 point, uint256 value, G1 memory pi)
        private view returns (bool)
    {
        (bool ok, G1 memory scaled) = _mul(s.g1, value);
        if (!ok) return false;
        (bool addOk, G1 memory left) = _add(commitment, _neg(scaled));
        if (!addOk) return false;
        (addOk, scaled) = _mul(pi, point);
        if (!addOk) return false;
        (addOk, left) = _add(left, scaled);
        return addOk && _pairEq(left, s.g20, pi, s.g21);
    }

    function _pairEq(G1 memory left, G2 memory leftG2, G1 memory right, G2 memory rightG2)
        private view returns (bool)
    {
        G1 memory negRight = _neg(right);
        bytes memory pairs = abi.encodePacked(
            left.x, left.y, leftG2.xIm, leftG2.xRe, leftG2.yIm, leftG2.yRe,
            negRight.x, negRight.y, rightG2.xIm, rightG2.xRe, rightG2.yIm, rightG2.yRe
        );
        (bool ok, bytes memory response) = address(0x08).staticcall(pairs);
        return ok && response.length == 32 && abi.decode(response, (uint256)) == 1;
    }

    function _add(G1 memory a, G1 memory b)
        private view returns (bool ok, G1 memory result)
    {
        (bool success, bytes memory response) = address(0x06).staticcall(
            abi.encodePacked(a.x, a.y, b.x, b.y)
        );
        if (!success || response.length != 64) return (false, result);
        (result.x, result.y) = abi.decode(response, (uint256,uint256));
        return (true, result);
    }

    function _mul(G1 memory a, uint256 scalar)
        private view returns (bool ok, G1 memory result)
    {
        (bool success, bytes memory response) = address(0x07).staticcall(
            abi.encodePacked(a.x, a.y, scalar)
        );
        if (!success || response.length != 64) return (false, result);
        (result.x, result.y) = abi.decode(response, (uint256,uint256));
        return (true, result);
    }

    function _neg(G1 memory p) private pure returns (G1 memory) {
        if (p.y != 0) p.y = FQ - p.y;
        return p;
    }

    function _isInfinity(G1 memory p) private pure returns (bool) {
        return p.x == 0 && p.y == 0;
    }

    function _validG1(G1 memory p) private pure returns (bool) {
        if (p.x >= FQ || p.y >= FQ) return false;
        if (_isInfinity(p)) return true;
        return mulmod(p.y, p.y, FQ) ==
            addmod(mulmod(mulmod(p.x,p.x,FQ),p.x,FQ),3,FQ);
    }

    function _validG2(G2 memory p) private pure returns (bool) {
        return p.xIm < FQ && p.xRe < FQ && p.yIm < FQ && p.yRe < FQ &&
            (p.xIm | p.xRe | p.yIm | p.yRe) != 0;
    }

    /// @dev SWFlags 0x80 means negative y, 0x40 means infinity.
    ///      x is serialized little-endian, exactly as ark-serialize 0.5.
    function _arkG1(G1 memory p) private pure returns (bytes memory result) {
        result = _le32(p.x);
        uint8 flag;
        if (_isInfinity(p)) {
            flag = 0x40;
        } else if (p.y > FQ - p.y) {
            flag = 0x80;
        }
        result[31] = bytes1(uint8(result[31]) | flag);
    }

    /// @dev Fq2 coordinates: c0 then c1, each LE; flags in c1's last byte.
    ///      Arkworks Fq2 ordering compares y.c1 first, then y.c0.
    function _arkG2(G2 memory p) private pure returns (bytes memory result) {
        bytes memory re = _le32(p.xRe);
        bytes memory im = _le32(p.xIm);
        bool infinity = (p.xRe | p.xIm | p.yRe | p.yIm) == 0;
        uint8 flag;
        if (infinity) {
            flag = 0x40;
        } else {
            uint256 negIm = p.yIm == 0 ? 0 : FQ - p.yIm;
            uint256 negRe = p.yRe == 0 ? 0 : FQ - p.yRe;
            if (p.yIm > negIm || (p.yIm == negIm && p.yRe > negRe)) flag = 0x80;
        }
        im[31] = bytes1(uint8(im[31]) | flag);
        result = bytes.concat(re,im);
    }

    function _le32(uint256 value) private pure returns (bytes memory result) {
        result = new bytes(32);
        for (uint256 i = 0; i < 32; ++i) {
            result[i] = bytes1(uint8(value >> (i*8)));
        }
    }

    function _challenge(bytes memory transcript, string memory label, uint8 rejectRootsForArity)
        private pure returns (uint256)
    {
        for (uint32 count = 0; count < 32; ++count) {
            uint256 candidate = uint256(sha256(abi.encodePacked(
                TRANSCRIPT_DOMAIN, uint64(bytes(label).length),
                label, transcript, count
            ))) % FR;
            if (candidate == 0) continue;
            if (rejectRootsForArity != 0 &&
                _powerForArity(candidate, rejectRootsForArity) == 1) continue;
            return candidate;
        }
        revert("Vanta Caulk+ Fiat-Shamir rejection limit");
    }

    function _powerForArity(uint256 value, uint8 arity)
        private pure returns (uint256)
    {
        if (arity == 1) return value;
        if (arity != 8 && arity != 32) revert InvalidQueryArity();
        for (uint256 i = 0; i < (arity == 8 ? 3 : 5); ++i) {
            value = mulmod(value, value, FR);
        }
        return value;
    }
}
