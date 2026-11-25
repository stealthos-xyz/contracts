// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Vanta v0 dummy namespace guard. Research only, no production authorization.
/// @dev D[slot] = PoseidonT3([0, DUMMY_DOMAIN, slot+1])[0].
///      Values are pinned by Rust/Node; this does NOT replace global real-note dedup.
library VantaDummyPolicy {
    uint256 internal constant FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function isDisallowedRealCommitment(uint256 commitment) internal pure returns (bool) {
        if (commitment == 0 || commitment >= FR) return true;
        uint256[32] memory reserved = [
            uint256(0x2944438ba3ab6536895041148123e8a32af13902733d1257592c521bc96dec6b),
            uint256(0x1a9182140239b80640e289a20e720344157dbf7cb2c2f17494784d4e3f27e8ad),
            uint256(0x18680b7d51b40b6260fe0c749a1a23591f1fecc877eb93d6928a30d24bdd4042),
            uint256(0x2211fe541f277e3a35ae509b1082406fdccf6240151b822a252144a40ee4a532),
            uint256(0x0cc558074548b6c6860a1e205bab4e7bda05e3c3c087fec8caf49abb7d9649c6),
            uint256(0x038568a5541c5bfbd7cbd13b09d7d136bebb87215b4378510d6114343d353372),
            uint256(0x17795652cbda7a7be59b11121438ca1b268ab87451255499487b0d328bc8dae7),
            uint256(0x1026711173a12c7522e9a969a9a9a09a6dadec533bc62909341cb0e5c68fcbff),
            uint256(0x212f85803a00b99df9eace5ce57e8a7f684bdaad69ecd2481153eb833aebf453),
            uint256(0x1f162816478922254d7cc6e04edde7a0d4c16b0b87995a1bda26a0a52c539889),
            uint256(0x29cedfadea17db8a8f72d041a0aa47ba1693ee32cb12a7ff2880942902f8edb9),
            uint256(0x2f8258644d5d923530e8811c90c4cd875c94164f789aacd1ebc8a23559e96d0e),
            uint256(0x1b5824527c0f55d228505716a92be0bb798f83dcec0be91049269214a2be6ebc),
            uint256(0x13384c4c41b3dd4f9f3018061f5f84c65dd9b830201c85d3367cd1adc79f3637),
            uint256(0x151cb1d55971db14bfacc3c0c830d99c2672dae5ee934b139f0f747f58cd4998),
            uint256(0x10a7346880cfb93bc889307e6e24fd95740dce30f9c9a8b454b54a58ca1dcb0e),
            uint256(0x2987429ded0ff103859bdc93be06e8d9ca1522a8cb5b2f81dee87ae4ae0c9db4),
            uint256(0x09f2a04fa601373aae67718a728f17a27ce6c6b0b0255292bbf96ee2af9ea19e),
            uint256(0x24ffd2100c5eff619970059936cd421824326b63c714de9d204e8f9d7aa16da7),
            uint256(0x1036fd6b7cce25ec035422398995d00009da4a923d9c666fa30625d49b7d6382),
            uint256(0x1c5f701c6704392524a9b087cc3b7e0c45ad96aa5c3b9ffef208f88fea21cfd3),
            uint256(0x03d5a1bb663a8fd51e9df4616f61a1290b4e901198854e03a987daddf5fc73d7),
            uint256(0x1963d01c53af1a186dcd6c62b703efff28f9e443cd9cfd749ca668946526c1db),
            uint256(0x25373d46695f26b5f10a9939201151a5d6237e6b51e1ad0a50b683734e4f99e1),
            uint256(0x085e6dc325e61831256668d266aac5c0cf2a89d3a416ba7875c765597560af11),
            uint256(0x0e83d4e45faf7838e2dceda2be32c6b1c2a3e713431ec25179a9be5185e6a1a0),
            uint256(0x25764bd9b30d62fa9a38f7258bd64fc9fb342f36d1b289198b7f9471737c21d4),
            uint256(0x22d0b21a044e977ef62674e024af55de6b55999a01b62b5c978283cb94fc50b7),
            uint256(0x2438043fee3276c8cd887fd72a61de3abb267a5534f3bf04a90f8b2a4d69a127),
            uint256(0x28fd466ded3ce291c567795e5d0cfd87b1ac923a0967e3fc86d3a1e2e32dfa52),
            uint256(0x279b9394b6c357dfb32431e1323ef4248d950a1ab34a03fdb3cda3b9d75a233d),
            uint256(0x0ff08689472c8256b45e361d3bcb72e8660f3800cf46559a0e0a9bdd93fc3f73)
        ];
        for (uint256 i = 0; i < reserved.length; ++i) {
            if (commitment == reserved[i]) return true;
        }
        return false;
    }
}
