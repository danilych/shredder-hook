// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Mock ZK Verifier for testing ZK privacy hook
/// @notice Simplified verifier for testing purposes - not for production use
contract MockZKVerifier {
    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[][] ic;
    }

    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    mapping(bytes32 => bool) public validProofs;
    bool public alwaysVerify = false;

    event ProofVerified(bytes32 indexed proofHash, bool result);

    /// @notice Set a proof as valid for testing
    function setValidProof(Proof memory proof, uint256[] memory publicSignals) external {
        bytes32 proofHash = keccak256(abi.encode(proof, publicSignals));
        validProofs[proofHash] = true;
    }

    /// @notice Set the verifier to always return true (for testing)
    function setAlwaysVerify(bool _alwaysVerify) external {
        alwaysVerify = _alwaysVerify;
    }

    /// @notice Verify a zk-SNARK proof
    function verifyProof(
        Proof memory proof,
        uint256[] memory publicSignals
    ) external returns (bool) {
        if (alwaysVerify) {
            emit ProofVerified(bytes32(0), true);
            return true;
        }

        bytes32 proofHash = keccak256(abi.encode(proof, publicSignals));
        bool isValid = validProofs[proofHash];
        
        emit ProofVerified(proofHash, isValid);
        return isValid;
    }

    /// @notice Verify a proof with additional context
    function verifyProofWithContext(
        Proof memory proof,
        uint256[] memory publicSignals,
        bytes32 context
    ) external returns (bool) {
        if (alwaysVerify) {
            emit ProofVerified(context, true);
            return true;
        }

        bytes32 proofHash = keccak256(abi.encode(proof, publicSignals, context));
        bool isValid = validProofs[proofHash];
        
        emit ProofVerified(proofHash, isValid);
        return isValid;
    }
}
