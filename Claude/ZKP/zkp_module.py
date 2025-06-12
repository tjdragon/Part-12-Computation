#!/usr/bin/env python3
"""
Zero-Knowledge Proof Module for CGGMP21 Threshold Signature System
Implements Schnorr proofs of knowledge for private key shares and commitments
"""

import secrets
import hashlib
import ecdsa
from ecdsa import ellipticcurve
from ecdsa.curves import SECP256k1
from typing import Tuple, Dict, Any, List
import time

# Curve parameters
CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order

def hash_points_and_message(*args) -> int:
    """
    Hashes points and messages into a challenge for Fiat-Shamir transform.
    Used to make interactive ZKPs non-interactive.
    """
    hasher = hashlib.sha256()
    for arg in args:
        if isinstance(arg, (ellipticcurve.Point, ellipticcurve.PointJacobi)):
            if arg == ellipticcurve.INFINITY:
                hasher.update(b"INFINITY")
            else:
                hasher.update(arg.x().to_bytes(32, 'big'))
                hasher.update(arg.y().to_bytes(32, 'big'))
        elif isinstance(arg, bytes):
            hasher.update(arg)
        elif isinstance(arg, str):
            hasher.update(arg.encode('utf-8'))
        elif isinstance(arg, int):
            hasher.update(arg.to_bytes(32, 'big'))
        else:
            hasher.update(str(arg).encode('utf-8'))
    
    return int.from_bytes(hasher.digest(), 'big') % N

class ZKProofOfKnowledge:
    """
    Schnorr Zero-Knowledge Proof of Knowledge for discrete logarithms.
    Used to prove knowledge of private key shares without revealing them.
    """
    
    def __init__(self, prover_id: int):
        self.prover_id = prover_id
        self.proof_history = []
    
    def generate_key_share_proof(self, private_key_share: int, public_key_share: ellipticcurve.Point, 
                                message: bytes = b"") -> Dict[str, Any]:
        """
        Generate ZKP that the prover knows the private key share corresponding to public key share.
        
        Protocol:
        1. Commitment: Generate random nonce v, compute R = v * G
        2. Challenge: e = H(public_key_share, R, message, prover_id)
        3. Response: s = v + e * private_key_share (mod N)
        
        Returns proof (R, s) and metadata
        """
        if not (1 <= private_key_share < N):
            raise ValueError("Private key share out of valid range")
        
        # Step 1: Commitment
        nonce_v = secrets.randbelow(N)
        if nonce_v == 0:
            nonce_v = 1  # Ensure non-zero nonce
        
        R = nonce_v * G
        
        # Step 2: Challenge (Fiat-Shamir)
        challenge_input = f"KeyShareProof_{self.prover_id}"
        e = hash_points_and_message(public_key_share, R, message, challenge_input)
        
        # Step 3: Response
        s = (nonce_v + e * private_key_share) % N
        
        proof = {
            "type": "key_share_proof",
            "prover_id": self.prover_id,
            "R": {"x": hex(R.x()), "y": hex(R.y())},
            "s": hex(s),
            "challenge": hex(e),
            "public_key_share": {"x": hex(public_key_share.x()), "y": hex(public_key_share.y())},
            "message": message.hex() if message else "",
            "timestamp": time.time()
        }
        
        self.proof_history.append(proof)
        return proof
    
    def verify_key_share_proof(self, proof: Dict[str, Any], expected_public_key: ellipticcurve.Point, 
                              message: bytes = b"") -> bool:
        """
        Verify a key share proof without learning the private key.
        
        Verification: Check if s * G == R + e * public_key_share
        """
        try:
            # Extract proof components
            R = ellipticcurve.Point(CURVE.curve, 
                                  int(proof["R"]["x"], 16), 
                                  int(proof["R"]["y"], 16))
            s = int(proof["s"], 16)
            prover_id = proof["prover_id"]
            
            # Validate bounds
            if R == ellipticcurve.INFINITY or not (1 <= s < N):
                return False
            
            # Recompute challenge
            challenge_input = f"KeyShareProof_{prover_id}"
            e = hash_points_and_message(expected_public_key, R, message, challenge_input)
            
            # Verify: s * G ?= R + e * public_key_share
            lhs = s * G
            rhs = R + e * expected_public_key
            
            return lhs == rhs
            
        except Exception:
            return False

class ZKCommitmentProof:
    """
    Zero-Knowledge Proof for polynomial commitments in DKG.
    Proves that commitments are correctly formed without revealing coefficients.
    """
    
    def __init__(self, prover_id: int):
        self.prover_id = prover_id
        self.proof_history = []
    
    def generate_commitment_proof(self, poly_coeffs: List[int], 
                                commitments: List[ellipticcurve.Point]) -> Dict[str, Any]:
        """
        Generate ZKP that commitments C_i = coeff_i * G are correctly formed.
        This is a batch proof for all polynomial coefficients.
        """
        if len(poly_coeffs) != len(commitments):
            raise ValueError("Polynomial coefficients and commitments length mismatch")
        
        # Generate random nonces for each coefficient
        nonces = [secrets.randbelow(N) for _ in range(len(poly_coeffs))]
        nonces = [n if n != 0 else 1 for n in nonces]  # Ensure non-zero
        
        # Step 1: Commitment - compute R_i = nonce_i * G for each coefficient
        R_points = [nonce * G for nonce in nonces]
        
        # Step 2: Challenge (Fiat-Shamir)
        challenge_input = f"CommitmentProof_{self.prover_id}"
        all_points = commitments + R_points
        e = hash_points_and_message(*all_points, challenge_input)
        
        # Step 3: Response - compute s_i = nonce_i + e * coeff_i for each coefficient
        responses = [(nonce + e * coeff) % N for nonce, coeff in zip(nonces, poly_coeffs)]
        
        proof = {
            "type": "commitment_proof",
            "prover_id": self.prover_id,
            "R_points": [{"x": hex(R.x()), "y": hex(R.y())} for R in R_points],
            "responses": [hex(s) for s in responses],
            "challenge": hex(e),
            "commitments": [{"x": hex(C.x()), "y": hex(C.y())} for C in commitments],
            "timestamp": time.time()
        }
        
        self.proof_history.append(proof)
        return proof
    
    def verify_commitment_proof(self, proof: Dict[str, Any]) -> bool:
        """
        Verify that commitments are correctly formed.
        
        For each i: Verify s_i * G ?= R_i + e * C_i
        """
        try:
            # Extract proof components
            R_points = [ellipticcurve.Point(CURVE.curve, 
                                          int(R["x"], 16), 
                                          int(R["y"], 16)) 
                       for R in proof["R_points"]]
            
            responses = [int(s, 16) for s in proof["responses"]]
            commitments = [ellipticcurve.Point(CURVE.curve, 
                                             int(C["x"], 16), 
                                             int(C["y"], 16)) 
                          for C in proof["commitments"]]
            
            prover_id = proof["prover_id"]
            
            # Validate all components
            if any(R == ellipticcurve.INFINITY for R in R_points):
                return False
            if any(not (1 <= s < N) for s in responses):
                return False
            
            # Recompute challenge
            challenge_input = f"CommitmentProof_{prover_id}"
            all_points = commitments + R_points
            e = hash_points_and_message(*all_points, challenge_input)
            
            # Verify each commitment: s_i * G ?= R_i + e * C_i
            for R_i, s_i, C_i in zip(R_points, responses, commitments):
                lhs = s_i * G
                rhs = R_i + e * C_i
                if lhs != rhs:
                    return False
            
            return True
            
        except Exception:
            return False

class ZKNonceProof:
    """
    Zero-Knowledge Proof for nonce generation in signing phase.
    Proves that R_i = k_i * G without revealing k_i.
    """
    
    def __init__(self, prover_id: int):
        self.prover_id = prover_id
        self.proof_history = []
    
    def generate_nonce_proof(self, k_share: int, R_share: ellipticcurve.Point, 
                           message_hash: bytes) -> Dict[str, Any]:
        """
        Generate ZKP that R_share = k_share * G for signing nonce.
        """
        if not (1 <= k_share < N):
            raise ValueError("Nonce share out of valid range")
        
        # Step 1: Commitment
        nonce_v = secrets.randbelow(N)
        if nonce_v == 0:
            nonce_v = 1
        
        R_commit = nonce_v * G
        
        # Step 2: Challenge (Fiat-Shamir)
        challenge_input = f"NonceProof_{self.prover_id}"
        e = hash_points_and_message(R_share, R_commit, message_hash, challenge_input)
        
        # Step 3: Response
        s = (nonce_v + e * k_share) % N
        
        proof = {
            "type": "nonce_proof",
            "prover_id": self.prover_id,
            "R_commit": {"x": hex(R_commit.x()), "y": hex(R_commit.y())},
            "s": hex(s),
            "challenge": hex(e),
            "R_share": {"x": hex(R_share.x()), "y": hex(R_share.y())},
            "message_hash": message_hash.hex(),
            "timestamp": time.time()
        }
        
        self.proof_history.append(proof)
        return proof
    
    def verify_nonce_proof(self, proof: Dict[str, Any], expected_R_share: ellipticcurve.Point, 
                          message_hash: bytes) -> bool:
        """
        Verify nonce proof: s * G ?= R_commit + e * R_share
        """
        try:
            # Extract components
            R_commit = ellipticcurve.Point(CURVE.curve, 
                                         int(proof["R_commit"]["x"], 16), 
                                         int(proof["R_commit"]["y"], 16))
            s = int(proof["s"], 16)
            prover_id = proof["prover_id"]
            
            # Validate
            if R_commit == ellipticcurve.INFINITY or not (1 <= s < N):
                return False
            
            # Recompute challenge
            challenge_input = f"NonceProof_{prover_id}"
            e = hash_points_and_message(expected_R_share, R_commit, message_hash, challenge_input)
            
            # Verify: s * G ?= R_commit + e * R_share
            lhs = s * G
            rhs = R_commit + e * expected_R_share
            
            return lhs == rhs
            
        except Exception:
            return False

class ZKAggregateVerifier:
    """
    Verifies multiple ZK proofs and maintains a security audit trail.
    """
    
    def __init__(self):
        self.verification_history = []
        self.security_stats = {
            "total_proofs_verified": 0,
            "failed_verifications": 0,
            "proof_types_seen": set()
        }
    
    def verify_proof(self, proof: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Universal proof verifier that routes to appropriate verification method.
        """
        proof_type = proof.get("type")
        verification_start = time.time()
        
        try:
            if proof_type == "key_share_proof":
                zkp = ZKProofOfKnowledge(proof["prover_id"])
                is_valid = zkp.verify_key_share_proof(
                    proof, 
                    kwargs.get("expected_public_key"), 
                    kwargs.get("message", b"")
                )
            elif proof_type == "commitment_proof":
                zkp = ZKCommitmentProof(proof["prover_id"])
                is_valid = zkp.verify_commitment_proof(proof)
            elif proof_type == "nonce_proof":
                zkp = ZKNonceProof(proof["prover_id"])
                is_valid = zkp.verify_nonce_proof(
                    proof,
                    kwargs.get("expected_R_share"),
                    kwargs.get("message_hash", b"")
                )
            else:
                is_valid = False
                
        except Exception as e:
            is_valid = False
        
        verification_time = time.time() - verification_start
        
        # Update statistics
        self.security_stats["total_proofs_verified"] += 1
        if not is_valid:
            self.security_stats["failed_verifications"] += 1
        self.security_stats["proof_types_seen"].add(proof_type)
        
        # Record verification
        verification_record = {
            "timestamp": time.time(),
            "proof_type": proof_type,
            "prover_id": proof.get("prover_id"),
            "is_valid": is_valid,
            "verification_time_ms": round(verification_time * 1000, 2),
            "proof_challenge": proof.get("challenge", "unknown")
        }
        
        self.verification_history.append(verification_record)
        
        return verification_record
    
    def get_security_report(self) -> Dict[str, Any]:
        """
        Generate a security report of all ZKP verifications.
        """
        if not self.verification_history:
            return {"status": "no_verifications_performed"}
        
        recent_verifications = self.verification_history[-10:]  # Last 10
        
        return {
            "total_verifications": len(self.verification_history),
            "success_rate": (
                (self.security_stats["total_proofs_verified"] - self.security_stats["failed_verifications"]) 
                / self.security_stats["total_proofs_verified"]
            ) if self.security_stats["total_proofs_verified"] > 0 else 0,
            "proof_types": list(self.security_stats["proof_types_seen"]),
            "failed_count": self.security_stats["failed_verifications"],
            "recent_verifications": recent_verifications,
            "avg_verification_time_ms": sum(v["verification_time_ms"] for v in recent_verifications) / len(recent_verifications)
        }

# Utility functions for integration with main system
def serialize_zkp_point(point: ellipticcurve.Point) -> Dict[str, str]:
    """Serialize elliptic curve point for ZKP transmission"""
    if point == ellipticcurve.INFINITY:
        return {"type": "infinity"}
    return {"x": hex(point.x()), "y": hex(point.y())}

def deserialize_zkp_point(data: Dict[str, str]) -> ellipticcurve.Point:
    """Deserialize elliptic curve point from ZKP data"""
    if data.get("type") == "infinity":
        return ellipticcurve.INFINITY
    return ellipticcurve.Point(CURVE.curve, int(data["x"], 16), int(data["y"], 16))

# Test function for standalone verification
def run_zkp_tests():
    """
    Run comprehensive tests of all ZKP functionality.
    """
    print("=== Zero-Knowledge Proof Tests ===")
    
    # Test 1: Key Share Proof
    print("\n1. Testing Key Share Proof...")
    private_key = secrets.randbelow(N)
    public_key = private_key * G
    
    zkp_key = ZKProofOfKnowledge(prover_id=1)
    proof = zkp_key.generate_key_share_proof(private_key, public_key, b"test_message")
    is_valid = zkp_key.verify_key_share_proof(proof, public_key, b"test_message")
    print(f"Key Share Proof: {'VALID' if is_valid else 'INVALID'}")
    
    # Test 2: Commitment Proof
    print("\n2. Testing Commitment Proof...")
    coeffs = [secrets.randbelow(N) for _ in range(3)]
    commits = [c * G for c in coeffs]
    
    zkp_commit = ZKCommitmentProof(prover_id=2)
    commit_proof = zkp_commit.generate_commitment_proof(coeffs, commits)
    commit_valid = zkp_commit.verify_commitment_proof(commit_proof)
    print(f"Commitment Proof: {'VALID' if commit_valid else 'INVALID'}")
    
    # Test 3: Nonce Proof
    print("\n3. Testing Nonce Proof...")
    k_nonce = secrets.randbelow(N)
    R_nonce = k_nonce * G
    msg_hash = hashlib.sha256(b"signing_message").digest()
    
    zkp_nonce = ZKNonceProof(prover_id=3)
    nonce_proof = zkp_nonce.generate_nonce_proof(k_nonce, R_nonce, msg_hash)
    nonce_valid = zkp_nonce.verify_nonce_proof(nonce_proof, R_nonce, msg_hash)
    print(f"Nonce Proof: {'VALID' if nonce_valid else 'INVALID'}")
    
    # Test 4: Aggregate Verifier
    print("\n4. Testing Aggregate Verifier...")
    verifier = ZKAggregateVerifier()
    
    result1 = verifier.verify_proof(proof, expected_public_key=public_key, message=b"test_message")
    result2 = verifier.verify_proof(commit_proof)
    result3 = verifier.verify_proof(nonce_proof, expected_R_share=R_nonce, message_hash=msg_hash)
    
    security_report = verifier.get_security_report()
    print(f"Aggregate Verification Results:")
    print(f"  Success Rate: {security_report['success_rate']:.2%}")
    print(f"  Total Verifications: {security_report['total_verifications']}")
    print(f"  Proof Types: {security_report['proof_types']}")
    
    print("\n=== All ZKP Tests Complete ===")

if __name__ == "__main__":
    run_zkp_tests()
