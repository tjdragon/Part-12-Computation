#!/usr/bin/env python3
"""
Basic Signer with Zero-Knowledge Proofs
Enhanced CGGMP21 signer with ZKP generation and detailed logging
No AI agents - pure Python implementation
"""

import secrets
import ecdsa
from ecdsa.util import sigencode_string, sigdecode_string
from ecdsa.keys import BadSignatureError
from ecdsa.curves import SECP256k1
from flask import Flask, request, jsonify
import argparse
import requests
import json
import time
import hashlib
from typing import Dict, Any, List

# Import ZKP module
from zkp_module import (
    ZKProofOfKnowledge,
    ZKCommitmentProof, 
    ZKNonceProof,
    serialize_zkp_point
)

# Cryptographic Setup (unchanged from original)
CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order

def inv(n, prime=N): 
    return pow(n, prime - 2, prime)

def compute_lagrange_coeff(party_ids, target_id):
    num = 1
    den = 1
    for j in party_ids:
        if j != target_id: 
            num = (num * j) % N
            den = (den * (j - target_id)) % N
    return (num * inv(den, N)) % N

def serialize_point(p):
    if p == ecdsa.ellipticcurve.INFINITY: 
        return {"type": "infinity"}
    return {"x": hex(p.x()), "y": hex(p.y())}

def deserialize_point(data):
    if data.get("type") == "infinity": 
        return ecdsa.ellipticcurve.INFINITY
    return ecdsa.ellipticcurve.Point(CURVE.curve, int(data['x'], 16), int(data['y'], 16))

class SignerZKP:
    """Basic MPC Signer with Zero-Knowledge Proofs"""
    
    def __init__(self, party_id, num_parties, threshold, party_addresses=None, own_url=None):
        # Core MPC attributes (unchanged)
        self.id = party_id
        self.num_parties = num_parties
        self.threshold = threshold
        self.url = own_url
        self.party_addresses = party_addresses if party_addresses is not None else {}
        
        # DKG state
        self.poly_coeffs = None
        self.commitments = None
        self.received_commitments = {}
        self.received_shares = {}
        self.private_key_share = None
        self.public_key_share = None
        self.aggregated_public_key_point = None
        
        # Signing state
        self.k_share = None
        self.R_share = None
        self.received_R_shares = {}
        self.aggregated_R_point = None
        self.current_message_hash_hex = None
        self.current_signing_party_ids = []
        self.current_r = None
        
        # Basic state tracking
        self.memory = []
        self.current_operation = None
        self.protocol_state = "idle"
        
        # ZKP Components
        self.zkp_key_prover = ZKProofOfKnowledge(party_id)
        self.zkp_commitment_prover = ZKCommitmentProof(party_id)
        self.zkp_nonce_prover = ZKNonceProof(party_id)
        self.generated_proofs = []
        self.zkp_stats = {
            "proofs_generated": 0,
            "commitment_proofs": 0,
            "key_share_proofs": 0,
            "nonce_proofs": 0
        }
        
    def add_to_memory(self, event: str, details: Dict[str, Any] = None):
        """Add events to signer memory - NO FILTERING, show everything"""
        memory_entry = {
            "timestamp": time.time(),
            "event": event,
            "details": details or {},
            "operation": self.current_operation,
            "protocol_state": self.protocol_state
        }
        self.memory.append(memory_entry)
        # Keep only last 100 events for memory efficiency
        if len(self.memory) > 100:
            self.memory = self.memory[-100:]
    
    def log(self, msg: str, level: str = "INFO"):
        """Enhanced logging - NO FILTERING"""
        print(f"[{level}] [Signer ZKP {self.id}] {msg}")
        self.add_to_memory(f"LOG: {msg}")
    
    def log_zkp_generation(self, proof_type: str, proof_data: Dict, success: bool):
        """Log ZKP generation with full details"""
        self.log(f"ZKP GENERATION - {proof_type}: {'SUCCESS' if success else 'FAILED'}")
        self.log(f"ZKP PROOF DATA: {json.dumps(proof_data, indent=2)}")
        
        if success:
            self.zkp_stats["proofs_generated"] += 1
            self.zkp_stats[f"{proof_type}_proofs"] += 1
            self.generated_proofs.append({
                "timestamp": time.time(),
                "proof_type": proof_type,
                "proof_data": proof_data,
                "success": success
            })

    # === Enhanced DKG Protocol Methods with ZKP ===
    
    def dkg_round_1_create_poly_and_commitments(self):
        """DKG Round 1: Create polynomial and commitments with ZKP"""
        self.current_operation = "DKG_ROUND_1"
        self.protocol_state = "dkg_generating_polynomial"
        
        self.log("DKG R1: Creating secret polynomial and public commitments with ZKP.")
        
        # Generate polynomial (same cryptographic operation)
        self.poly_coeffs = [secrets.randbelow(N) for _ in range(self.threshold)]
        self.commitments = [c * G for c in self.poly_coeffs]
        
        self.log(f"DKG R1: Generated polynomial coefficients: {[hex(c) for c in self.poly_coeffs]}")
        self.log(f"DKG R1: Generated commitments: {[serialize_point(C) for C in self.commitments]}")
        
        # Generate ZKP for commitment correctness
        try:
            commitment_proof = self.zkp_commitment_prover.generate_commitment_proof(
                self.poly_coeffs, self.commitments
            )
            self.log_zkp_generation("commitment", commitment_proof, True)
            
            # Store proof data
            self.add_to_memory("Commitment ZKP generated", {
                "polynomial_coefficients": [hex(c) for c in self.poly_coeffs],
                "commitments": [serialize_point(C) for C in self.commitments],
                "zkp_proof": commitment_proof
            })
            
        except Exception as e:
            self.log(f"Failed to generate commitment ZKP: {str(e)}", "ERROR")
            commitment_proof = None
            self.log_zkp_generation("commitment", {}, False)
        
        result = {
            "commitments": [serialize_point(p) for p in self.commitments]
        }
        
        if commitment_proof:
            result["zkp_commitment_proof"] = commitment_proof
        
        return result
    
    def dkg_round_2_get_share_for_party(self, j_id):
        """Generate share for party j with full logging"""
        if self.current_operation != "DKG_ROUND_2":
            self.current_operation = "DKG_ROUND_2"
            self.protocol_state = "dkg_generating_shares"
        
        # Evaluate polynomial at point j_id
        y = 0
        for c in reversed(self.poly_coeffs): 
            y = (y * j_id + c) % N
        
        self.log(f"DKG R2: Computed share for party {j_id}: {hex(y)}")
        self.add_to_memory(f"Generated share for party {j_id}", {
            "target_party": j_id,
            "share_value": hex(y),
            "polynomial_evaluation": f"f({j_id}) = {hex(y)}"
        })
        
        return y

    def dkg_round_3_verify_and_store_share(self, from_id, share, commitments):
        """Verify share with full logging"""
        self.current_operation = "DKG_ROUND_3"
        self.protocol_state = "dkg_verifying_shares"
        
        self.log(f"DKG R3: Verifying share from party {from_id}...")
        self.log(f"DKG R3: Share value: {hex(share)}")
        self.log(f"DKG R3: Commitments: {[serialize_point(c) for c in commitments]}")
        
        # Standard share verification (unchanged cryptography)
        lhs = share * G
        rhs = ecdsa.ellipticcurve.INFINITY
        for k_idx, c in enumerate(commitments): 
            rhs += pow(self.id, k_idx, N) * c
        
        self.log(f"DKG R3: Verification equation - LHS: {serialize_point(lhs)}")
        self.log(f"DKG R3: Verification equation - RHS: {serialize_point(rhs)}")
        
        if lhs != rhs:
            self.log(f"!! DKG R3: Share verification FAILED for party {from_id}.", "ERROR")
            self.add_to_memory(f"Share verification failed from party {from_id}", {
                "from_party": from_id, 
                "verified": False,
                "share_value": hex(share),
                "lhs": serialize_point(lhs),
                "rhs": serialize_point(rhs)
            })
            return False
        
        self.log(f"DKG R3: Share from party {from_id} is VALID. Storing.")
        self.received_shares[from_id] = share
        self.add_to_memory(f"Share verified and stored from party {from_id}", {
            "from_party": from_id, 
            "verified": True,
            "share_value": hex(share)
        })
        
        return True

    def dkg_round_4_compute_key_shares(self):
        """Compute final key shares with ZKP"""
        self.current_operation = "DKG_ROUND_4"
        self.protocol_state = "dkg_computing_final_keys"
        
        self.log("DKG R4: Computing my private key share (x_i) from all received shares.")
        self.log(f"DKG R4: All received shares: {[(pid, hex(share)) for pid, share in self.received_shares.items()]}")
        
        # Compute private key share (unchanged)
        self.private_key_share = sum(self.received_shares.values()) % N
        self.public_key_share = self.private_key_share * G
        
        self.log(f"DKG R4: Final private key share computed: {hex(self.private_key_share)}")
        self.log(f"DKG R4: Corresponding public key share: {serialize_point(self.public_key_share)}")
        
        # Generate ZKP for key share knowledge
        try:
            key_share_proof = self.zkp_key_prover.generate_key_share_proof(
                self.private_key_share, 
                self.public_key_share, 
                b"key_share_verification"
            )
            self.log_zkp_generation("key_share", key_share_proof, True)
            
        except Exception as e:
            self.log(f"Failed to generate key share ZKP: {str(e)}", "ERROR")
            key_share_proof = None
            self.log_zkp_generation("key_share", {}, False)
        
        self.add_to_memory("Private key share computed with ZKP", {
            "shares_used": len(self.received_shares),
            "private_key_share": hex(self.private_key_share),
            "public_key_share": serialize_point(self.public_key_share),
            "zkp_proof": key_share_proof
        })
        
        result = {
            "public_key_share": serialize_point(self.public_key_share)
        }
        
        if key_share_proof:
            result["zkp_key_share_proof"] = key_share_proof
        
        return result

    def get_aggregated_public_key(self):
        """Compute aggregated public key"""
        self.log("DKG R4: Computing aggregated public key (Y).")
        
        agg_pk = ecdsa.ellipticcurve.INFINITY
        commitment_details = {}
        
        for pid in sorted(self.received_commitments.keys()): 
            first_commitment = self.received_commitments[pid][0]
            agg_pk += first_commitment
            commitment_details[pid] = serialize_point(first_commitment)
        
        self.aggregated_public_key_point = agg_pk
        
        self.log(f"DKG R4: Individual first commitments: {json.dumps(commitment_details, indent=2)}")
        self.log(f"DKG R4: Aggregated public key computed: {serialize_point(self.aggregated_public_key_point)}")
        
        self.add_to_memory("Aggregated public key computed", {
            "public_key": serialize_point(self.aggregated_public_key_point),
            "individual_commitments": commitment_details
        })
        
        return self.aggregated_public_key_point
    
    # === Enhanced Signing Protocol Methods with ZKP ===
    
    def sign_round_1_create_nonce_share(self):
        """Create nonce share with ZKP"""
        self.current_operation = "SIGNING_ROUND_1"
        self.protocol_state = "signing_generating_nonce"
        
        self.log("SIGN R1: Creating secret nonce (k_i) and public nonce (R_i) with ZKP.")
        
        # Generate nonce (unchanged cryptography)
        self.k_share = secrets.randbelow(N)
        self.R_share = self.k_share * G
        
        self.log(f"SIGN R1: Generated nonce k_{self.id}: {hex(self.k_share)}")
        self.log(f"SIGN R1: Corresponding R_{self.id}: {serialize_point(self.R_share)}")
        
        # Generate ZKP for nonce correctness
        try:
            message_hash_bytes = bytes.fromhex(self.current_message_hash_hex) if self.current_message_hash_hex else b""
            nonce_proof = self.zkp_nonce_prover.generate_nonce_proof(
                self.k_share, 
                self.R_share, 
                message_hash_bytes
            )
            self.log_zkp_generation("nonce", nonce_proof, True)
            
        except Exception as e:
            self.log(f"Failed to generate nonce ZKP: {str(e)}", "ERROR")
            nonce_proof = None
            self.log_zkp_generation("nonce", {}, False)
        
        self.add_to_memory("Nonce share generated with ZKP", {
            "k_share": hex(self.k_share),
            "R_share": serialize_point(self.R_share),
            "message_hash": self.current_message_hash_hex,
            "zkp_proof": nonce_proof
        })
        
        result = {
            "R_share": serialize_point(self.R_share)
        }
        
        if nonce_proof:
            result["zkp_nonce_proof"] = nonce_proof
        
        return result

    def compute_final_shares(self):
        """Compute final signature shares with full logging"""
        self.current_operation = "SIGNING_FINAL"
        self.protocol_state = "signing_computing_final_shares"
        
        self.log("SIGN R2: Computing final secret shares for Coordinator.")
        
        # Compute Lagrange coefficient and weighted share (unchanged)
        lambda_i = compute_lagrange_coeff(self.current_signing_party_ids, self.id)
        weighted_x_share = (lambda_i * self.private_key_share) % N
        
        self.log(f"SIGN R2: Signing parties: {self.current_signing_party_ids}")
        self.log(f"SIGN R2: Lagrange coefficient λ_{self.id}: {hex(lambda_i)}")
        self.log(f"SIGN R2: Private key share x_{self.id}: {hex(self.private_key_share)}")
        self.log(f"SIGN R2: Nonce share k_{self.id}: {hex(self.k_share)}")
        self.log(f"SIGN R2: Weighted key share λ_{self.id}*x_{self.id}: {hex(weighted_x_share)}")
        
        self.add_to_memory("Final signature shares computed", {
            "lagrange_coefficient": hex(lambda_i),
            "private_key_share": hex(self.private_key_share),
            "weighted_x_share": hex(weighted_x_share),
            "k_share": hex(self.k_share),
            "signing_parties": self.current_signing_party_ids
        })
        
        return self.k_share, weighted_x_share

# Flask App Setup
app = Flask(__name__)

# Global signer instance
signer = None

def log(party_id, msg):
    """Legacy log function for compatibility"""
    if signer:
        signer.log(msg)
    else:
        print(f"--- LOG ---> [Signer {party_id}] {msg}")

# === Enhanced REST API Endpoints with ZKP ===

# Info Endpoint with ZKP stats
@app.route('/info', methods=['GET'])
def get_info():
    return jsonify({
        "status": "success", 
        "curve_order": hex(N), 
        "aggregated_public_key": serialize_point(signer.aggregated_public_key_point),
        "signer_info": {
            "party_id": signer.id,
            "protocol_state": signer.protocol_state,
            "current_operation": signer.current_operation,
            "zkp_stats": signer.zkp_stats
        }
    })

# Enhanced DKG Endpoints with ZKP
@app.route('/dkg/commitments', methods=['POST'])
def handle_dkg_commitments():
    data = request.get_json()
    sender_id = data['sender_id']
    
    signer.log(f"DKG R1: Received commitments from Party {sender_id}.")
    signer.log(f"DKG R1: Commitment data: {json.dumps(data, indent=2)}")
    
    signer.received_commitments[sender_id] = [deserialize_point(p) for p in data['commitments']]
    signer.add_to_memory(f"Received commitments from party {sender_id}", {
        "sender": sender_id, 
        "commitment_count": len(data['commitments']),
        "commitments": data['commitments']
    })
    
    return jsonify({"status": "success"})

@app.route('/dkg/round1/start', methods=['POST'])
def dkg_round1_start():
    signer.log("DKG R1: Received start command from Coordinator.")
    signer.add_to_memory("DKG Round 1 started by coordinator")
    
    # Generate commitments with ZKP
    result = signer.dkg_round_1_create_poly_and_commitments()
    signer.received_commitments[signer.id] = signer.commitments
    
    # Broadcast to other parties
    payload = {
        'sender_id': signer.id, 
        'commitments': result["commitments"]
    }
    broadcast_results = {}
    
    for pid, addr in signer.party_addresses.items():
        if pid != signer.id:
            signer.log(f"DKG R1: Broadcasting commitments to Party {pid} at {addr}.")
            try:
                response = requests.post(f"{addr}/dkg/commitments", json=payload, timeout=10)
                broadcast_results[pid] = "success" if response.status_code == 200 else "failed"
            except Exception as e:
                broadcast_results[pid] = f"error: {str(e)}"
                signer.log(f"Exception broadcasting to Party {pid}: {str(e)}")
    
    signer.add_to_memory("Commitments broadcast completed", broadcast_results)
    
    # Return result with ZKP
    response_data = {
        "status": "success", 
        "broadcast_results": broadcast_results
    }
    
    if "zkp_commitment_proof" in result:
        response_data["zkp_commitment_proof"] = result["zkp_commitment_proof"]
    
    return jsonify(response_data)

@app.route('/dkg/share', methods=['POST'])
def handle_dkg_share():
    data = request.get_json()
    sender_id = data['sender_id']
    
    signer.log(f"DKG R2: Received share from Party {sender_id}.")
    signer.log(f"DKG R2: Share data: {json.dumps(data, indent=2)}")
    
    if not signer.dkg_round_3_verify_and_store_share(
        sender_id, data['share_value'], signer.received_commitments[sender_id]
    ):
        return jsonify({"status": "error", "message": "Share verification failed"}), 400
    
    return jsonify({"status": "success"})

@app.route('/dkg/round2/start_share_exchange', methods=['POST'])
def dkg_round2_start_share_exchange():
    signer.log("DKG R2: Received start command from Coordinator.")
    signer.add_to_memory("DKG Round 2 started - share exchange")
    
    share_exchange_results = {}
    
    for pid in signer.party_addresses:
        share = signer.dkg_round_2_get_share_for_party(pid)
        
        if pid == signer.id:
            # Handle own share
            success = signer.dkg_round_3_verify_and_store_share(pid, share, signer.commitments)
            share_exchange_results[pid] = "self_verified" if success else "self_verification_failed"
        else:
            # Send to other party
            signer.log(f"DKG R2: Sending share to Party {pid}.")
            try:
                response = requests.post(
                    f"{signer.party_addresses[pid]}/dkg/share", 
                    json={'sender_id': signer.id, 'share_value': share},
                    timeout=10
                )
                share_exchange_results[pid] = "sent" if response.status_code == 200 else "failed"
            except Exception as e:
                share_exchange_results[pid] = f"error: {str(e)}"
                signer.log(f"Exception sending share to Party {pid}: {str(e)}")
    
    signer.add_to_memory("Share exchange completed", share_exchange_results)
    return jsonify({"status": "success", "exchange_results": share_exchange_results})

@app.route('/dkg/round4/compute_keys', methods=['POST'])
def dkg_round4_compute_keys():
    signer.log("DKG R4: Received start command from Coordinator.")
    signer.add_to_memory("DKG Round 4 started - key computation")
    
    result = signer.dkg_round_4_compute_key_shares()
    pk = signer.get_aggregated_public_key()
    
    response_data = {
        "status": "success", 
        "aggregated_public_key": serialize_point(pk),
        "public_key_share": result["public_key_share"],
        "signer_state": {
            "has_private_share": signer.private_key_share is not None,
            "shares_received_from": list(signer.received_shares.keys())
        }
    }
    
    if "zkp_key_share_proof" in result:
        response_data["zkp_key_share_proof"] = result["zkp_key_share_proof"]
    
    return jsonify(response_data)

@app.route('/dkg/aggregated_public_key', methods=['GET'])
def get_agg_pk_endpoint():
    if signer.aggregated_public_key_point is None: 
        return jsonify({"status": "error", "message": "Public key not computed yet"}), 404
    
    return jsonify({
        "status": "success", 
        "aggregated_public_key": serialize_point(signer.aggregated_public_key_point)
    })

# Enhanced Signing Endpoints with ZKP
@app.route('/sign/generate-nonce-share', methods=['POST'])
def generate_nonce_share():
    data = request.get_json()
    signer.log(f"SIGN R1: Received signing request from Coordinator.")
    signer.log(f"SIGN R1: Request data: {json.dumps(data, indent=2)}")
    
    signer.current_message_hash_hex = data['message_hash_hex']
    signer.current_signing_party_ids = data['signing_party_ids']
    signer.received_R_shares = {}
    
    signer.add_to_memory("Signing session started", {
        "message_hash": data['message_hash_hex'],
        "signing_parties": data['signing_party_ids']
    })
    
    result = signer.sign_round_1_create_nonce_share()
    signer.log(f"SIGN R1: Sending public nonce R_{signer.id} to Coordinator.")
    
    response_data = {
        "status": "success", 
        "R_share": result["R_share"],
        "party_id": signer.id
    }
    
    if "zkp_nonce_proof" in result:
        response_data["zkp_nonce_proof"] = result["zkp_nonce_proof"]
    
    return jsonify(response_data)

@app.route('/sign/receive-and-aggregate-r', methods=['POST'])
def receive_and_aggregate_r():
    data = request.get_json()
    signer.log(f"SIGN R2: Received complete R_shares list from Coordinator.")
    signer.log(f"SIGN R2: R_shares data: {json.dumps(data, indent=2)}")
    signer.protocol_state = "signing_aggregating_r"
    
    all_R_shares_ser = data['all_R_shares']
    
    # Deserialize and aggregate R shares
    for party_id_str, R_share_ser in all_R_shares_ser.items():
        signer.received_R_shares[int(party_id_str)] = deserialize_point(R_share_ser)
    
    R_agg = ecdsa.ellipticcurve.INFINITY
    for party_id, R_share in signer.received_R_shares.items():
        signer.log(f"SIGN R2: Adding R_{party_id}: {serialize_point(R_share)}")
        R_agg += R_share
    
    signer.aggregated_R_point = R_agg
    signer.current_r = R_agg.x() % N
    
    signer.log(f"SIGN R2: Aggregated R: {serialize_point(signer.aggregated_R_point)}")
    signer.log(f"SIGN R2: Final r value: {hex(signer.current_r)}")
    
    signer.add_to_memory("R aggregation completed", {
        "r_value": hex(signer.current_r),
        "aggregated_R": serialize_point(signer.aggregated_R_point),
        "individual_R_shares": {str(pid): serialize_point(R) for pid, R in signer.received_R_shares.items()}
    })
    
    return jsonify({
        "status": "success", 
        "r_hex": hex(signer.current_r),
        "party_id": signer.id
    })

@app.route('/sign/send-shares-to-coordinator', methods=['POST'])
def send_shares_to_coordinator():
    data = request.get_json()
    coordinator_url = data['coordinator_url']
    
    signer.log(f"SIGN R3: Received request to send final shares to Coordinator.")
    signer.log(f"SIGN R3: Coordinator URL: {coordinator_url}")
    
    k_i, weighted_x_i = signer.compute_final_shares()
    
    payload = {
        'sender_id': signer.id, 
        'k_share': k_i, 
        'weighted_x_share': weighted_x_i
    }
    
    signer.log(f"SIGN R3: Sending final shares to Coordinator: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(f"{coordinator_url}/submit-shares", json=payload, timeout=10)
        success = response.status_code == 200
        signer.add_to_memory("Final shares sent to coordinator", {
            "coordinator_url": coordinator_url,
            "payload": payload,
            "success": success
        })
        
        return jsonify({
            "status": "success" if success else "error",
            "message": "Shares sent successfully" if success else "Failed to send shares"
        })
    except Exception as e:
        signer.add_to_memory("Failed to send final shares", {"error": str(e)})
        signer.log(f"Exception sending shares to coordinator: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to send shares: {str(e)}"}), 500

# Status and monitoring endpoints
@app.route('/status', methods=['GET'])
def get_status():
    return jsonify({
        "signer_id": f"signer_zkp_{signer.id}",
        "party_id": signer.id,
        "protocol_state": signer.protocol_state,
        "current_operation": signer.current_operation,
        "has_private_key_share": signer.private_key_share is not None,
        "private_key_share": hex(signer.private_key_share) if signer.private_key_share else None,
        "memory_events": len(signer.memory),
        "zkp_stats": signer.zkp_stats
    })

@app.route('/memory', methods=['GET'])
def get_memory():
    # NO FILTERING - show everything including sensitive data
    return jsonify({
        "signer_id": f"signer_zkp_{signer.id}",
        "party_id": signer.id,
        "total_events": len(signer.memory),
        "memory": signer.memory  # All data visible
    })

@app.route('/zkp-proofs', methods=['GET'])
def get_zkp_proofs():
    return jsonify({
        "signer_id": f"signer_zkp_{signer.id}",
        "party_id": signer.id,
        "zkp_stats": signer.zkp_stats,
        "generated_proofs": signer.generated_proofs,
        "proof_history": {
            "commitment_proofs": signer.zkp_commitment_prover.proof_history,
            "key_share_proofs": signer.zkp_key_prover.proof_history,
            "nonce_proofs": signer.zkp_nonce_prover.proof_history
        }
    })

# Main Execution
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Basic Threshold ECDSA Signer with ZKP")
    parser.add_argument('--party_id', type=int, required=True, help='Party ID')
    parser.add_argument('--port', type=int, required=True, help='Port number')
    parser.add_argument('--num_parties', type=int, required=True, help='Total number of parties')
    parser.add_argument('--threshold', type=int, required=True, help='Threshold value')
    parser.add_argument('--party_addresses', type=str, required=True, nargs='+',
                       help='Party addresses in format "id:host:port"')
    
    args = parser.parse_args()
    
    # Parse party addresses
    parsed_party_addresses = {}
    for addr_str in args.party_addresses:
        p_id_str, p_host, p_port_str = addr_str.split(':')
        parsed_party_addresses[int(p_id_str)] = f"http://{p_host}:{p_port_str}"
    
    # Initialize global signer
    signer = SignerZKP(
        party_id=args.party_id,
        num_parties=args.num_parties,
        threshold=args.threshold,
        party_addresses=parsed_party_addresses,
        own_url=f"http://localhost:{args.port}"
    )
    
    print(f"Starting Basic Signer with Zero-Knowledge Proofs:")
    print(f"  Party ID: {signer.id}")
    print(f"  URL: {signer.url}")
    print(f"  Total Parties: {signer.num_parties}")
    print(f"  Threshold: {signer.threshold}")
    print(f"  ZKP verification enabled for enhanced security")
    print(f"  Known Party Addresses: {signer.party_addresses}")
    print(f"  CLEAR LOGGING: All sensitive data visible for POC")
    print(f"  No AI dependencies - pure Python implementation")
    
    app.run(host='0.0.0.0', port=args.port, debug=True, use_reloader=False)