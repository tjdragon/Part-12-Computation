#!/usr/bin/env python3
"""
Basic Coordinator with Zero-Knowledge Proofs
Enhanced CGGMP21 system with ZKP verification and detailed logging
No AI agents - pure Python implementation
"""

import requests
import json
import time
import ecdsa
import hashlib
from flask import Flask, request, jsonify
from typing import List, Dict, Any

# Import ZKP module
from zkp_module import (
    ZKAggregateVerifier, 
    deserialize_zkp_point,
    hash_points_and_message
)

# --- Configuration ---
PARTY_ADDRESSES = {
    1: "http://localhost:5001",
    2: "http://localhost:5002", 
    3: "http://localhost:5003",
}
COORDINATOR_PORT = 6000
COORDINATOR_URL = f"http://localhost:{COORDINATOR_PORT}"

current_session_data = {"k_shares": {}, "weighted_x_shares": {}}
app = Flask(__name__)

class CoordinatorZKP:
    def __init__(self):
        self.coordinator_id = "coordinator_zkp"
        self.context_memory = []
        self.current_operation = None
        self.protocol_state = "idle"
        
        # ZKP Components
        self.zkp_verifier = ZKAggregateVerifier()
        self.zkp_audit_trail = []
        self.party_zkp_status = {
            1: {"key_share_proven": False, "commitment_proven": False, "nonce_proven": False},
            2: {"key_share_proven": False, "commitment_proven": False, "nonce_proven": False},
            3: {"key_share_proven": False, "commitment_proven": False, "nonce_proven": False}
        }
        
    def add_to_memory(self, event: str, details: Dict[str, Any] = None):
        """Add events to coordinator memory - ALL DATA VISIBLE"""
        memory_entry = {
            "timestamp": time.time(),
            "event": event,
            "details": details or {},
            "operation": self.current_operation,
            "protocol_state": self.protocol_state
        }
        self.context_memory.append(memory_entry)
        # Keep only last 100 events
        if len(self.context_memory) > 100:
            self.context_memory = self.context_memory[-100:]
    
    def log(self, msg: str, level: str = "INFO"):
        """Enhanced logging with full visibility"""
        print(f"[{level}] [Coordinator ZKP] {msg}")
        self.add_to_memory(f"LOG: {msg}")
    
    def log_zkp_verification(self, party_id: int, proof_type: str, proof_data: Dict, is_valid: bool):
        """Log ZKP verification with full details"""
        self.log(f"ZKP VERIFICATION - Party {party_id} {proof_type}: {'VALID' if is_valid else 'INVALID'}")
        self.log(f"ZKP Details: {json.dumps(proof_data, indent=2)}")
        
        zkp_entry = {
            "party_id": party_id,
            "proof_type": proof_type,
            "is_valid": is_valid,
            "proof_data": proof_data,
            "timestamp": time.time()
        }
        self.zkp_audit_trail.append(zkp_entry)
        
        # Update party ZKP status
        if proof_type in self.party_zkp_status[party_id]:
            self.party_zkp_status[party_id][proof_type + "_proven"] = is_valid

coordinator = CoordinatorZKP()

def log(msg):
    """Legacy log function"""
    coordinator.log(msg)

def reset_session():
    current_session_data["k_shares"] = {}
    current_session_data["weighted_x_shares"] = {}
    coordinator.add_to_memory("Session reset", {"operation": "reset"})

# Enhanced DKG with ZKP Verification
@app.route('/dkg/start', methods=['POST'])
def start_dkg_process():
    coordinator.current_operation = "DKG"
    coordinator.protocol_state = "dkg_starting"
    
    log("Coordinator with ZKP received request to start DKG process.")
    coordinator.add_to_memory("DKG process with ZKP started", {"parties": list(PARTY_ADDRESSES.keys())})
    
    # Step 1: Commitment Exchange with ZKP
    log("DKG Step 1: Instructing parties to create commitments with ZK proofs...")
    coordinator.protocol_state = "dkg_commitments"
    
    commitment_results = {}
    zkp_commitment_results = {}
    
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Requesting commitments and ZKP from {address}/dkg/round1/start")
        try:
            response = requests.post(f"{address}/dkg/round1/start", timeout=10)
            if response.status_code == 200:
                result = response.json()
                commitment_results[party_id] = "success"
                log(f"Commitment response from Party {party_id}: {json.dumps(result, indent=2)}")
                
                # Verify ZKP if provided
                if "zkp_commitment_proof" in result:
                    zkp_proof = result["zkp_commitment_proof"]
                    verification_result = coordinator.zkp_verifier.verify_proof(zkp_proof)
                    
                    coordinator.log_zkp_verification(
                        party_id, "commitment", zkp_proof, verification_result["is_valid"]
                    )
                    zkp_commitment_results[party_id] = verification_result["is_valid"]
                else:
                    log(f"WARNING: Party {party_id} did not provide commitment ZKP")
                    zkp_commitment_results[party_id] = False
            else:
                commitment_results[party_id] = "failed"
                zkp_commitment_results[party_id] = False
                log(f"Failed to get commitments from Party {party_id}: HTTP {response.status_code}")
        except Exception as e:
            commitment_results[party_id] = f"error: {str(e)}"
            zkp_commitment_results[party_id] = False
            log(f"Exception getting commitments from Party {party_id}: {str(e)}")
    
    coordinator.add_to_memory("Commitment phase with ZKP completed", {
        "commitment_results": commitment_results,
        "zkp_results": zkp_commitment_results
    })
    time.sleep(2)

    # Step 2: Share Exchange
    log("DKG Step 2: Instructing parties to start share exchange...")
    coordinator.protocol_state = "dkg_shares"
    
    share_results = {}
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Sending POST to {address}/dkg/round2/start_share_exchange")
        try:
            response = requests.post(f"{address}/dkg/round2/start_share_exchange", timeout=10)
            share_results[party_id] = "success" if response.status_code == 200 else "failed"
            if response.status_code == 200:
                result = response.json()
                log(f"Share exchange response from Party {party_id}: {json.dumps(result, indent=2)}")
        except Exception as e:
            share_results[party_id] = f"error: {str(e)}"
            log(f"Exception in share exchange with Party {party_id}: {str(e)}")
    
    coordinator.add_to_memory("Share exchange completed", share_results)
    time.sleep(2)

    # Step 3: Compute Final Keys with ZKP Verification
    log("DKG Step 3: Instructing parties to compute final keys with ZK proofs...")
    coordinator.protocol_state = "dkg_finalization"
    
    key_computation_results = {}
    zkp_key_share_results = {}
    
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Requesting key computation and ZKP from {address}/dkg/round4/compute_keys")
        try:
            response = requests.post(f"{address}/dkg/round4/compute_keys", timeout=10)
            if response.status_code == 200:
                result = response.json()
                key_computation_results[party_id] = "success"
                log(f"Key computation response from Party {party_id}: {json.dumps(result, indent=2)}")
                
                # Verify key share ZKP if provided
                if "zkp_key_share_proof" in result:
                    zkp_proof = result["zkp_key_share_proof"]
                    expected_public_key = deserialize_zkp_point(result["public_key_share"])
                    
                    verification_result = coordinator.zkp_verifier.verify_proof(
                        zkp_proof, 
                        expected_public_key=expected_public_key,
                        message=b"key_share_verification"
                    )
                    
                    coordinator.log_zkp_verification(
                        party_id, "key_share", zkp_proof, verification_result["is_valid"]
                    )
                    zkp_key_share_results[party_id] = verification_result["is_valid"]
                else:
                    log(f"WARNING: Party {party_id} did not provide key share ZKP")
                    zkp_key_share_results[party_id] = False
            else:
                key_computation_results[party_id] = "failed"
                zkp_key_share_results[party_id] = False
                log(f"Failed key computation from Party {party_id}: HTTP {response.status_code}")
        except Exception as e:
            key_computation_results[party_id] = f"error: {str(e)}"
            zkp_key_share_results[party_id] = False
            log(f"Exception in key computation with Party {party_id}: {str(e)}")
    
    coordinator.add_to_memory("Key computation with ZKP completed", {
        "computation_results": key_computation_results,
        "zkp_results": zkp_key_share_results
    })
    time.sleep(1)

    # Step 4: Verification with ZKP Security Assessment
    log("DKG Step 4: Verifying DKG success and ZKP security status...")
    coordinator.protocol_state = "dkg_verification"
    
    first_pk = None
    agg_pk_hex = None
    verification_results = {}
    
    for party_id, address in PARTY_ADDRESSES.items():
        try:
            response = requests.get(f"{address}/dkg/aggregated_public_key")
            response.raise_for_status()
            current_pk = response.json()
            verification_results[party_id] = current_pk
            log(f"Received public key from Party {party_id}: {json.dumps(current_pk, indent=2)}")
            
            if first_pk is None:
                first_pk = current_pk
                agg_pk_hex = first_pk.get('aggregated_public_key')
            elif first_pk != current_pk:
                coordinator.add_to_memory("DKG FAILED", {"reason": f"Key mismatch at party {party_id}"})
                log(f"!! DKG FAILED: Mismatch in public keys at party {party_id}.")
                return jsonify({"status": "error", "message": f"DKG failed! Key mismatch at party {party_id}."}), 500
        except Exception as e:
            verification_results[party_id] = f"error: {str(e)}"
            log(f"Exception getting public key from Party {party_id}: {str(e)}")
    
    # Generate ZKP security report
    zkp_security_report = coordinator.zkp_verifier.get_security_report()
    
    coordinator.add_to_memory("DKG verification completed", {
        "verification_results": verification_results,
        "zkp_security_report": zkp_security_report
    })
    
    log("ZKP Security Summary:")
    log(f"  Total Proofs Verified: {zkp_security_report.get('total_verifications', 0)}")
    log(f"  Success Rate: {zkp_security_report.get('success_rate', 0):.1%}")
    log(f"  Failed Verifications: {zkp_security_report.get('failed_count', 0)}")
    
    coordinator.protocol_state = "idle"
    coordinator.current_operation = None
    
    log("DKG Process with Zero-Knowledge Proofs Completed Successfully.")
    return jsonify({
        "status": "success", 
        "message": "DKG with ZKP verification completed", 
        "aggregated_public_key": agg_pk_hex,
        "zkp_security_report": zkp_security_report,
        "zkp_party_status": coordinator.party_zkp_status
    })

# Enhanced Signing with ZKP Verification
@app.route('/request-signature', methods=['POST'])
def request_signature():
    coordinator.current_operation = "SIGNING"
    coordinator.protocol_state = "signing_starting"
    
    reset_session()
    data = request.get_json()
    message_hash_hex = data['message_hash_hex']
    signing_party_ids = data['signing_party_ids']
    
    coordinator.add_to_memory("Signature request with ZKP received", {
        "message_hash": message_hash_hex,
        "signing_parties": signing_party_ids
    })
    
    log(f"Received signature request for parties {signing_party_ids}")
    log(f"Message hash: {message_hash_hex}")

    # Round 1: Collect Public Nonces with ZKP
    log("Signing Step 1: Collecting public nonces with ZK proofs...")
    coordinator.protocol_state = "signing_nonces"
    
    all_R_shares = {}
    nonce_results = {}
    zkp_nonce_results = {}
    payload_r1 = {'message_hash_hex': message_hash_hex, 'signing_party_ids': signing_party_ids}
    
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/generate-nonce-share"
        log(f"Requesting nonce and ZKP from Party {party_id} at {url}")
        try:
            response = requests.post(url, json=payload_r1, timeout=10)
            response.raise_for_status()
            result = response.json()
            r_share_data = result['R_share']
            all_R_shares[str(party_id)] = r_share_data
            nonce_results[party_id] = "success"
            
            log(f"Received R_share from Party {party_id}: {json.dumps(r_share_data, indent=2)}")
            log(f"Full nonce response from Party {party_id}: {json.dumps(result, indent=2)}")
            
            # Verify nonce ZKP if provided
            if "zkp_nonce_proof" in result:
                zkp_proof = result["zkp_nonce_proof"]
                expected_R_share = deserialize_zkp_point(r_share_data)
                message_hash_bytes = bytes.fromhex(message_hash_hex)
                
                verification_result = coordinator.zkp_verifier.verify_proof(
                    zkp_proof,
                    expected_R_share=expected_R_share,
                    message_hash=message_hash_bytes
                )
                
                coordinator.log_zkp_verification(
                    party_id, "nonce", zkp_proof, verification_result["is_valid"]
                )
                zkp_nonce_results[party_id] = verification_result["is_valid"]
            else:
                log(f"WARNING: Party {party_id} did not provide nonce ZKP")
                zkp_nonce_results[party_id] = False
                
        except Exception as e:
            nonce_results[party_id] = f"error: {str(e)}"
            zkp_nonce_results[party_id] = False
            log(f"Exception getting nonce from Party {party_id}: {str(e)}")
    
    coordinator.add_to_memory("Nonce collection with ZKP completed", {
        "nonce_results": nonce_results,
        "zkp_results": zkp_nonce_results
    })
    
    # Round 2: Distribute All Nonces and Aggregate R
    log("Signing Step 2: Distributing complete nonce list to all parties...")
    coordinator.protocol_state = "signing_aggregation"
    
    r_hex = None
    aggregation_results = {}
    payload_r2 = {'all_R_shares': all_R_shares}
    
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/receive-and-aggregate-r"
        log(f"Sending full R_share list to Party {party_id} at {url}")
        log(f"R_shares payload: {json.dumps(payload_r2, indent=2)}")
        try:
            response = requests.post(url, json=payload_r2, timeout=10)
            response.raise_for_status()
            result = response.json()
            if r_hex is None: 
                r_hex = result.get('r_hex')
            aggregation_results[party_id] = "success"
            log(f"R aggregation response from Party {party_id}: {json.dumps(result, indent=2)}")
        except Exception as e:
            aggregation_results[party_id] = f"error: {str(e)}"
            log(f"Exception in R aggregation with Party {party_id}: {str(e)}")
    
    coordinator.add_to_memory("R aggregation completed", {
        "r_value": r_hex, 
        "results": aggregation_results
    })
    log(f"All parties agreed on r = {r_hex}")

    # Round 3: Request Final Shares
    log("Signing Step 3: Instructing parties to send final shares...")
    coordinator.protocol_state = "signing_shares"
    
    payload_r3 = {'coordinator_url': COORDINATOR_URL}
    share_collection_results = {}
    
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/send-shares-to-coordinator"
        log(f"Requesting final shares from Party {party_id} at {url}")
        try:
            response = requests.post(url, json=payload_r3, timeout=10)
            share_collection_results[party_id] = "success" if response.status_code == 200 else "failed"
            if response.status_code == 200:
                result = response.json()
                log(f"Share collection response from Party {party_id}: {json.dumps(result, indent=2)}")
        except Exception as e:
            share_collection_results[party_id] = f"error: {str(e)}"
            log(f"Exception in share collection from Party {party_id}: {str(e)}")
    
    coordinator.add_to_memory("Share collection requested", share_collection_results)
    time.sleep(1)

    # Round 4 & 5: Assemble and Verify
    log("Signing Step 4: Assembling final signature...")
    coordinator.protocol_state = "signing_finalization"
    
    if len(current_session_data["k_shares"]) != len(signing_party_ids):
        error_msg = "Did not receive shares from all parties."
        coordinator.add_to_memory("Signature assembly failed", {"reason": error_msg})
        log(f"ERROR: {error_msg}")
        return jsonify({"status": "error", "message": error_msg}), 500
    
    k_agg = sum(current_session_data["k_shares"].values())
    x_recon = sum(current_session_data["weighted_x_shares"].values())
    
    log(f"CLEAR DATA - Aggregated k_agg: {hex(k_agg)}")
    log(f"CLEAR DATA - Reconstructed x_recon: {hex(x_recon)}")
    log(f"CLEAR DATA - All k_shares: {[hex(k) for k in current_session_data['k_shares'].values()]}")
    log(f"CLEAR DATA - All weighted_x_shares: {[hex(x) for x in current_session_data['weighted_x_shares'].values()]}")
    
    # Get curve parameters and public key
    resp = requests.get(f"{PARTY_ADDRESSES[signing_party_ids[0]]}/info")
    info = resp.json()
    N = int(info['curve_order'], 16)
    agg_pk_data = info['aggregated_public_key']
    agg_pk_point = deserialize_point(agg_pk_data)
    
    log(f"CLEAR DATA - Curve order N: {hex(N)}")
    log(f"CLEAR DATA - Aggregated public key: {json.dumps(agg_pk_data, indent=2)}")
    
    # Calculate final signature
    k_inv = pow(k_agg, N - 2, N)
    r_val = int(r_hex, 16)
    e = int(message_hash_hex, 16)
    s_val = (k_inv * (e + r_val * x_recon)) % N
    
    log(f"CLEAR DATA - Final signature components:")
    log(f"  k_inv: {hex(k_inv)}")
    log(f"  r_val: {hex(r_val)}")
    log(f"  e (message hash): {hex(e)}")
    log(f"  s_val: {hex(s_val)}")

    # Verification
    log("Signing Step 5: Verifying final signature...")
    coordinator.protocol_state = "signing_verification"
    
    try:
        vk = ecdsa.VerifyingKey.from_public_point(agg_pk_point, curve=ecdsa.SECP256k1)
        sig_der = ecdsa.util.sigencode_string(r_val, s_val, N)
        is_valid = vk.verify_digest(sig_der, bytes.fromhex(message_hash_hex), sigdecode=ecdsa.util.sigdecode_string)
        log(f"Signature verification result: {is_valid}")
    except Exception as e:
        coordinator.add_to_memory("Signature verification failed", {"error": str(e)})
        log(f"Exception in signature verification: {str(e)}")
        return jsonify({"status": "error", "message": f"Verification error: {str(e)}"}), 500

    # Generate comprehensive ZKP security report
    final_zkp_report = coordinator.zkp_verifier.get_security_report()
    
    log("Final ZKP Security Report:")
    log(f"  Total Verifications: {final_zkp_report.get('total_verifications', 0)}")
    log(f"  Success Rate: {final_zkp_report.get('success_rate', 0):.1%}")
    log(f"  Failed Count: {final_zkp_report.get('failed_count', 0)}")
    log(f"  Proof Types: {final_zkp_report.get('proof_types', [])}")
    
    coordinator.protocol_state = "idle"
    coordinator.current_operation = None

    if is_valid:
        coordinator.add_to_memory("Signature with ZKP completed successfully", {
            "r": hex(r_val), 
            "s": hex(s_val),
            "verified": True,
            "zkp_report": final_zkp_report
        })
        log("Signature is VALID with Zero-Knowledge Proof verification.")
        return jsonify({
            "status": "success", 
            "signature": {"r": hex(r_val), "s": hex(s_val)},
            "zkp_security_report": final_zkp_report,
            "zkp_party_status": coordinator.party_zkp_status
        })
    else:
        coordinator.add_to_memory("Signature verification failed", {
            "r": hex(r_val), 
            "s": hex(s_val),
            "verified": False
        })
        log("!! Signature is INVALID.")
        return jsonify({"status": "error", "message": "Final signature failed verification."}), 500

# Endpoint for Signers to submit their final shares
@app.route('/submit-shares', methods=['POST'])
def submit_shares():
    data = request.get_json()
    sender_id = data['sender_id']
    
    coordinator.add_to_memory(f"Received shares from party {sender_id}", data)
    log(f"CLEAR DATA - Received final shares from Party {sender_id}: {json.dumps(data, indent=2)}")
    
    current_session_data["k_shares"][sender_id] = data['k_share']
    current_session_data["weighted_x_shares"][sender_id] = data['weighted_x_share']
    
    return jsonify({"status": "success"})

# Status and monitoring endpoints
@app.route('/status', methods=['GET'])
def get_status():
    zkp_report = coordinator.zkp_verifier.get_security_report()
    return jsonify({
        "coordinator_id": coordinator.coordinator_id,
        "protocol_state": coordinator.protocol_state,
        "current_operation": coordinator.current_operation,
        "memory_events": len(coordinator.context_memory),
        "zkp_verifier_stats": coordinator.zkp_verifier.security_stats,
        "zkp_security_report": zkp_report,
        "party_zkp_status": coordinator.party_zkp_status
    })

@app.route('/memory', methods=['GET'])
def get_memory():
    return jsonify({
        "coordinator_id": coordinator.coordinator_id,
        "total_events": len(coordinator.context_memory),
        "memory": coordinator.context_memory
    })

@app.route('/zkp-audit', methods=['GET'])
def get_zkp_audit():
    return jsonify({
        "coordinator_id": coordinator.coordinator_id,
        "zkp_audit_trail": coordinator.zkp_audit_trail,
        "zkp_security_report": coordinator.zkp_verifier.get_security_report(),
        "verification_history": coordinator.zkp_verifier.verification_history
    })

def deserialize_point(data):
    if data.get("type") == "infinity": 
        return ecdsa.ellipticcurve.INFINITY
    return ecdsa.ellipticcurve.Point(ecdsa.SECP256k1.curve, int(data['x'], 16), int(data['y'], 16))

if __name__ == '__main__':
    print(f"Starting Basic Coordinator with Zero-Knowledge Proofs on {COORDINATOR_URL}")
    print("ZKP verification enabled for enhanced security")
    print("No AI dependencies - pure Python implementation")
    app.run(host='0.0.0.0', port=COORDINATOR_PORT)
