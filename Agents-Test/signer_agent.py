#!/usr/bin/env python3
"""
AI-Powered Signer Agent for CGGMP21 Threshold Signature System
Uses Ollama for intelligent decision making and natural language communication
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
import asyncio
import aiohttp
from typing import Dict, Any, List

# Ollama Configuration
OLLAMA_API_URL = "http://localhost:11434/api/generate"

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

class SignerAgent:
    """AI-Enhanced MPC Signer Agent"""
    
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
        
        # AI Agent attributes
        self.agent_memory = []
        self.current_operation = None
        self.protocol_state = "idle"
        self.trust_scores = {pid: 1.0 for pid in range(1, num_parties + 1)}  # Trust other parties
        self.decision_history = []
        
    def add_to_memory(self, event: str, details: Dict[str, Any] = None, security_level: str = "normal"):
        """Add events to agent memory with security awareness"""
        memory_entry = {
            "timestamp": time.time(),
            "event": event,
            "details": details or {},
            "operation": self.current_operation,
            "protocol_state": self.protocol_state,
            "security_level": security_level
        }
        self.agent_memory.append(memory_entry)
        # Keep only last 100 events for memory efficiency
        if len(self.agent_memory) > 100:
            self.agent_memory = self.agent_memory[-100:]
    
    async def think(self, situation: str, decision_needed: str = None, security_context: str = None) -> str:
        """Use Ollama AI to reason about MPC operations"""
        context = self._build_context()
        
        security_note = f"\nSecurity Context: {security_context}" if security_context else ""
        
        prompt = f"""You are Signer Agent {self.id} in a {self.num_parties}-party threshold cryptography system (threshold={self.threshold}).

Your Role: Participate in secure multi-party computation for ECDSA signatures while maintaining cryptographic security.

Current Context:
{context}

Current Situation: {situation}
{security_note}

{f"Decision Needed: {decision_needed}" if decision_needed else ""}

Provide a brief, technical response about your participation in this MPC protocol. Focus on security and correct protocol execution. Keep response under 100 words."""

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": "llama3.2:1b",
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,  # Lower temperature for more deterministic crypto decisions
                        "max_tokens": 100
                    }
                }
                
                async with session.post(OLLAMA_API_URL, json=payload, timeout=10) as response:
                    if response.status == 200:
                        result = await response.json()
                        reasoning = result.get("response", "").strip()
                        self.decision_history.append({
                            "timestamp": time.time(),
                            "situation": situation,
                            "reasoning": reasoning
                        })
                        return reasoning
                    else:
                        return "AI reasoning unavailable, following protocol strictly"
        except Exception as e:
            return f"AI reasoning failed ({str(e)}), following standard protocol"
    
    def _build_context(self) -> str:
        """Build context from recent memory"""
        if not self.agent_memory:
            return f"Signer {self.id} initialized. No previous protocol activity."
        
        recent_events = self.agent_memory[-5:]  # Last 5 events
        context_lines = [f"Party {self.id} Recent Activity:"]
        
        for event in recent_events:
            context_lines.append(f"- {event['event']} (State: {event['protocol_state']})")
            if event['details'] and event['security_level'] != "sensitive":
                context_lines.append(f"  Details: {event['details']}")
        
        # Add current protocol state
        context_lines.append(f"\nCurrent State: {self.protocol_state}")
        context_lines.append(f"Has Private Key Share: {self.private_key_share is not None}")
        context_lines.append(f"Received Shares From: {list(self.received_shares.keys())}")
        
        return "\n".join(context_lines)
    
    def log(self, msg: str, level: str = "INFO", security: str = "normal"):
        """Enhanced logging with AI context and security awareness"""
        print(f"[{level}] [Signer Agent {self.id}] {msg}")
        if security != "sensitive":  # Don't log sensitive crypto material
            self.add_to_memory(f"LOG: {msg}", security_level=security)

    # === DKG Protocol Methods (Enhanced with AI) ===
    
    def dkg_round_1_create_poly_and_commitments(self):
        """DKG Round 1: Create polynomial and commitments with AI oversight"""
        self.current_operation = "DKG_ROUND_1"
        self.protocol_state = "dkg_generating_polynomial"
        
        self.log("DKG R1: Creating secret polynomial and public commitments.")
        
        # AI reasoning about polynomial generation
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ai_reasoning = loop.run_until_complete(
                self.think(
                    f"Generating degree-{self.threshold-1} polynomial for threshold scheme",
                    "Should I proceed with polynomial generation?",
                    "Critical: Polynomial coefficients must remain secret"
                )
            )
            self.log(f"AI Decision: {ai_reasoning}")
        except:
            self.log("AI reasoning unavailable for polynomial generation")
        
        # Generate polynomial (same cryptographic operation)
        self.poly_coeffs = [secrets.randbelow(N) for _ in range(self.threshold)]
        self.commitments = [c * G for c in self.poly_coeffs]
        
        self.log(f"DKG R1: Generated polynomial with first coefficient: {hex(self.poly_coeffs[0])}", security="sensitive")
        self.add_to_memory("Polynomial and commitments generated", 
                          {"threshold": self.threshold, "commitment_count": len(self.commitments)})
        
        return [serialize_point(p) for p in self.commitments]
    
    def dkg_round_2_get_share_for_party(self, j_id):
        """Generate share for party j with AI validation"""
        if self.current_operation != "DKG_ROUND_2":
            self.current_operation = "DKG_ROUND_2"
            self.protocol_state = "dkg_generating_shares"
        
        # Evaluate polynomial at point j_id
        y = 0
        for c in reversed(self.poly_coeffs): 
            y = (y * j_id + c) % N
        
        self.log(f"DKG R2: Computed share for party {j_id}: {hex(y)}", security="sensitive")
        self.add_to_memory(f"Generated share for party {j_id}", {"target_party": j_id}, "sensitive")
        
        return y

    def dkg_round_3_verify_and_store_share(self, from_id, share, commitments):
        """Verify share with AI-enhanced validation"""
        self.current_operation = "DKG_ROUND_3"
        self.protocol_state = "dkg_verifying_shares"
        
        self.log(f"DKG R3: Verifying share from party {from_id}...")
        
        # AI reasoning about share verification
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ai_reasoning = loop.run_until_complete(
                self.think(
                    f"Verifying secret share from party {from_id} using commitment scheme",
                    "Should I trust this share if it verifies correctly?",
                    "Critical: Share verification prevents malicious behavior"
                )
            )
            self.log(f"AI Security Assessment: {ai_reasoning}")
        except:
            self.log("AI verification reasoning unavailable")
        
        # Standard share verification (unchanged cryptography)
        lhs = share * G
        rhs = ecdsa.ellipticcurve.INFINITY
        for k_idx, c in enumerate(commitments): 
            rhs += pow(self.id, k_idx, N) * c
        
        if lhs != rhs:
            self.log(f"!! DKG R3: Share verification FAILED for party {from_id}.", "ERROR")
            self.add_to_memory(f"Share verification failed from party {from_id}", 
                             {"from_party": from_id, "verified": False})
            # Reduce trust in this party
            if from_id in self.trust_scores:
                self.trust_scores[from_id] *= 0.5
            return False
        
        self.log(f"DKG R3: Share from party {from_id} is VALID. Storing.")
        self.received_shares[from_id] = share
        self.add_to_memory(f"Share verified and stored from party {from_id}", 
                          {"from_party": from_id, "verified": True})
        
        return True

    def dkg_round_4_compute_key_shares(self):
        """Compute final key shares with AI oversight"""
        self.current_operation = "DKG_ROUND_4"
        self.protocol_state = "dkg_computing_final_keys"
        
        self.log("DKG R4: Computing my private key share (x_i) from all received shares.")
        
        # AI reasoning about key computation
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ai_reasoning = loop.run_until_complete(
                self.think(
                    f"Computing final private key share from {len(self.received_shares)} verified shares",
                    "Is it safe to finalize my key share computation?",
                    "Critical: This creates my permanent key share"
                )
            )
            self.log(f"AI Key Security Assessment: {ai_reasoning}")
        except:
            self.log("AI key computation reasoning unavailable")
        
        # Compute private key share (unchanged)
        self.private_key_share = sum(self.received_shares.values()) % N
        self.public_key_share = self.private_key_share * G
        
        self.log(f"DKG R4: Final private key share computed: {hex(self.private_key_share)}", security="sensitive")
        self.add_to_memory("Private key share computed", 
                          {"shares_used": len(self.received_shares)}, "sensitive")
        
        return True

    def get_aggregated_public_key(self):
        """Compute aggregated public key with AI verification"""
        self.log("DKG R4: Computing aggregated public key (Y).")
        
        agg_pk = ecdsa.ellipticcurve.INFINITY
        for pid in sorted(self.received_commitments.keys()): 
            agg_pk += self.received_commitments[pid][0]
        
        self.aggregated_public_key_point = agg_pk
        self.log(f"DKG R4: Aggregated public key computed: {serialize_point(self.aggregated_public_key_point)}")
        
        # AI validation of public key
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ai_validation = loop.run_until_complete(
                self.think(
                    f"Computed aggregated public key from {len(self.received_commitments)} party commitments",
                    "Does this public key look valid for our threshold scheme?"
                )
            )
            self.log(f"AI Public Key Validation: {ai_validation}")
        except:
            self.log("AI public key validation unavailable")
        
        self.add_to_memory("Aggregated public key computed", 
                          {"public_key": serialize_point(self.aggregated_public_key_point)})
        
        return self.aggregated_public_key_point
    
    # === Signing Protocol Methods (Enhanced with AI) ===
    
    def sign_round_1_create_nonce_share(self):
        """Create nonce share with AI security assessment"""
        self.current_operation = "SIGNING_ROUND_1"
        self.protocol_state = "signing_generating_nonce"
        
        self.log("SIGN R1: Creating secret nonce (k_i) and public nonce (R_i).")
        
        # AI reasoning about nonce generation
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ai_reasoning = loop.run_until_complete(
                self.think(
                    "Generating cryptographically secure nonce for ECDSA signing",
                    "Should I proceed with nonce generation for this signing session?",
                    "Critical: Nonce must be unique and secret for signature security"
                )
            )
            self.log(f"AI Nonce Security Assessment: {ai_reasoning}")
        except:
            self.log("AI nonce reasoning unavailable")
        
        # Generate nonce (unchanged cryptography)
        self.k_share = secrets.randbelow(N)
        self.R_share = self.k_share * G
        
        self.log(f"SIGN R1: Generated nonce k_{self.id}: {hex(self.k_share)}", security="sensitive")
        self.add_to_memory("Nonce share generated", 
                          {"R_share": serialize_point(self.R_share)}, "sensitive")
        
        return serialize_point(self.R_share)

    def compute_final_shares(self):
        """Compute final signature shares with AI oversight"""
        self.current_operation = "SIGNING_FINAL"
        self.protocol_state = "signing_computing_final_shares"
        
        self.log("SIGN R2: Computing final secret shares for Coordinator.")
        
        # AI reasoning about final share computation
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ai_reasoning = loop.run_until_complete(
                self.think(
                    f"Computing final signature shares using Lagrange coefficient for parties {self.current_signing_party_ids}",
                    "Should I provide my final shares to complete the signature?",
                    "Critical: Final shares complete the threshold signature"
                )
            )
            self.log(f"AI Final Share Assessment: {ai_reasoning}")
        except:
            self.log("AI final share reasoning unavailable")
        
        # Compute Lagrange coefficient and weighted share (unchanged)
        lambda_i = compute_lagrange_coeff(self.current_signing_party_ids, self.id)
        weighted_x_share = (lambda_i * self.private_key_share) % N
        
        self.log(f"SIGN R2: Lagrange coefficient λ_{self.id}: {hex(lambda_i)}")
        self.log(f"SIGN R2: Nonce share k_{self.id}: {hex(self.k_share)}", security="sensitive")
        self.log(f"SIGN R2: Weighted key share λ_{self.id}*x_{self.id}: {hex(weighted_x_share)}", security="sensitive")
        
        self.add_to_memory("Final signature shares computed", 
                          {"lagrange_coeff": hex(lambda_i), "signing_parties": self.current_signing_party_ids}, 
                          "sensitive")
        
        return self.k_share, weighted_x_share

# Flask App Setup
app = Flask(__name__)

# Global signer agent instance
signer_agent = None

def log(party_id, msg):
    """Legacy log function for compatibility"""
    if signer_agent:
        signer_agent.log(msg)
    else:
        print(f"--- LOG ---> [Signer {party_id}] {msg}")

# === REST API Endpoints (Enhanced with AI) ===

# Info Endpoint
@app.route('/info', methods=['GET'])
def get_info():
    return jsonify({
        "status": "success", 
        "curve_order": hex(N), 
        "aggregated_public_key": serialize_point(signer_agent.aggregated_public_key_point),
        "agent_info": {
            "party_id": signer_agent.id,
            "protocol_state": signer_agent.protocol_state,
            "current_operation": signer_agent.current_operation
        }
    })

# DKG Endpoints
@app.route('/dkg/commitments', methods=['POST'])
def handle_dkg_commitments():
    data = request.get_json()
    sender_id = data['sender_id']
    
    signer_agent.log(f"DKG R1: Received commitments from Party {sender_id}.")
    signer_agent.received_commitments[sender_id] = [deserialize_point(p) for p in data['commitments']]
    signer_agent.add_to_memory(f"Received commitments from party {sender_id}", 
                              {"sender": sender_id, "commitment_count": len(data['commitments'])})
    
    return jsonify({"status": "success"})

@app.route('/dkg/round1/start', methods=['POST'])
def dkg_round1_start():
    signer_agent.log("DKG R1: Received start command from Coordinator.")
    signer_agent.add_to_memory("DKG Round 1 started by coordinator")
    
    # Generate commitments
    c_ser = signer_agent.dkg_round_1_create_poly_and_commitments()
    signer_agent.received_commitments[signer_agent.id] = signer_agent.commitments
    
    # Broadcast to other parties
    payload = {'sender_id': signer_agent.id, 'commitments': c_ser}
    broadcast_results = {}
    
    for pid, addr in signer_agent.party_addresses.items():
        if pid != signer_agent.id:
            signer_agent.log(f"DKG R1: Broadcasting my commitments to Party {pid} at {addr}.")
            try:
                response = requests.post(f"{addr}/dkg/commitments", json=payload, timeout=5)
                broadcast_results[pid] = "success" if response.status_code == 200 else "failed"
            except Exception as e:
                broadcast_results[pid] = f"error: {str(e)}"
    
    signer_agent.add_to_memory("Commitments broadcast completed", broadcast_results)
    return jsonify({"status": "success", "broadcast_results": broadcast_results})

@app.route('/dkg/share', methods=['POST'])
def handle_dkg_share():
    data = request.get_json()
    sender_id = data['sender_id']
    
    signer_agent.log(f"DKG R2: Received share from Party {sender_id}.")
    
    if not signer_agent.dkg_round_3_verify_and_store_share(
        sender_id, data['share_value'], signer_agent.received_commitments[sender_id]
    ):
        return jsonify({"status": "error", "message": "Share verification failed"}), 400
    
    return jsonify({"status": "success"})

@app.route('/dkg/round2/start_share_exchange', methods=['POST'])
def dkg_round2_start_share_exchange():
    signer_agent.log("DKG R2: Received start command from Coordinator.")
    signer_agent.add_to_memory("DKG Round 2 started - share exchange")
    
    share_exchange_results = {}
    
    for pid in signer_agent.party_addresses:
        share = signer_agent.dkg_round_2_get_share_for_party(pid)
        
        if pid == signer_agent.id:
            # Handle own share
            success = signer_agent.dkg_round_3_verify_and_store_share(pid, share, signer_agent.commitments)
            share_exchange_results[pid] = "self_verified" if success else "self_verification_failed"
        else:
            # Send to other party
            signer_agent.log(f"DKG R2: Sending share to Party {pid}.")
            try:
                response = requests.post(
                    f"{signer_agent.party_addresses[pid]}/dkg/share", 
                    json={'sender_id': signer_agent.id, 'share_value': share},
                    timeout=5
                )
                share_exchange_results[pid] = "sent" if response.status_code == 200 else "failed"
            except Exception as e:
                share_exchange_results[pid] = f"error: {str(e)}"
    
    signer_agent.add_to_memory("Share exchange completed", share_exchange_results)
    return jsonify({"status": "success", "exchange_results": share_exchange_results})

@app.route('/dkg/round4/compute_keys', methods=['POST'])
def dkg_round4_compute_keys():
    signer_agent.log("DKG R4: Received start command from Coordinator.")
    signer_agent.add_to_memory("DKG Round 4 started - key computation")
    
    signer_agent.dkg_round_4_compute_key_shares()
    pk = signer_agent.get_aggregated_public_key()
    
    return jsonify({
        "status": "success", 
        "aggregated_public_key": serialize_point(pk),
        "agent_state": {
            "has_private_share": signer_agent.private_key_share is not None,
            "shares_received_from": list(signer_agent.received_shares.keys())
        }
    })

@app.route('/dkg/aggregated_public_key', methods=['GET'])
def get_agg_pk_endpoint():
    if signer_agent.aggregated_public_key_point is None: 
        return jsonify({"status": "error", "message": "Public key not computed yet"}), 404
    
    return jsonify({
        "status": "success", 
        "aggregated_public_key": serialize_point(signer_agent.aggregated_public_key_point)
    })

# Signing Endpoints
@app.route('/sign/generate-nonce-share', methods=['POST'])
def generate_nonce_share():
    data = request.get_json()
    signer_agent.log(f"SIGN R1: Received signing request from Coordinator.")
    
    signer_agent.current_message_hash_hex = data['message_hash_hex']
    signer_agent.current_signing_party_ids = data['signing_party_ids']
    signer_agent.received_R_shares = {}
    
    signer_agent.add_to_memory("Signing session started", {
        "message_hash": data['message_hash_hex'],
        "signing_parties": data['signing_party_ids']
    })
    
    r_share_ser = signer_agent.sign_round_1_create_nonce_share()
    signer_agent.log(f"SIGN R1: Sending public nonce R_{signer_agent.id} to Coordinator.")
    
    return jsonify({
        "status": "success", 
        "R_share": r_share_ser,
        "party_id": signer_agent.id
    })

@app.route('/sign/receive-and-aggregate-r', methods=['POST'])
def receive_and_aggregate_r():
    data = request.get_json()
    signer_agent.log(f"SIGN R2: Received complete R_shares list from Coordinator.")
    signer_agent.protocol_state = "signing_aggregating_r"
    
    all_R_shares_ser = data['all_R_shares']
    
    # AI reasoning about R aggregation
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ai_reasoning = loop.run_until_complete(
            signer_agent.think(
                f"Aggregating {len(all_R_shares_ser)} R shares to compute signature r value",
                "Should I trust these R shares for signature aggregation?"
            )
        )
        signer_agent.log(f"AI R Aggregation Assessment: {ai_reasoning}")
    except:
        signer_agent.log("AI R aggregation reasoning unavailable")
    
    for party_id_str, R_share_ser in all_R_shares_ser.items():
        signer_agent.received_R_shares[int(party_id_str)] = deserialize_point(R_share_ser)
    
    R_agg = ecdsa.ellipticcurve.INFINITY
    for R_share in signer_agent.received_R_shares.values():
        R_agg += R_share
    
    signer_agent.aggregated_R_point = R_agg
    signer_agent.current_r = R_agg.x() % N
    
    signer_agent.log(f"SIGN R2: Aggregated R shares. Final r value: {hex(signer_agent.current_r)}")
    signer_agent.add_to_memory("R aggregation completed", {
        "r_value": hex(signer_agent.current_r),
        "r_shares_count": len(all_R_shares_ser)
    })
    
    return jsonify({
        "status": "success", 
        "r_hex": hex(signer_agent.current_r),
        "party_id": signer_agent.id
    })

@app.route('/sign/send-shares-to-coordinator', methods=['POST'])
def send_shares_to_coordinator():
    data = request.get_json()
    coordinator_url = data['coordinator_url']
    
    signer_agent.log(f"SIGN R3: Received request to send final shares to Coordinator.")
    
    k_i, weighted_x_i = signer_agent.compute_final_shares()
    
    payload = {
        'sender_id': signer_agent.id, 
        'k_share': k_i, 
        'weighted_x_share': weighted_x_i
    }
    
    signer_agent.log(f"SIGN R3: Sending final shares to Coordinator at {coordinator_url}.")
    
    try:
        response = requests.post(f"{coordinator_url}/submit-shares", json=payload, timeout=5)
        success = response.status_code == 200
        signer_agent.add_to_memory("Final shares sent to coordinator", {
            "coordinator_url": coordinator_url,
            "success": success
        }, "sensitive")
        
        return jsonify({
            "status": "success" if success else "error",
            "message": "Shares sent successfully" if success else "Failed to send shares"
        })
    except Exception as e:
        signer_agent.add_to_memory("Failed to send final shares", {"error": str(e)})
        return jsonify({"status": "error", "message": f"Failed to send shares: {str(e)}"}), 500

# Agent-specific endpoints
@app.route('/agent/status', methods=['GET'])
def get_agent_status():
    return jsonify({
        "agent_id": f"signer_agent_{signer_agent.id}",
        "party_id": signer_agent.id,
        "protocol_state": signer_agent.protocol_state,
        "current_operation": signer_agent.current_operation,
        "has_private_key_share": signer_agent.private_key_share is not None,
        "memory_events": len(signer_agent.agent_memory),
        "trust_scores": signer_agent.trust_scores,
        "recent_decisions": signer_agent.decision_history[-3:] if signer_agent.decision_history else []
    })

@app.route('/agent/memory', methods=['GET'])
def get_agent_memory():
    # Filter out sensitive information from memory export
    safe_memory = []
    for entry in signer_agent.agent_memory:
        safe_entry = entry.copy()
        if entry.get('security_level') == 'sensitive':
            safe_entry['details'] = "[REDACTED - SENSITIVE]"
        safe_memory.append(safe_entry)
    
    return jsonify({
        "agent_id": f"signer_agent_{signer_agent.id}",
        "party_id": signer_agent.id,
        "total_events": len(signer_agent.agent_memory),
        "memory": safe_memory
    })

@app.route('/agent/trust', methods=['GET'])
def get_trust_scores():
    return jsonify({
        "agent_id": f"signer_agent_{signer_agent.id}",
        "party_id": signer_agent.id,
        "trust_scores": signer_agent.trust_scores,
        "decision_history_count": len(signer_agent.decision_history)
    })

# Main Execution
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AI-Enhanced Threshold ECDSA Signer Agent")
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
    
    # Initialize global signer agent
    signer_agent = SignerAgent(
        party_id=args.party_id,
        num_parties=args.num_parties,
        threshold=args.threshold,
        party_addresses=parsed_party_addresses,
        own_url=f"http://localhost:{args.port}"
    )
    
    print(f"Starting AI-Enhanced Signer Agent:")
    print(f"  Party ID: {signer_agent.id}")
    print(f"  URL: {signer_agent.url}")
    print(f"  Total Parties: {signer_agent.num_parties}")
    print(f"  Threshold: {signer_agent.threshold}")
    print(f"  AI capabilities powered by Ollama")
    print(f"  Known Party Addresses: {signer_agent.party_addresses}")
    
    app.run(host='0.0.0.0', port=args.port, debug=True, use_reloader=False)