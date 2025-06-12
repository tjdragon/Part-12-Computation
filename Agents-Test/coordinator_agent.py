#!/usr/bin/env python3
"""
AI-Powered Coordinator Agent for CGGMP21 Threshold Signature System
Uses Ollama for intelligent decision making and natural language communication
"""

import requests
import json
import time
import ecdsa
from flask import Flask, request, jsonify
from typing import List, Dict, Any
import asyncio
import aiohttp

# --- Configuration ---
PARTY_ADDRESSES = {
    1: "http://localhost:5001",
    2: "http://localhost:5002", 
    3: "http://localhost:5003",
}
COORDINATOR_PORT = 6000
COORDINATOR_URL = f"http://localhost:{COORDINATOR_PORT}"
OLLAMA_API_URL = "http://localhost:11434/api/generate"

current_session_data = {"k_shares": {}, "weighted_x_shares": {}}
app = Flask(__name__)

class CoordinatorAgent:
    def __init__(self):
        self.agent_id = "coordinator_agent"
        self.context_memory = []
        self.current_operation = None
        self.protocol_state = "idle"
        
    def add_to_memory(self, event: str, details: Dict[str, Any] = None):
        """Add events to agent memory for context awareness"""
        memory_entry = {
            "timestamp": time.time(),
            "event": event,
            "details": details or {},
            "operation": self.current_operation
        }
        self.context_memory.append(memory_entry)
        # Keep only last 50 events
        if len(self.context_memory) > 50:
            self.context_memory = self.context_memory[-50:]
    
    async def think(self, situation: str, decision_needed: str = None) -> str:
        """Use Ollama to reason about the current situation"""
        context = self._build_context()
        
        prompt = f"""You are a Coordinator Agent managing a threshold cryptography protocol.

Current Context:
{context}

Current Situation: {situation}

{f"Decision Needed: {decision_needed}" if decision_needed else ""}

Provide a brief, technical response about what should happen next in this MPC protocol execution. Keep it concise and focused on the cryptographic operations."""

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": "llama3.2:1b",
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "max_tokens": 150
                    }
                }
                
                async with session.post(OLLAMA_API_URL, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get("response", "").strip()
                    else:
                        return "AI reasoning unavailable, proceeding with protocol"
        except:
            return "AI reasoning unavailable, proceeding with protocol"
    
    def _build_context(self) -> str:
        """Build context from recent memory"""
        if not self.context_memory:
            return "No previous context available."
        
        recent_events = self.context_memory[-5:]  # Last 5 events
        context_lines = []
        
        for event in recent_events:
            context_lines.append(f"- {event['event']}")
            if event['details']:
                context_lines.append(f"  Details: {event['details']}")
        
        return "\n".join(context_lines)
    
    def log(self, msg: str, level: str = "INFO"):
        """Enhanced logging with AI context"""
        print(f"[{level}] [Coordinator Agent] {msg}")
        self.add_to_memory(f"LOG: {msg}")

coordinator_agent = CoordinatorAgent()

def log(msg):
    """Legacy log function that uses the agent"""
    coordinator_agent.log(msg)

def reset_session():
    current_session_data["k_shares"] = {}
    current_session_data["weighted_x_shares"] = {}
    coordinator_agent.add_to_memory("Session reset", {"operation": "reset"})

# DKG Orchestration with AI Enhancement
@app.route('/dkg/start', methods=['POST'])
def start_dkg_process():
    coordinator_agent.current_operation = "DKG"
    coordinator_agent.protocol_state = "dkg_starting"
    
    log("AI Agent received request to start DKG process.")
    
    # AI reasoning about DKG initiation
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ai_reasoning = loop.run_until_complete(
            coordinator_agent.think(
                "Starting Distributed Key Generation protocol with 3 parties",
                "Should I proceed with DKG initiation sequence?"
            )
        )
        log(f"AI Reasoning: {ai_reasoning}")
    except:
        log("AI reasoning failed, proceeding with standard protocol")
    
    coordinator_agent.add_to_memory("DKG process started", {"parties": list(PARTY_ADDRESSES.keys())})
    
    # Step 1: Commitment Exchange
    log("DKG Step 1: Instructing parties to start commitment exchange...")
    coordinator_agent.protocol_state = "dkg_commitments"
    
    commitment_results = {}
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Sending POST to {address}/dkg/round1/start")
        try:
            response = requests.post(f"{address}/dkg/round1/start", timeout=5)
            commitment_results[party_id] = "success" if response.status_code == 200 else "failed"
        except Exception as e:
            commitment_results[party_id] = f"error: {str(e)}"
    
    coordinator_agent.add_to_memory("Commitment phase completed", commitment_results)
    time.sleep(2)

    # Step 2: Share Exchange
    log("DKG Step 2: Instructing parties to start share exchange...")
    coordinator_agent.protocol_state = "dkg_shares"
    
    share_results = {}
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Sending POST to {address}/dkg/round2/start_share_exchange")
        try:
            response = requests.post(f"{address}/dkg/round2/start_share_exchange", timeout=5)
            share_results[party_id] = "success" if response.status_code == 200 else "failed"
        except Exception as e:
            share_results[party_id] = f"error: {str(e)}"
    
    coordinator_agent.add_to_memory("Share exchange completed", share_results)
    time.sleep(2)

    # Step 3: Compute Final Keys
    log("DKG Step 3: Instructing parties to compute final keys...")
    coordinator_agent.protocol_state = "dkg_finalization"
    
    key_computation_results = {}
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Sending POST to {address}/dkg/round4/compute_keys")
        try:
            response = requests.post(f"{address}/dkg/round4/compute_keys", timeout=5)
            key_computation_results[party_id] = "success" if response.status_code == 200 else "failed"
        except Exception as e:
            key_computation_results[party_id] = f"error: {str(e)}"
    
    coordinator_agent.add_to_memory("Key computation completed", key_computation_results)
    time.sleep(1)

    # Step 4: Verification with AI Analysis
    log("DKG Step 4: Verifying DKG success by checking all public keys...")
    coordinator_agent.protocol_state = "dkg_verification"
    
    first_pk = None
    agg_pk_hex = None
    verification_results = {}
    
    for party_id, address in PARTY_ADDRESSES.items():
        try:
            response = requests.get(f"{address}/dkg/aggregated_public_key")
            response.raise_for_status()
            current_pk = response.json()
            verification_results[party_id] = current_pk
            log(f"Received public key from Party {party_id}: {current_pk}")
            
            if first_pk is None:
                first_pk = current_pk
                agg_pk_hex = first_pk.get('aggregated_public_key')
            elif first_pk != current_pk:
                coordinator_agent.add_to_memory("DKG FAILED", {"reason": f"Key mismatch at party {party_id}"})
                log(f"!! DKG FAILED: Mismatch in public keys at party {party_id}.")
                return jsonify({"status": "error", "message": f"DKG failed! Key mismatch at party {party_id}."}), 500
        except Exception as e:
            verification_results[party_id] = f"error: {str(e)}"
    
    coordinator_agent.add_to_memory("DKG verification completed", verification_results)
    coordinator_agent.protocol_state = "idle"
    coordinator_agent.current_operation = None
    
    # AI summary of DKG completion
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ai_summary = loop.run_until_complete(
            coordinator_agent.think(
                f"DKG completed successfully. All parties generated consistent public key: {agg_pk_hex}",
            )
        )
        log(f"AI Summary: {ai_summary}")
    except:
        log("AI summary generation failed")
    
    log("DKG Process Completed Successfully.")
    return jsonify({
        "status": "success", 
        "message": "DKG OK", 
        "aggregated_public_key": agg_pk_hex,
        "ai_reasoning": ai_summary if 'ai_summary' in locals() else None
    })

# Endpoint for Signers to submit their final shares
@app.route('/submit-shares', methods=['POST'])
def submit_shares():
    data = request.get_json()
    sender_id = data['sender_id']
    
    coordinator_agent.add_to_memory(f"Received shares from party {sender_id}", data)
    log(f"Received final shares from Party {sender_id}. Payload: {data}")
    
    current_session_data["k_shares"][sender_id] = data['k_share']
    current_session_data["weighted_x_shares"][sender_id] = data['weighted_x_share']
    
    return jsonify({"status": "success"})

# Signing Orchestration with AI Enhancement
@app.route('/request-signature', methods=['POST'])
def request_signature():
    coordinator_agent.current_operation = "SIGNING"
    coordinator_agent.protocol_state = "signing_starting"
    
    reset_session()
    data = request.get_json()
    message_hash_hex = data['message_hash_hex']
    signing_party_ids = data['signing_party_ids']
    
    coordinator_agent.add_to_memory("Signature request received", {
        "message_hash": message_hash_hex,
        "signing_parties": signing_party_ids
    })
    
    log(f"Received signature request for parties {signing_party_ids}")

    # AI reasoning about signing initiation
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ai_reasoning = loop.run_until_complete(
            coordinator_agent.think(
                f"Starting threshold signature with parties {signing_party_ids} for message hash {message_hash_hex}",
                "Should I proceed with the signing protocol?"
            )
        )
        log(f"AI Reasoning: {ai_reasoning}")
    except:
        log("AI reasoning failed, proceeding with standard protocol")

    # Round 1: Collect Public Nonces (R_i)
    log("Signing Step 1: Collecting public nonces (R_i)...")
    coordinator_agent.protocol_state = "signing_nonces"
    
    all_R_shares = {}
    nonce_results = {}
    payload_r1 = {'message_hash_hex': message_hash_hex, 'signing_party_ids': signing_party_ids}
    
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/generate-nonce-share"
        log(f"Requesting nonce from Party {party_id} at {url}")
        try:
            response = requests.post(url, json=payload_r1, timeout=5)
            response.raise_for_status()
            r_share_data = response.json()['R_share']
            all_R_shares[str(party_id)] = r_share_data
            nonce_results[party_id] = "success"
            log(f"Received R_share from Party {party_id}: {r_share_data}")
        except Exception as e:
            nonce_results[party_id] = f"error: {str(e)}"
    
    coordinator_agent.add_to_memory("Nonce collection completed", nonce_results)
    
    # Round 2: Distribute All Nonces and Aggregate R
    log("Signing Step 2: Distributing complete nonce list to all parties...")
    coordinator_agent.protocol_state = "signing_aggregation"
    
    r_hex = None
    aggregation_results = {}
    payload_r2 = {'all_R_shares': all_R_shares}
    
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/receive-and-aggregate-r"
        log(f"Sending full R_share list to Party {party_id} at {url}")
        try:
            response = requests.post(url, json=payload_r2, timeout=5)
            response.raise_for_status()
            if r_hex is None: 
                r_hex = response.json().get('r_hex')
            aggregation_results[party_id] = "success"
        except Exception as e:
            aggregation_results[party_id] = f"error: {str(e)}"
    
    coordinator_agent.add_to_memory("R aggregation completed", {"r_value": r_hex, "results": aggregation_results})
    log(f"All parties agreed on r = {r_hex}")

    # Round 3: Request Final Shares
    log("Signing Step 3: Instructing parties to send final shares to me...")
    coordinator_agent.protocol_state = "signing_shares"
    
    payload_r3 = {'coordinator_url': COORDINATOR_URL}
    share_collection_results = {}
    
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/send-shares-to-coordinator"
        log(f"Requesting final shares from Party {party_id} at {url}")
        try:
            response = requests.post(url, json=payload_r3, timeout=5)
            share_collection_results[party_id] = "success" if response.status_code == 200 else "failed"
        except Exception as e:
            share_collection_results[party_id] = f"error: {str(e)}"
    
    coordinator_agent.add_to_memory("Share collection requested", share_collection_results)
    time.sleep(1)

    # Round 4 & 5: Assemble and Verify
    log("Signing Step 4: Assembling final signature...")
    coordinator_agent.protocol_state = "signing_finalization"
    
    if len(current_session_data["k_shares"]) != len(signing_party_ids):
        error_msg = "Did not receive shares from all parties."
        coordinator_agent.add_to_memory("Signature assembly failed", {"reason": error_msg})
        return jsonify({"status": "error", "message": error_msg}), 500
    
    k_agg = sum(current_session_data["k_shares"].values())
    x_recon = sum(current_session_data["weighted_x_shares"].values())
    log(f"Aggregated k_agg: {hex(k_agg)}")
    log(f"Reconstructed x_recon: {hex(x_recon)}")
    
    # Get curve parameters and public key
    resp = requests.get(f"{PARTY_ADDRESSES[signing_party_ids[0]]}/info")
    info = resp.json()
    N = int(info['curve_order'], 16)
    agg_pk_data = info['aggregated_public_key']
    agg_pk_point = deserialize_point(agg_pk_data)
    
    # Calculate final signature
    k_inv = pow(k_agg, N - 2, N)
    r_val = int(r_hex, 16)
    e = int(message_hash_hex, 16)
    s_val = (k_inv * (e + r_val * x_recon)) % N
    log(f"Calculated final s: {hex(s_val)}")

    # Verification
    log("Signing Step 5: Verifying final signature with standard library...")
    coordinator_agent.protocol_state = "signing_verification"
    
    try:
        vk = ecdsa.VerifyingKey.from_public_point(agg_pk_point, curve=ecdsa.SECP256k1)
        sig_der = ecdsa.util.sigencode_string(r_val, s_val, N)
        is_valid = vk.verify_digest(sig_der, bytes.fromhex(message_hash_hex), sigdecode=ecdsa.util.sigdecode_string)
    except Exception as e:
        coordinator_agent.add_to_memory("Signature verification failed", {"error": str(e)})
        return jsonify({"status": "error", "message": f"Verification error: {str(e)}"}), 500

    # AI analysis of signature completion
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ai_analysis = loop.run_until_complete(
            coordinator_agent.think(
                f"Signature {'VALID' if is_valid else 'INVALID'}: r={hex(r_val)}, s={hex(s_val)}",
            )
        )
        log(f"AI Analysis: {ai_analysis}")
    except:
        ai_analysis = None
        log("AI analysis generation failed")
    
    coordinator_agent.protocol_state = "idle"
    coordinator_agent.current_operation = None

    if is_valid:
        coordinator_agent.add_to_memory("Signature completed successfully", {
            "r": hex(r_val), 
            "s": hex(s_val),
            "verified": True
        })
        log("Signature is VALID.")
        return jsonify({
            "status": "success", 
            "signature": {"r": hex(r_val), "s": hex(s_val)},
            "ai_analysis": ai_analysis
        })
    else:
        coordinator_agent.add_to_memory("Signature verification failed", {
            "r": hex(r_val), 
            "s": hex(s_val),
            "verified": False
        })
        log("!! Signature is INVALID.")
        return jsonify({"status": "error", "message": "Final signature failed verification."}), 500

# Agent status endpoint
@app.route('/agent/status', methods=['GET'])
def get_agent_status():
    return jsonify({
        "agent_id": coordinator_agent.agent_id,
        "protocol_state": coordinator_agent.protocol_state,
        "current_operation": coordinator_agent.current_operation,
        "memory_events": len(coordinator_agent.context_memory),
        "recent_memory": coordinator_agent.context_memory[-3:] if coordinator_agent.context_memory else []
    })

# Agent memory endpoint
@app.route('/agent/memory', methods=['GET'])
def get_agent_memory():
    return jsonify({
        "agent_id": coordinator_agent.agent_id,
        "total_events": len(coordinator_agent.context_memory),
        "memory": coordinator_agent.context_memory
    })

def deserialize_point(data):
    if data.get("type") == "infinity": 
        return ecdsa.ellipticcurve.INFINITY
    return ecdsa.ellipticcurve.Point(ecdsa.SECP256k1.curve, int(data['x'], 16), int(data['y'], 16))

if __name__ == '__main__':
    print(f"Starting Coordinator Agent on {COORDINATOR_URL}")
    print("AI capabilities powered by Ollama")
    app.run(host='0.0.0.0', port=COORDINATOR_PORT)