import requests
from flask import Flask, request, jsonify
import time
import ecdsa
import json

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

def log(msg):
    """Helper function for standardized logging."""
    print(f"--- LOG ---> [Coordinator] {msg}")

def reset_session():
    current_session_data["k_shares"] = {}
    current_session_data["weighted_x_shares"] = {}

# DKG Orchestration
@app.route('/dkg/start', methods=['POST'])
def start_dkg_process():
    log("Received request to start DKG process.")
    
    # Step 1: Commitment Exchange
    log("DKG Step 1: Instructing parties to start commitment exchange...")
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Sending POST to {address}/dkg/round1/start")
        requests.post(f"{address}/dkg/round1/start", timeout=5)
    time.sleep(2)

    # Step 2: Share Exchange
    log("DKG Step 2: Instructing parties to start share exchange...")
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Sending POST to {address}/dkg/round2/start_share_exchange")
        requests.post(f"{address}/dkg/round2/start_share_exchange", timeout=5)
    time.sleep(2)

    # Step 3: Compute Final Keys
    log("DKG Step 3: Instructing parties to compute final keys...")
    for party_id, address in PARTY_ADDRESSES.items():
        log(f"Sending POST to {address}/dkg/round4/compute_keys")
        requests.post(f"{address}/dkg/round4/compute_keys", timeout=5)
    time.sleep(1)

    # Step 4: Verification
    log("DKG Step 4: Verifying DKG success by checking all public keys...")
    first_pk = None; agg_pk_hex = None
    for party_id, address in PARTY_ADDRESSES.items():
        response = requests.get(f"{address}/dkg/aggregated_public_key")
        response.raise_for_status()
        current_pk = response.json()
        log(f"Received public key from Party {party_id}: {current_pk}")
        if first_pk is None:
            first_pk = current_pk
            agg_pk_hex = first_pk.get('aggregated_public_key')
        elif first_pk != current_pk:
            log(f"!! DKG FAILED: Mismatch in public keys at party {party_id}.")
            return jsonify({"status": "error", "message": f"DKG failed! Key mismatch at party {party_id}."}), 500
    
    log("DKG Process Completed Successfully.")
    return jsonify({"status": "success", "message": "DKG OK", "aggregated_public_key": agg_pk_hex})

# Endpoint for Signers to submit their final shares
@app.route('/submit-shares', methods=['POST'])
def submit_shares():
    data = request.get_json()
    sender_id = data['sender_id']
    log(f"Received final shares from Party {sender_id}. Payload: {data}")
    current_session_data["k_shares"][sender_id] = data['k_share']
    current_session_data["weighted_x_shares"][sender_id] = data['weighted_x_share']
    return jsonify({"status": "success"})

# Signing Orchestration
@app.route('/request-signature', methods=['POST'])
def request_signature():
    reset_session()
    data = request.get_json()
    message_hash_hex = data['message_hash_hex']
    signing_party_ids = data['signing_party_ids']
    
    log(f"Received signature request for parties {signing_party_ids}")

    # Round 1: Collect Public Nonces (R_i)
    log("Signing Step 1: Collecting public nonces (R_i)...")
    all_R_shares = {}
    payload_r1 = {'message_hash_hex': message_hash_hex, 'signing_party_ids': signing_party_ids}
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/generate-nonce-share"
        log(f"Requesting nonce from Party {party_id} at {url}")
        response = requests.post(url, json=payload_r1, timeout=5)
        response.raise_for_status()
        r_share_data = response.json()['R_share']
        log(f"Received R_share from Party {party_id}: {r_share_data}")
        all_R_shares[str(party_id)] = r_share_data
    
    # Round 2: Distribute All Nonces and Aggregate R
    log("Signing Step 2: Distributing complete nonce list to all parties...")
    r_hex = None
    payload_r2 = {'all_R_shares': all_R_shares}
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/receive-and-aggregate-r"
        log(f"Sending full R_share list to Party {party_id} at {url}")
        response = requests.post(url, json=payload_r2, timeout=5)
        response.raise_for_status()
        if r_hex is None: r_hex = response.json().get('r_hex')
    log(f"All parties agreed on r = {r_hex}")

    # Round 3: Request Final Shares
    log("Signing Step 3: Instructing parties to send final shares to me...")
    payload_r3 = {'coordinator_url': COORDINATOR_URL}
    for party_id in signing_party_ids:
        url = f"{PARTY_ADDRESSES[party_id]}/sign/send-shares-to-coordinator"
        log(f"Requesting final shares from Party {party_id} at {url}")
        requests.post(url, json=payload_r3, timeout=5)
    time.sleep(1)

    # Round 4 & 5: Assemble and Verify
    log("Signing Step 4: Assembling final signature...")
    if len(current_session_data["k_shares"]) != len(signing_party_ids):
        return jsonify({"status": "error", "message": "Did not receive shares from all parties."}), 500
    
    k_agg = sum(current_session_data["k_shares"].values())
    x_recon = sum(current_session_data["weighted_x_shares"].values())
    log(f"Aggregated k_agg: {hex(k_agg)}")
    log(f"Reconstructed x_recon: {hex(x_recon)}")
    
    resp = requests.get(f"{PARTY_ADDRESSES[signing_party_ids[0]]}/info")
    info = resp.json(); N = int(info['curve_order'], 16); agg_pk_data = info['aggregated_public_key']
    agg_pk_point = deserialize_point(agg_pk_data)
    
    k_inv = pow(k_agg, N - 2, N); r_val = int(r_hex, 16); e = int(message_hash_hex, 16)
    s_val = (k_inv * (e + r_val * x_recon)) % N
    log(f"Calculated final s: {hex(s_val)}")

    log("Signing Step 5: Verifying final signature with standard library...")
    vk = ecdsa.VerifyingKey.from_public_point(agg_pk_point, curve=ecdsa.SECP256k1)
    sig_der = ecdsa.util.sigencode_string(r_val, s_val, N)
    is_valid = vk.verify_digest(sig_der, bytes.fromhex(message_hash_hex), sigdecode=ecdsa.util.sigdecode_string)

    if is_valid:
        log("Signature is VALID.")
        return jsonify({"status": "success", "signature": {"r": hex(r_val), "s": hex(s_val)}})
    else:
        log("!! Signature is INVALID.")
        return jsonify({"status": "error", "message": "Final signature failed verification."}), 500

def deserialize_point(data):
    if data.get("type")=="infinity": return ecdsa.ellipticcurve.INFINITY
    return ecdsa.ellipticcurve.Point(ecdsa.SECP256k1.curve, int(data['x'],16), int(data['y'],16))

if __name__ == '__main__':
    print(f"Starting Coordinator on {COORDINATOR_URL}")
    app.run(host='0.0.0.0', port=COORDINATOR_PORT)