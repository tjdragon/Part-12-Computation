import secrets
import ecdsa
from ecdsa.util import sigencode_string, sigdecode_string
from ecdsa.keys import BadSignatureError
from ecdsa.curves import SECP256k1
from flask import Flask, request, jsonify
import argparse
import requests
import json

# --- Helper function for standardized logging ---
def log(party_id, msg):
    print(f"--- LOG ---> [Signer {party_id}] {msg}")

# (Curve, Lagrange, Point Serialization functions are unchanged)
CURVE = SECP256k1; G = CURVE.generator; N = CURVE.order
def inv(n, prime=N): return pow(n, prime - 2, prime)
def compute_lagrange_coeff(party_ids, target_id):
    num=1; den=1
    for j in party_ids:
        if j != target_id: num=(num*j)%N; den=(den*(j-target_id))%N
    return (num * inv(den, N)) % N
def serialize_point(p):
    if p==ecdsa.ellipticcurve.INFINITY: return {"type": "infinity"}
    return {"x": hex(p.x()), "y": hex(p.y())}
def deserialize_point(data):
    if data.get("type")=="infinity": return ecdsa.ellipticcurve.INFINITY
    return ecdsa.ellipticcurve.Point(CURVE.curve, int(data['x'],16), int(data['y'],16))

class Signer:
    def __init__(self, party_id, num_parties, threshold, party_addresses=None, own_url=None):
        self.id=party_id; self.num_parties=num_parties; self.threshold=threshold
        self.url=own_url; self.party_addresses=party_addresses if party_addresses is not None else {}
        self.poly_coeffs, self.commitments, self.received_commitments, self.received_shares = None, None, {}, {}
        self.private_key_share, self.public_key_share, self.aggregated_public_key_point = None, None, None
        self.k_share, self.R_share, self.received_R_shares, self.aggregated_R_point = None, None, {}, None
        self.current_message_hash_hex, self.current_signing_party_ids, self.current_r = None, [], None

    def dkg_round_1_create_poly_and_commitments(self):
        log(self.id, "DKG R1: Creating secret polynomial and public commitments.")
        self.poly_coeffs=[secrets.randbelow(N) for _ in range(self.threshold)]
        self.commitments=[c*G for c in self.poly_coeffs]
        log(self.id, f"DKG R1: First coefficient (a_i0): {hex(self.poly_coeffs[0])}")
        return [serialize_point(p) for p in self.commitments]
    
    def dkg_round_2_get_share_for_party(self, j_id):
        y=0
        for c in reversed(self.poly_coeffs): y=(y*j_id+c)%N
        log(self.id, f"DKG R2: Computed share for party {j_id}: {hex(y)}")
        return y

    def dkg_round_3_verify_and_store_share(self, from_id, share, commitments):
        log(self.id, f"DKG R3: Verifying share from party {from_id}...")
        lhs=share*G; rhs=ecdsa.ellipticcurve.INFINITY
        for k_idx,c in enumerate(commitments): rhs+=pow(self.id,k_idx,N)*c
        if lhs!=rhs:
            log(self.id, f"!! DKG R3: Share verification FAILED for share from party {from_id}.")
            return False
        log(self.id, f"DKG R3: Share from party {from_id} is VALID. Storing.")
        self.received_shares[from_id]=share; return True

    def dkg_round_4_compute_key_shares(self):
        log(self.id, "DKG R4: Computing my private key share (x_i) from all received shares.")
        self.private_key_share=sum(self.received_shares.values())%N
        self.public_key_share=self.private_key_share*G
        log(self.id, f"DKG R4: Final private key share (x_{self.id}): {hex(self.private_key_share)}")
        return True

    def get_aggregated_public_key(self):
        log(self.id, "DKG R4: Computing aggregated public key (Y).")
        agg_pk=ecdsa.ellipticcurve.INFINITY
        for pid in sorted(self.received_commitments.keys()): agg_pk+=self.received_commitments[pid][0]
        self.aggregated_public_key_point = agg_pk
        log(self.id, f"DKG R4: Aggregated public key (Y): {serialize_point(self.aggregated_public_key_point)}")
        return self.aggregated_public_key_point
    
    def sign_round_1_create_nonce_share(self):
        log(self.id, "SIGN R1: Creating secret nonce (k_i) and public nonce (R_i).")
        self.k_share=secrets.randbelow(N); self.R_share=self.k_share*G
        log(self.id, f"SIGN R1: My secret k_{self.id} is {hex(self.k_share)}")
        return serialize_point(self.R_share)

    def compute_final_shares(self):
        log(self.id, "SIGN R2: Computing final secret shares for Coordinator.")
        lambda_i=compute_lagrange_coeff(self.current_signing_party_ids,self.id)
        weighted_x_share=(lambda_i*self.private_key_share)%N
        log(self.id, f"SIGN R2: My Lagrange coefficient (lambda_{self.id}) is {hex(lambda_i)}")
        log(self.id, f"SIGN R2: My secret nonce share (k_{self.id}) is {hex(self.k_share)}")
        log(self.id, f"SIGN R2: My weighted private key share (lambda_{self.id}*x_{self.id}) is {hex(weighted_x_share)}")
        return self.k_share, weighted_x_share

app = Flask(__name__)

# Info Endpoint
@app.route('/info', methods=['GET'])
def get_info():
    return jsonify({"status":"success", "curve_order":hex(N), "aggregated_public_key":serialize_point(signer_node.aggregated_public_key_point)})

# DKG Endpoints
@app.route('/dkg/commitments', methods=['POST'])
def handle_dkg_commitments():
    data = request.get_json()
    log(signer_node.id, f"DKG R1: Received commitments from Party {data['sender_id']}.")
    signer_node.received_commitments[data['sender_id']]=[deserialize_point(p) for p in data['commitments']]
    return jsonify({"status":"success"})

@app.route('/dkg/round1/start', methods=['POST'])
def dkg_round1_start():
    log(signer_node.id, "DKG R1: Received start command from Coordinator.")
    c_ser=signer_node.dkg_round_1_create_poly_and_commitments()
    signer_node.received_commitments[signer_node.id]=signer_node.commitments
    payload={'sender_id':signer_node.id, 'commitments':c_ser}
    for pid,addr in signer_node.party_addresses.items():
        if pid != signer_node.id:
            log(signer_node.id, f"DKG R1: Broadcasting my commitments to Party {pid} at {addr}.")
            requests.post(f"{addr}/dkg/commitments", json=payload)
    return jsonify({"status":"success"})

@app.route('/dkg/share', methods=['POST'])
def handle_dkg_share():
    data = request.get_json()
    log(signer_node.id, f"DKG R2: Received share from Party {data['sender_id']}. Payload: {data}")
    if not signer_node.dkg_round_3_verify_and_store_share(data['sender_id'], data['share_value'], signer_node.received_commitments[data['sender_id']]):
        return jsonify({"status":"error"}), 400
    return jsonify({"status":"success"})

@app.route('/dkg/round2/start_share_exchange', methods=['POST'])
def dkg_round2_start_share_exchange():
    log(signer_node.id, "DKG R2: Received start command from Coordinator.")
    for pid in signer_node.party_addresses:
        share=signer_node.dkg_round_2_get_share_for_party(pid)
        if pid==signer_node.id:
            signer_node.dkg_round_3_verify_and_store_share(pid,share,signer_node.commitments)
        else:
            log(signer_node.id, f"DKG R2: Sending my share for Party {pid} to them.")
            requests.post(f"{signer_node.party_addresses[pid]}/dkg/share", json={'sender_id':signer_node.id, 'share_value':share})
    return jsonify({"status":"success"})

@app.route('/dkg/round4/compute_keys', methods=['POST'])
def dkg_round4_compute_keys():
    log(signer_node.id, "DKG R4: Received start command from Coordinator.")
    signer_node.dkg_round_4_compute_key_shares(); pk=signer_node.get_aggregated_public_key()
    return jsonify({"status":"success", "aggregated_public_key":serialize_point(pk)})

@app.route('/dkg/aggregated_public_key', methods=['GET'])
def get_agg_pk_endpoint():
    if signer_node.aggregated_public_key_point is None: return jsonify({"status":"error"}),404
    return jsonify({"status":"success", "aggregated_public_key":serialize_point(signer_node.aggregated_public_key_point)})

# Signing Endpoints
@app.route('/sign/generate-nonce-share', methods=['POST'])
def generate_nonce_share():
    data = request.get_json()
    log(signer_node.id, f"SIGN R1: Received request from Coordinator. Payload: {data}")
    signer_node.current_message_hash_hex = data['message_hash_hex']
    signer_node.current_signing_party_ids = data['signing_party_ids']
    signer_node.received_R_shares = {}
    r_share_ser = signer_node.sign_round_1_create_nonce_share()
    log(signer_node.id, f"SIGN R1: Sending my public nonce (R_{signer_node.id}) back to Coordinator.")
    return jsonify({"status": "success", "R_share": r_share_ser})

@app.route('/sign/receive-and-aggregate-r', methods=['POST'])
def receive_and_aggregate_r():
    data = request.get_json()
    log(signer_node.id, f"SIGN R2: Received complete list of R_shares from Coordinator. Payload: {json.dumps(data, indent=2)}")
    all_R_shares_ser = data['all_R_shares']
    for party_id_str, R_share_ser in all_R_shares_ser.items():
        signer_node.received_R_shares[int(party_id_str)] = deserialize_point(R_share_ser)
    R_agg = ecdsa.ellipticcurve.INFINITY
    for R_share in signer_node.received_R_shares.values():
        R_agg += R_share
    signer_node.aggregated_R_point = R_agg
    signer_node.current_r = R_agg.x() % N
    log(signer_node.id, f"SIGN R2: Aggregated all R_shares. Final r value: {hex(signer_node.current_r)}")
    return jsonify({"status": "success", "r_hex": hex(signer_node.current_r)})

@app.route('/sign/send-shares-to-coordinator', methods=['POST'])
def send_shares_to_coordinator():
    data = request.get_json()
    log(signer_node.id, f"SIGN R3: Received request to send final shares. Payload: {data}")
    coordinator_url = data['coordinator_url']
    k_i, weighted_x_i = signer_node.compute_final_shares()
    payload = {'sender_id': signer_node.id, 'k_share': k_i, 'weighted_x_share': weighted_x_i}
    log(signer_node.id, f"SIGN R3: Sending my final shares to Coordinator at {coordinator_url}. Payload: {payload}")
    requests.post(f"{coordinator_url}/submit-shares", json=payload, timeout=5)
    return jsonify({"status": "success"})

# Main Execution
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Threshold ECDSA Signer Node")
    parser.add_argument('--party_id', type=int, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--num_parties', type=int, required=True)
    parser.add_argument('--threshold', type=int, required=True)
    parser.add_argument('--party_addresses', type=str, required=True, nargs='+')
    args = parser.parse_args()
    parsed_party_addresses = {}
    for addr_str in args.party_addresses:
        p_id_str, p_host, p_port_str = addr_str.split(':')
        parsed_party_addresses[int(p_id_str)] = f"http://{p_host}:{p_port_str}"
    signer_node = Signer(party_id=args.party_id, num_parties=args.num_parties, threshold=args.threshold,
                         party_addresses=parsed_party_addresses, own_url=f"http://localhost:{args.port}")
    print(f"Starting Signer Node: ID={signer_node.id}, URL={signer_node.url}")
    app.run(host='0.0.0.0', port=args.port, debug=True, use_reloader=False)