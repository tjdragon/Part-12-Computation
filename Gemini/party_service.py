import secrets
import sys
from flask import Flask, request, jsonify
from ecdsa.ellipticcurve import INFINITY
from shared import CURVE, G, N, serialize_point, deserialize_point

# --- Signer Class Definition (State manager for each party) ---
class Signer:
    def __init__(self, party_id, num_parties, threshold):
        self.id = party_id
        self.num_parties = num_parties
        self.threshold = threshold
        # DKG state (private)
        self.poly_coeffs = None
        self.commitments = None
        self.received_shares = {}
        self.private_key_share = None # THE private key share x_i
        # Signing state (private)
        self.k_share = None # The private nonce k_i
        self.R_share = None # The public nonce R_i

    def dkg_round_1_create_poly_and_commitments(self):
        """Each party creates its own secret polynomial and commitment."""
        self.poly_coeffs = [secrets.randbelow(N) for _ in range(self.threshold)]
        self.commitments = [c * G for c in self.poly_coeffs]
        return self.commitments

    def dkg_round_2_get_share_for_party(self, party_j_id):
        """Calculates the share s_ij = f_i(j) for party j."""
        y = 0
        for coeff in reversed(self.poly_coeffs):
            y = (y * party_j_id + coeff) % N
        return y

    def dkg_round_3_verify_and_store_share(self, from_party_id, share, commitments_points):
        """Verify the received share s_ji against party j's commitment C_j."""
        lhs = share * G
        rhs = INFINITY
        for k in range(self.threshold):
            term = pow(self.id, k, N) * commitments_points[k]
            rhs += term

        if lhs != rhs:
            raise ValueError(f"Bad share received from Party {from_party_id}")
        self.received_shares[from_party_id] = share

    def dkg_round_4_compute_key_shares(self):
        """Compute final private key share x_i = sum(s_ji)."""
        # Add the party's own share f_i(i) to the received shares
        self_share = self.dkg_round_2_get_share_for_party(self.id)
        self.received_shares[self.id] = self_share
        # Sum all shares to get the final private key share
        self.private_key_share = sum(self.received_shares.values()) % N

    def sign_round_1_create_nonce_share(self):
        """Generate secret nonce k_i and public nonce share R_i."""
        self.k_share = secrets.randbelow(N)
        self.R_share = self.k_share * G
        return self.R_share

# --- Flask App Factory ---
def create_app(party_id, num_parties, threshold):
    app = Flask(__name__)
    signer = Signer(party_id, num_parties, threshold)

    @app.route('/state', methods=['GET'])
    def get_state():
        return jsonify({
            "id": signer.id,
            "private_key_share_set": signer.private_key_share is not None,
            "nonce_share_set": signer.k_share is not None
        })

    # --- DKG Endpoints ---
    @app.route('/dkg/1/commitments', methods=['POST'])
    def dkg1_commit():
        commitments = signer.dkg_round_1_create_poly_and_commitments()
        # Return public commitments, serialized for JSON
        return jsonify({"commitments": [serialize_point(c) for c in commitments]})

    @app.route('/dkg/2/share', methods=['POST'])
    def dkg2_get_share():
        data = request.get_json()
        receiver_id = data['receiver_id']
        share = signer.dkg_round_2_get_share_for_party(receiver_id)
        # Return a private share (payload)
        return jsonify({"share": share})

    @app.route('/dkg/3/verify', methods=['POST'])
    def dkg3_verify():
        data = request.get_json()
        from_party_id = data['from_party_id']
        share = data['share']
        # Deserialize commitments received in the payload
        commitments = [deserialize_point(p) for p in data['commitments']]
        try:
            signer.dkg_round_3_verify_and_store_share(from_party_id, share, commitments)
            return jsonify({"status": "success"})
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    @app.route('/dkg/4/compute', methods=['POST'])
    def dkg4_compute():
        signer.dkg_round_4_compute_key_shares()
        return jsonify({"status": "private key share computed"})

    # --- Signing Endpoints ---
    @app.route('/sign/1/nonce', methods=['POST'])
    def sign1_nonce():
        R_share = signer.sign_round_1_create_nonce_share()
        # Return public nonce share R_i
        return jsonify({"R_share": serialize_point(R_share)})

    @app.route('/sign/2/partial-sig', methods=['POST'])
    def sign2_partial_sig():
        data = request.get_json()
        signing_ids = data['signing_ids']
        m_int = data['m_int']
        r = data['r']
        
        # This party computes its own lagrange coefficient
        lagrange_coeff = compute_lagrange_coeff(signing_ids, signer.id)
        
        # Calculate this party's partial signature s_i
        s_i = (signer.k_share + lagrange_coeff * r * signer.private_key_share) % N

        # Return the partial signature component. The orchestrator will sum these up.
        return jsonify({"s_i": s_i})

    return app

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python party_service.py <PORT> <PARTY_ID> <THRESHOLD>")
        sys.exit(1)
        
    port = int(sys.argv[1])
    party_id = int(sys.argv[2])
    threshold = int(sys.argv[3])
    
    # In this simulation, we assume the party knows the total number of parties.
    # A more robust system might have a discovery service.
    N_PARTIES = 5 

    app = create_app(party_id, N_PARTIES, threshold)
    print(f"Starting Party {party_id} on port {port}...")
    app.run(host='0.0.0.0', port=port)