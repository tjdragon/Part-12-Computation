import subprocess
import time
import requests
import hashlib
from ecdsa.util import sigencode_string
from ecdsa import VerifyingKey, BadSignatureError
from ecdsa.ellipticcurve import INFINITY
from shared import CURVE, N, G, serialize_point, deserialize_point, compute_lagrange_coeff

# --- Simulation Parameters ---
N_PARTIES = 5
THRESHOLD = 3
BASE_PORT = 5000

def get_party_url(party_id):
    return f"http://127.0.0.1:{BASE_PORT + party_id}"

def run_command(cmd):
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def main():
    processes = []
    party_ids = list(range(1, N_PARTIES + 1))

    print("--- Starting Party Services ---")
    for i in party_ids:
        cmd = [
            "python", "party_service.py",
            str(BASE_PORT + i),
            str(i),
            str(THRESHOLD)
        ]
        proc = run_command(cmd)
        processes.append(proc)
        print(f"Started Party {i} on port {BASE_PORT + i} (PID: {proc.pid})")
    
    # Give the services a moment to start up
    time.sleep(2)
    print("\n--- All services started. Beginning protocol simulation. ---\n")

    try:
        # === Phase 1: Distributed Key Generation (DKG) ===
        print("--- Phase 1: Distributed Key Generation ---")
        all_commitments_ser = {} # Store serialized commitments

        # DKG Round 1: All parties create commitments
        print("DKG Round 1: Creating commitments...")
        for i in party_ids:
            res = requests.post(f"{get_party_url(i)}/dkg/1/commitments")
            res.raise_for_status()
            all_commitments_ser[i] = res.json()['commitments']
        print(" -> All parties created commitments.")

        # DKG Round 2 & 3: Exchange and verify shares
        print("\nDKG Round 2 & 3: Exchanging and verifying shares...")
        for sender_id in party_ids:
            for receiver_id in party_ids:
                if sender_id == receiver_id:
                    continue # Parties don't send shares to themselves
                
                # Round 2: Sender generates a share for the receiver
                payload = {"receiver_id": receiver_id}
                res = requests.post(f"{get_party_url(sender_id)}/dkg/2/share", json=payload)
                res.raise_for_status()
                share = res.json()['share']

                # Round 3: Receiver verifies and stores the share
                payload = {
                    "from_party_id": sender_id,
                    "share": share,
                    "commitments": all_commitments_ser[sender_id]
                }
                res = requests.post(f"{get_party_url(receiver_id)}/dkg/3/verify", json=payload)
                res.raise_for_status()
        print(" -> All shares exchanged and verified.")

        # DKG Round 4: All parties compute their final private key share
        print("\nDKG Round 4: Computing private key shares...")
        for i in party_ids:
            requests.post(f"{get_party_url(i)}/dkg/4/compute").raise_for_status()
        print(" -> All parties computed their private key shares (x_i).")

        # Orchestrator computes the aggregated public key
        agg_public_key_point = INFINITY
        for i in party_ids:
            # Add the first commitment C_i0 (which is x_i0 * G) from each party
            agg_public_key_point += deserialize_point(all_commitments_ser[i][0])
        
        agg_verifying_key = VerifyingKey.from_public_point(agg_public_key_point, curve=CURVE)
        print("\nDKG Complete!")
        print(f"Aggregated Public Key (Y):\n  x: {hex(agg_public_key_point.x())}\n  y: {hex(agg_public_key_point.y())}\n")

        # === Phase 2: Threshold Signing ===
        print("--- Phase 2: Threshold Signing ---")
        message = b"CGGMP21 REST API is a cool protocol"
        msg_hash = hashlib.sha256(message).digest()
        m_int = int.from_bytes(msg_hash, 'big')

        signing_party_ids = party_ids[:THRESHOLD] # Select the first 't+1' parties
        print(f"Message: '{message.decode()}'")
        print(f"Signing with parties: {signing_party_ids}\n")

        # Signing Round 1: Create nonce shares and aggregate R
        print("Signing Round 1: Aggregating nonces (R)...")
        R_agg = INFINITY
        for i in signing_party_ids:
            res = requests.post(f"{get_party_url(i)}/sign/1/nonce")
            res.raise_for_status()
            R_share = deserialize_point(res.json()['R_share'])
            R_agg += R_share
        
        r = R_agg.x() % N
        if r == 0:
            raise RuntimeError("r is zero, must restart signing round")
        print(f" -> Aggregated R computed. Signature 'r' value is: {hex(r)}")

        # Signing Round 2: Each party computes a partial signature s_i
        print("\nSigning Round 2: Computing and aggregating partial signatures (s_i)...")
        s_sum = 0
        for i in signing_party_ids:
            payload = {
                "signing_ids": signing_party_ids,
                "m_int": m_int,
                "r": r
            }
            res = requests.post(f"{get_party_url(i)}/sign/2/partial-sig", json=payload)
            res.raise_for_status()
            s_sum = (s_sum + res.json()['s_i']) % N

        # The orchestrator computes the final signature 's' from the sum of s_i's.
        # This is a slight modification to the CGGMP21 paper for simplicity, where s = sum(s_i).
        s = s_sum
        if s == 0:
            raise RuntimeError("s is zero, must restart signing round")

        final_signature_raw = sigencode_string(r, s, N)
        print(f" -> Final signature 's' value is: {hex(s)}\n")

        # === Phase 3: Verification ===
        print("--- Phase 3: Verification ---")
        is_valid = agg_verifying_key.verify_digest(final_signature_raw, msg_hash, sigdecode=sigdecode_string)
        print(f"Signature valid: {is_valid}")
        
        if is_valid:
            print("\n✅ SUCCESS: The threshold signature was verified correctly.")
        else:
            print("\n❌ FAILURE: The signature verification failed.")

    except requests.exceptions.RequestException as e:
        print(f"\nAn API error occurred: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
    finally:
        # === Shutdown ===
        print("\n--- Shutting down party services ---")
        for p in processes:
            p.terminate() # Send SIGTERM
            try:
                # Wait for the process to terminate
                p.wait(timeout=5)
                print(f"Process {p.pid} terminated.")
            except subprocess.TimeoutExpired:
                print(f"Process {p.pid} did not terminate, killing.")
                p.kill() # Force kill

if __name__ == '__main__':
    main()