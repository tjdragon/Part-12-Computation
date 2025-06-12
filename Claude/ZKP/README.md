# Basic Threshold Signature System with Zero-Knowledge Proofs

This is a **Python implementation** of the CGGMP21 threshold signature system enhanced with Zero-Knowledge Proofs. Straightforward Python code with comprehensive ZKP capabilities and detailed logging.

## 🔐 Zero-Knowledge Proof Features

### **What ZKPs Prove (Without Revealing Secrets)**
1. **Commitment Proofs**: Polynomial commitments are correctly formed
2. **Key Share Proofs**: Knowledge of private key shares  
3. **Nonce Proofs**: Signing nonces are properly generated

### **What Remains Secret (Until Logged)**
- Polynomial coefficients (visible in logs for POC)
- Private key shares (logged clearly for debugging)
- Signing nonces (fully exposed in logs)

## 🚀 Quick Start

### Prerequisites

**Only Python packages needed:**
```bash
pip install flask requests ecdsa
```

### Files Required

1. `zkp_module.py` - ZKP implementation
2. `coordinator_zkp.py` - coordinator with ZKP
3. `signer_zkp.py` - signer with ZKP

### Launch the System

#### Terminal 1: Signer 1
```bash
python signer_zkp.py \
    --party_id 1 \
    --port 5001 \
    --num_parties 3 \
    --threshold 2 \
    --party_addresses "1:localhost:5001" "2:localhost:5002" "3:localhost:5003"
```

#### Terminal 2: Signer 2
```bash
python signer_zkp.py \
    --party_id 2 \
    --port 5002 \
    --num_parties 3 \
    --threshold 2 \
    --party_addresses "1:localhost:5001" "2:localhost:5002" "3:localhost:5003"
```

#### Terminal 3: Signer 3
```bash
python signer_zkp.py \
    --party_id 3 \
    --port 5003 \
    --num_parties 3 \
    --threshold 2 \
    --party_addresses "1:localhost:5001" "2:localhost:5002" "3:localhost:5003"
```

#### Terminal 4: Coordinator
```bash
python coordinator_zkp.py
```

## 🧪 Testing with ZKP Verification

### Phase 1: DKG with Zero-Knowledge Proofs

```bash
curl -X POST http://localhost:6000/dkg/start
```

**Output:**
```json
{
  "status": "success",
  "message": "DKG with ZKP verification completed",
  "aggregated_public_key": {
    "x": "0x...",
    "y": "0x..."
  },
  "zkp_security_report": {
    "total_verifications": 6,
    "success_rate": 1.0,
    "proof_types": ["commitment_proof", "key_share_proof"],
    "failed_count": 0,
    "avg_verification_time_ms": 15.2
  },
  "zkp_party_status": {
    "1": {"key_share_proven": true, "commitment_proven": true, "nonce_proven": false},
    "2": {"key_share_proven": true, "commitment_proven": true, "nonce_proven": false},
    "3": {"key_share_proven": true, "commitment_proven": true, "nonce_proven": false}
  }
}
```

### Phase 2: Signing with ZKP Verification

```bash
# Calculate message hash
echo -n "basic zkp test message" | sha256sum | awk '{print $1}'
# Output: e1f2a3b4c5d6...

# Request signature
curl -X POST -H "Content-Type: application/json" \
     -d '{
         "message_hash_hex": "a44b004e1739aaa257f841768199c1711cb051ae5a2dbd62adc2ead99bf6268f",
         "signing_party_ids": [1, 3]
     }' \
     http://localhost:6000/request-signature
```

**Enhanced Output:**
```json
{
  "status": "success",
  "signature": {
    "r": "0x...",
    "s": "0x..."
  },
  "zkp_security_report": {
    "total_verifications": 8,
    "success_rate": 1.0,
    "proof_types": ["commitment_proof", "key_share_proof", "nonce_proof"],
    "failed_count": 0
  },
  "zkp_party_status": {
    "1": {"key_share_proven": true, "commitment_proven": true, "nonce_proven": true},
    "3": {"key_share_proven": true, "commitment_proven": true, "nonce_proven": true}
  }
}
```

## 📊 Clear Logging Examples

### Coordinator Logs (All Sensitive Data Visible)
```
[INFO] [Coordinator ZKP] Coordinator with ZKP received request to start DKG process.
[INFO] [Coordinator ZKP] Commitment response from Party 1: {
  "status": "success",
  "zkp_commitment_proof": {
    "type": "commitment_proof",
    "prover_id": 1,
    "challenge": "0x7a2b1c9d8e3f4a5b6c7d8e9f0a1b2c3d",
    "responses": ["0x1a2b3c4d5e6f7a8b", "0x9c0d1e2f3a4b5c6d"],
    "commitments": [{"x": "0x...", "y": "0x..."}]
  }
}
[INFO] [Coordinator ZKP] ZKP VERIFICATION - Party 1 commitment: VALID
[INFO] [Coordinator ZKP] CLEAR DATA - Aggregated k_agg: 0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
[INFO] [Coordinator ZKP] CLEAR DATA - All k_shares: ["0x1a2b3c4d", "0x5e6f7a8b"]
```

### Signer Logs
```
[INFO] [Signer ZKP 1] DKG R1: Generated polynomial coefficients: ["0x1a2b3c4d5e6f7a8b", "0x9c0d1e2f3a4b5c6d"]
[INFO] [Signer ZKP 1] DKG R4: Final private key share computed: 0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
[INFO] [Signer ZKP 1] SIGN R1: Generated nonce k_1: 0x9f8e7d6c5b4a3928
[INFO] [Signer ZKP 1] ZKP GENERATION - commitment: SUCCESS
[INFO] [Signer ZKP 1] ZKP PROOF DATA: {
  "type": "commitment_proof",
  "prover_id": 1,
  "R_points": [{"x": "0x...", "y": "0x..."}],
  "responses": ["0x1a2b3c4d"],
  "challenge": "0x7a2b1c9d"
}
```

## 🔍 Monitoring and Debugging

### Check Coordinator Status
```bash
curl http://localhost:6000/status
```

**Response:**
```json
{
  "coordinator_id": "coordinator_zkp",
  "protocol_state": "idle",
  "current_operation": null,
  "memory_events": 25,
  "zkp_security_report": {
    "total_verifications": 6,
    "success_rate": 1.0,
    "failed_count": 0
  },
  "party_zkp_status": {
    "1": {"key_share_proven": true, "commitment_proven": true, "nonce_proven": false}
  }
}
```

### View Complete ZKP Audit Trail
```bash
curl http://localhost:6000/zkp-audit
```

### Check Individual Signer Status
```bash
curl http://localhost:5001/status
```

**Response (All Secrets Visible):**
```json
{
  "signer_id": "signer_zkp_1",
  "party_id": 1,
  "protocol_state": "idle",
  "has_private_key_share": true,
  "private_key_share": "0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
  "zkp_stats": {
    "proofs_generated": 3,
    "commitment_proofs": 1,
    "key_share_proofs": 1,
    "nonce_proofs": 1
  }
}
```

### View Complete Signer Memory (Unfiltered)
```bash
curl http://localhost:5001/memory
```

**Response (All Sensitive Data Exposed):**
```json
{
  "memory": [
    {
      "event": "Polynomial and commitments generated",
      "details": {
        "polynomial_coefficients": ["0x1a2b3c4d", "0x5e6f7a8b"],
        "commitments": [{"x": "0x...", "y": "0x..."}],
        "zkp_proof": {"challenge": "0x7a2b1c9d", "responses": ["0x..."]}
      }
    },
    {
      "event": "Final signature shares computed",
      "details": {
        "private_key_share": "0x7a8b9c0d1e2f3a4b",
        "k_share": "0x9f8e7d6c5b4a3928",
        "weighted_x_share": "0x2c3d4e5f6a7b8c9d"
      }
    }
  ]
}
```

### View ZKP Proof History
```bash
curl http://localhost:5001/zkp-proofs
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Basic Coordinator                            │
│              (coordinator_zkp.py)                           │
│   • Python MPC orchestration                                │
│   • ZKP verification and audit trail                        │
│   • Clear logging with all sensitive data                   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ REST API Communication
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              Basic Signers                                  │
│             (signer_zkp.py x3)                              │
│   • Python MPC parties                                      │
│   • ZKP generation for all protocol steps                   │
│   • Complete transparency in logging                        │
│   • No AI dependencies                                      │
└─────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                ZKP Module                                   │
│              (zkp_module.py)                                │
│   • Schnorr proof implementations                           │
│   • Commitment, key share, and nonce proofs                 │
│   • Fiat-Shamir heuristic for non-interactivity             │
└─────────────────────────────────────────────────────────────┘
```

### What ZKPs Prove

1. **Commitment Correctness**: Each party's polynomial commitments are valid
2. **Key Share Knowledge**: Each party knows their private key share
3. **Nonce Correctness**: Each signing nonce corresponds to its public point
4. **Protocol Compliance**: All parties follow the protocol correctly

### What ZKPs Don't Reveal

1. **Polynomial Coefficients**: Secret values remain hidden
2. **Private Key Shares**: Individual shares never exposed
3. **Nonce Values**: Signing nonces remain secret
4. **Final Private Key**: Never reconstructed or revealed

### ZKP Protocol Flow

```
DKG Phase:
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Party 1   │    │   Party 2   │    │   Party 3   │
│             │    │             │    │             │
│ Generate    │    │ Generate    │    │ Generate    │
│ Polynomial  │    │ Polynomial  │    │ Polynomial  │
│     ↓       │    │     ↓       │    │     ↓       │
│ Create ZKP  │    │ Create ZKP  │    │ Create ZKP  │
│ Commitment  │    │ Commitment  │    │ Commitment  │
│     ↓       │    │     ↓       │    │     ↓       │
│ Broadcast   │    │ Broadcast   │    │ Broadcast   │
│ Commitment  │    │ Commitment  │    │ Commitment  │
│ + ZKP       │    │ + ZKP       │    │ + ZKP       │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                  ┌─────────────┐
                  │ Coordinator │
                  │   Verifies  │
                  │ All ZKPs    │
                  └─────────────┘

Signing Phase:
┌─────────────┐    ┌─────────────┐
│   Party 1   │    │   Party 3   │
│             │    │             │
│ Generate    │    │ Generate    │
│ Nonce k_1   │    │ Nonce k_3   │
│     ↓       │    │     ↓       │
│ Compute     │    │ Compute     │
│ R_1 = k_1*G │    │ R_3 = k_3*G │
│     ↓       │    │     ↓       │
│ Create ZKP  │    │ Create ZKP  │
│ Nonce Proof │    │ Nonce Proof │
│     ↓       │    │     ↓       │
│ Send R_1    │    │ Send R_3    │
│ + ZKP       │    │ + ZKP       │
└─────────────┘    └─────────────┘
       │                   │
       └───────────────────┘
                  │
         ┌─────────────┐
         │ Coordinator │
         │  Verifies   │
         │ Nonce ZKPs  │
         │ Aggregates  │
         │ Signature   │
         └─────────────┘
```


## 🔧 API Endpoints Summary

### Coordinator Endpoints
- `POST /dkg/start` - Start DKG with ZKP verification
- `POST /request-signature` - Request signature with ZKP verification  
- `GET /status` - Get coordinator status and ZKP stats
- `GET /memory` - View complete coordinator memory
- `GET /zkp-audit` - Get full ZKP audit trail

### Signer Endpoints  
- `GET /status` - Get signer status (including private key)
- `GET /memory` - Get complete memory (all sensitive data visible)
- `GET /zkp-proofs` - Get all generated ZKP proofs
- Standard DKG endpoints: `/dkg/round1/start`, `/dkg/round2/start_share_exchange`, etc.
- Standard signing endpoints: `/sign/generate-nonce-share`, `/sign/receive-and-aggregate-r`, etc.

## 📝 Testing the ZKP Module Standalone

```bash
python zkp_module.py
```

**Output:**
```
=== Zero-Knowledge Proof Tests ===

1. Testing Key Share Proof...
Key Share Proof: VALID

2. Testing Commitment Proof...  
Commitment Proof: VALID

3. Testing Nonce Proof...
Nonce Proof: VALID

4. Testing Aggregate Verifier...
Aggregate Verification Results:
  Success Rate: 100.00%
  Total Verifications: 3
  Proof Types: ['key_share_proof', 'commitment_proof', 'nonce_proof']

=== All ZKP Tests Complete ===
```

## 🎉 Summary

This basic implementation provides: Learning and development purposes.
