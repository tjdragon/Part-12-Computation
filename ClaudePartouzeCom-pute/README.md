### Key Features

- ✅ **Distributed Key Generation (DKG)**: Creates secure keys split across multiple parties
- ✅ **Threshold Signing**: Requires cooperation (e.g., 2-of-3, 3-of-5) to sign transactions  
- ✅ **Multi-Asset Support**: Bitcoin and Ethereum transaction signing
- ✅ **Policy Engine**: Configurable transaction validation rules
- ✅ **Encrypted Storage**: AES-256-GCM encrypted key shares
- ✅ **REST API**: Complete FastAPI-based web service
- ✅ **CLI Interface**: Command-line tools for all operations
- ✅ **Comprehensive Testing**: Full test suite included

### Security Properties

- **No Single Point of Failure**: Keys distributed across parties
- **Threshold Security**: Requires minimum participants to operate
- **Policy Enforcement**: Business rule validation before signing
- **Encrypted Storage**: All key material protected at rest
- **Audit Trail**: Complete transaction logging

## 🚀 Quick Start


### Installation

create a virtual env 

then
```bash
pip install -r requirements.txt
```

### Project Structure

```
cryptovault-mpc/
├── mpc_system.py              # Main application
├── test_mpc_standalone.py     # Standalone test script  
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── data/                      # Key storage directory
│   └── keystore.db           # Encrypted SQLite database
├── logs/                      # Application logs
└── venv/                      # Virtual environment
```

## 🧪 Testing Your Installation

### Step 1: Run Standalone Tests

```bash
# Run comprehensive test suite
python test_mpc_standalone.py
```

**Expected Output:**
```
🎉 ALL TESTS PASSED! Your MPC system is working correctly.
Total: 8/8 tests passed
```

### Step 2: Test CLI Interface

```bash
# Create a 2-of-3 wallet
python mpc_system.py create-wallet --parties "alice,bob,charlie" --threshold 2

# Example output:
# ✅ Wallet created successfully!
# Key ID: abc123def456
# Public Key: 02d5231e817436ddf1d3...
# Threshold: 2/3

# List all wallets
python mpc_system.py list-wallets

# Sign a Bitcoin transaction
python mpc_system.py sign \
  --key-id "abc123def456" \
  --asset bitcoin \
  --to-address "btc_recipient" \
  --amount 50000 \
  --participants "alice,bob"
```

### Step 3: Test API Server

```bash
# Terminal 1: Start API server
python mpc_system.py server

# Terminal 2: Test API endpoints
# Health check
curl http://localhost:8000/health

# Create wallet via API
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{"parties": ["alice", "bob", "charlie"], "threshold": 2}'

# Sign transaction via API  
curl -X POST "http://localhost:8000/wallets/{key_id}/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_recipient", 
    "amount": 50000,
    "participants": ["alice", "bob"]
  }'
```

## 📖 Basic Usage Guide

### Creating Wallets

**Different threshold configurations:**

```bash
# 1-of-2: Either party can sign (operational flexibility)
python mpc_system.py create-wallet --parties "server1,server2" --threshold 1

# 2-of-3: Standard corporate approval  
python mpc_system.py create-wallet --parties "ceo,cfo,cto" --threshold 2

# 3-of-5: High-security executive approval
python mpc_system.py create-wallet --parties "ceo,cfo,cto,chairman,ciso" --threshold 3

# 5-of-7: Ultra-secure institutional setup
python mpc_system.py create-wallet --parties "trustee1,trustee2,trustee3,trustee4,trustee5,backup1,backup2" --threshold 5
```

### Signing Transactions

**Bitcoin transactions:**
```bash
# Small transaction (0.0005 BTC)
python mpc_system.py sign \
  --key-id "your_key_id" \
  --asset bitcoin \
  --to-address "recipient_btc_address" \
  --amount 50000 \
  --participants "party1,party2"

# Larger transaction (0.05 BTC)  
python mpc_system.py sign \
  --key-id "your_key_id" \
  --asset bitcoin \
  --to-address "vendor_payment_address" \
  --amount 5000000 \
  --participants "ceo,cfo,cto"
```

**Ethereum transactions:**
```bash
# Standard ETH transfer (0.1 ETH)
python mpc_system.py sign \
  --key-id "your_key_id" \
  --asset ethereum \
  --to-address "0xrecipient_address" \
  --amount 100000000000000000 \
  --participants "party1,party2"
```

### Wallet Management

```bash
# List all wallets
python mpc_system.py list-wallets

# Get specific wallet info (via API)
curl -X GET "http://localhost:8000/wallets/{key_id}" \
  -H "Authorization: Bearer demo_token"

# Check supported assets
curl -X GET "http://localhost:8000/assets" \
  -H "Authorization: Bearer demo_token"
```

## 🔌 API Reference

### Authentication

All API endpoints require Bearer token authentication:
```
Authorization: Bearer demo_token
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/wallets` | Create new MPC wallet |
| `GET` | `/wallets` | List all wallets |
| `GET` | `/wallets/{key_id}` | Get wallet information |
| `POST` | `/wallets/{key_id}/sign` | Sign transaction |
| `GET` | `/assets` | List supported assets |

### API Examples

#### Create Wallet
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["alice", "bob", "charlie"],
    "threshold": 2,
    "name": "my_wallet"
  }'
```

**Response:**
```json
{
  "key_id": "abc123def456",
  "public_key": "02d5231e817436ddf1d3...",
  "threshold": 2,
  "parties": 3
}
```

#### Sign Transaction
```bash
curl -X POST "http://localhost:8000/wallets/{key_id}/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_recipient",
    "amount": 50000,
    "participants": ["alice", "bob"]
  }'
```

**Response:**
```json
{
  "transaction_hash": "e8890c3d784267bad460...",
  "signature": "3044022004fe1637238d1fe1042e...",
  "from_address": "btc_00304c22893d75e3c3c5...",
  "to_address": "btc_recipient", 
  "amount": 50000,
  "asset_type": "bitcoin",
  "signed_at": "2025-06-06T17:03:36.404018"
}
```

## 🛡️ Security Considerations

### ⚠️ POC Limitations

This is a **Proof of Concept** with the following limitations:

- **Simplified MPC**: Uses Shamir Secret Sharing instead of advanced protocols like GG20/FROST
- **Local Simulation**: All parties simulated on single machine
- **Basic Authentication**: Simple bearer token instead of enterprise auth
- **Simplified Cryptography**: Basic ECDSA operations without advanced security features

### 🔐 Security Features Implemented

- **Threshold Cryptography**: No single party can compromise system
- **Encrypted Storage**: All key shares encrypted with AES-256-GCM  
- **Policy Engine**: Configurable transaction validation
- **Input Validation**: Comprehensive request validation
- **Audit Logging**: All operations logged for compliance

### 🚨 Production Requirements

For production deployment, implement:

1. **Real MPC Protocols**: GG20, FROST, or CGGMP
2. **Hardware Security Modules**: Dedicated HSM integration
3. **Network Security**: TLS 1.3, certificate pinning, VPN
4. **Advanced Authentication**: Multi-factor auth, hardware tokens
5. **Formal Verification**: Mathematical security proofs
6. **Air-Gap Support**: Offline signing capabilities
7. **Regulatory Compliance**: GDPR, MiCA, SOC2 compliance
8. **Monitoring**: Real-time security monitoring and alerting

## 📊 Policy Configuration

### Default Policies

The system includes these default policies:

- **Maximum Transaction Amount**: 
  - Bitcoin: 0.1 BTC (10,000,000 satoshis)
  - Ethereum: 100 ETH (100,000,000,000,000,000,000 wei)
- **Minimum Approvals**: Threshold number of participants required
- **Blacklist Check**: Blocks transactions to forbidden addresses

### Customizing Policies

Edit the `PolicyEngine._load_default_rules()` method in `mpc_system.py`:

```python
def _load_default_rules(self):
    self.rules = [
        PolicyRule(
            name="custom_limit",
            condition="amount > 5000000",  # Custom limit
            action="deny", 
            description="Custom transaction limit"
        )
    ]
```

## 🔧 Troubleshooting

### Common Issues

#### Runtime Issues
```bash
# Error: Permission denied for database
# Solution: Check directory permissions
chmod 755 data/

# Error: Port already in use  
# Solution: Use different port
python mpc_system.py server --port 8001

# Error: Module not found
# Solution: Activate virtual environment
source venv/bin/activate
```

#### API Issues
```bash
# Error: 401 Unauthorized
# Solution: Include Bearer token
curl -H "Authorization: Bearer demo_token" ...

# Error: 422 Unprocessable Entity
# Solution: Check request format
# Ensure JSON is valid and includes required fields
```

### Debugging

#### Enable Debug Logging
```python
# In mpc_system.py, change logging level:
logging.basicConfig(level=logging.DEBUG)
```

#### Database Inspection
```bash
# Connect to SQLite database
sqlite3 data/keystore.db

# View tables
.tables

# View stored keys
SELECT key_id, threshold, parties, created_at FROM public_keys;
```

## 🎯 Use Cases

### Corporate Treasury
- Multi-signature approval for large payments
- Department budget controls
- Executive oversight for strategic transactions

### Financial Services  
- Investment fund management
- Bank digital asset custody
- Insurance pool operations

### DeFi Protocols
- DAO treasury management
- Liquidity pool controls
- Cross-chain bridge security

### Gaming & NFTs
- Guild treasury management
- Metaverse asset purchases
- Revenue sharing agreements

## 🚀 Production Roadmap

### Phase 1: Core Enhancement
- [ ] Implement GG20/FROST protocols
- [ ] Add hardware security module integration
- [ ] Network-based party communication
- [ ] Advanced key derivation (BIP32/44)

### Phase 2: Enterprise Features
- [ ] Role-based access control
- [ ] Multi-factor authentication
- [ ] Comprehensive audit trails
- [ ] Regulatory compliance modules

### Phase 3: Scaling
- [ ] High availability clustering
- [ ] Performance optimization
- [ ] Backup and disaster recovery
- [ ] Monitoring and alerting

### Phase 4: Advanced Capabilities
- [ ] Post-quantum cryptography
- [ ] Zero-knowledge privacy features
- [ ] Cross-chain atomic swaps
- [ ] AI-powered security analytics


## 🙏 Acknowledgments

- **Shamir Secret Sharing**: Based on Adi Shamir's original paper
- **ECDSA**: Using the secp256k1 curve for Bitcoin compatibility
- **FastAPI**: For the REST API framework
- **Cryptography Library**: For secure cryptographic operations

---

**⚠️ Important**: This is a Proof of Concept for demonstration and educational purposes. Do not use in production without implementing proper security measures and conducting thorough security audits.
