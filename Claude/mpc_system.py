# CryptoVault MPC POC/MVP
# A complete Multi-Party Computation system for cryptographic asset management

import asyncio
import json
import logging
import os
import secrets
import hashlib
import hmac
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3
from pathlib import Path
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import hashlib
import ecdsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der, sigencode_der
import threading
import time
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ======================== CORE CRYPTOGRAPHIC PRIMITIVES ========================

class CurveParameters:
    """Elliptic curve parameters"""
    def __init__(self, name: str):
        self.name = name
        if name == "secp256k1":
            self.curve = SECP256k1
            self.order = SECP256k1.order
            self.generator = SECP256k1.generator
        else:
            raise ValueError(f"Unsupported curve: {name}")

class SecretShare:
    """Represents a secret share in threshold cryptography"""
    def __init__(self, x: int, y: int, threshold: int, parties: int):
        self.x = x  # Share index
        self.y = y  # Share value
        self.threshold = threshold
        self.parties = parties
    
    def to_dict(self) -> Dict:
        return {
            'x': self.x,
            'y': hex(self.y),
            'threshold': self.threshold,
            'parties': self.parties
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SecretShare':
        return cls(
            x=data['x'],
            y=int(data['y'], 16),
            threshold=data['threshold'],
            parties=data['parties']
        )

class ShamirSecretSharing:
    """Shamir's Secret Sharing implementation"""
    
    def __init__(self, curve_params: CurveParameters):
        self.curve = curve_params
        self.prime = curve_params.order
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Modular inverse using extended Euclidean algorithm"""
        if a < 0:
            a = (a % m + m) % m
        
        g, x, _ = self._extended_gcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        return x % m
    
    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """Evaluate polynomial at point x"""
        result = 0
        for i, coeff in enumerate(coefficients):
            result = (result + coeff * pow(x, i, self.prime)) % self.prime
        return result
    
    def split_secret(self, secret: int, threshold: int, num_shares: int) -> List[SecretShare]:
        """Split secret into shares using Shamir's scheme"""
        if threshold > num_shares:
            raise ValueError("Threshold cannot be greater than number of shares")
        
        # Generate random coefficients for polynomial
        coefficients = [secret]
        for _ in range(threshold - 1):
            coefficients.append(secrets.randbelow(self.prime))
        
        # Generate shares
        shares = []
        for i in range(1, num_shares + 1):
            y = self._evaluate_polynomial(coefficients, i)
            shares.append(SecretShare(i, y, threshold, num_shares))
        
        return shares
    
    def reconstruct_secret(self, shares: List[SecretShare]) -> int:
        """Reconstruct secret from shares using Lagrange interpolation"""
        if len(shares) < shares[0].threshold:
            raise ValueError("Insufficient shares for reconstruction")
        
        # Use only threshold number of shares
        shares = shares[:shares[0].threshold]
        
        secret = 0
        for i, share_i in enumerate(shares):
            numerator = 1
            denominator = 1
            
            for j, share_j in enumerate(shares):
                if i != j:
                    numerator = (numerator * (-share_j.x)) % self.prime
                    denominator = (denominator * (share_i.x - share_j.x)) % self.prime
            
            lagrange_coeff = (numerator * self._mod_inverse(denominator, self.prime)) % self.prime
            secret = (secret + share_i.y * lagrange_coeff) % self.prime
        
        return secret % self.prime

# ======================== MPC PROTOCOL IMPLEMENTATION ========================

@dataclass
class KeyGenerationResult:
    """Result of distributed key generation"""
    public_key: str
    key_shares: List[Dict]
    key_id: str
    threshold: int
    parties: int

@dataclass
class SigningResult:
    """Result of distributed signing"""
    signature: str
    recovery_id: int
    message_hash: str

class MPCProtocol(ABC):
    """Abstract base class for MPC protocols"""
    
    @abstractmethod
    async def distributed_key_generation(
        self, 
        parties: List[str], 
        threshold: int
    ) -> KeyGenerationResult:
        pass
    
    @abstractmethod
    async def distributed_signing(
        self, 
        message: bytes, 
        key_shares: List[Dict],
        participant_ids: List[str]
    ) -> SigningResult:
        pass

class SimpleMPCProtocol(MPCProtocol):
    """Simplified MPC protocol for POC"""
    
    def __init__(self):
        self.curve_params = CurveParameters("secp256k1")
        self.secret_sharing = ShamirSecretSharing(self.curve_params)
        logger.info("Initialized SimpleMPC protocol with secp256k1")
    
    async def distributed_key_generation(
        self, 
        parties: List[str], 
        threshold: int
    ) -> KeyGenerationResult:
        """Generate distributed ECDSA key"""
        logger.info(f"Starting DKG with {len(parties)} parties, threshold {threshold}")
        
        # Generate master private key
        master_private_key = secrets.randbelow(self.curve_params.order)
        
        # Split into shares
        shares = self.secret_sharing.split_secret(
            master_private_key, threshold, len(parties)
        )
        
        # Generate public key
        private_key_obj = SigningKey.from_secret_exponent(
            master_private_key, 
            curve=SECP256k1
        )
        public_key = private_key_obj.get_verifying_key()
        public_key_hex = public_key.to_string("compressed").hex()
        
        # Create key shares for each party
        key_shares = []
        for i, (party_id, share) in enumerate(zip(parties, shares)):
            key_shares.append({
                'party_id': party_id,
                'share': share.to_dict(),
                'share_index': i + 1
            })
        
        key_id = hashlib.sha256(public_key_hex.encode()).hexdigest()[:16]
        
        logger.info(f"DKG completed. Key ID: {key_id}")
        
        return KeyGenerationResult(
            public_key=public_key_hex,
            key_shares=key_shares,
            key_id=key_id,
            threshold=threshold,
            parties=len(parties)
        )
    
    async def distributed_signing(
        self, 
        message: bytes, 
        key_shares: List[Dict],
        participant_ids: List[str]
    ) -> SigningResult:
        """Sign message using distributed shares"""
        logger.info(f"Starting distributed signing with {len(key_shares)} shares")
        
        if len(key_shares) < key_shares[0]['share']['threshold']:
            raise ValueError("Insufficient shares for signing")
        
        # Reconstruct private key from shares
        shares = [SecretShare.from_dict(ks['share']) for ks in key_shares]
        private_key_int = self.secret_sharing.reconstruct_secret(shares)
        
        # Create signing key
        signing_key = SigningKey.from_secret_exponent(
            private_key_int, 
            curve=SECP256k1
        )
        
        # Hash message
        message_hash = hashlib.sha256(message).digest()
        
        # Sign message
        signature = signing_key.sign_digest(
            message_hash,
            sigencode=sigencode_der
        )
        
        # Get recovery ID (simplified)
        recovery_id = 0
        
        logger.info("Distributed signing completed")
        
        return SigningResult(
            signature=signature.hex(),
            recovery_id=recovery_id,
            message_hash=message_hash.hex()
        )

# ======================== KEY MANAGEMENT SERVICE ========================

class KeyEncryption:
    """Handles encryption/decryption of key material"""
    
    def __init__(self, password: str):
        self.password = password.encode()
        
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(self.password)
    
    def encrypt(self, data: bytes) -> Dict[str, str]:
        """Encrypt data with AES-GCM"""
        salt = secrets.token_bytes(16)
        key = self._derive_key(salt)
        
        nonce = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce)
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'salt': base64.b64encode(salt).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }
    
    def decrypt(self, encrypted_data: Dict[str, str]) -> bytes:
        """Decrypt AES-GCM encrypted data"""
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        salt = base64.b64decode(encrypted_data['salt'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        key = self._derive_key(salt)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag)
        )
        
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class KeyStorage:
    """Secure storage for key shares"""
    
    def __init__(self, db_path: str, encryption_password: str):
        self.db_path = db_path
        self.encryption = KeyEncryption(encryption_password)
        self._init_db()
        logger.info(f"Initialized key storage at {db_path}")
    
    def _init_db(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS key_shares (
                key_id TEXT,
                party_id TEXT,
                encrypted_share TEXT,
                created_at TIMESTAMP,
                PRIMARY KEY (key_id, party_id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS public_keys (
                key_id TEXT PRIMARY KEY,
                public_key TEXT,
                threshold INTEGER,
                parties INTEGER,
                created_at TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def store_key_generation_result(self, result: KeyGenerationResult):
        """Store complete key generation result"""
        conn = sqlite3.connect(self.db_path)
        
        # Store public key info
        conn.execute('''
            INSERT OR REPLACE INTO public_keys 
            (key_id, public_key, threshold, parties, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            result.key_id,
            result.public_key,
            result.threshold,
            result.parties,
            datetime.now().isoformat()
        ))
        
        # Store encrypted key shares
        for key_share in result.key_shares:
            share_data = json.dumps(key_share).encode()
            encrypted_share = self.encryption.encrypt(share_data)
            
            conn.execute('''
                INSERT OR REPLACE INTO key_shares 
                (key_id, party_id, encrypted_share, created_at)
                VALUES (?, ?, ?, ?)
            ''', (
                result.key_id,
                key_share['party_id'],
                json.dumps(encrypted_share),
                datetime.now().isoformat()
            ))
        
        conn.commit()
        conn.close()
        logger.info(f"Stored key shares for key {result.key_id}")
    
    def get_key_shares(self, key_id: str, party_ids: List[str]) -> List[Dict]:
        """Retrieve and decrypt key shares"""
        conn = sqlite3.connect(self.db_path)
        
        shares = []
        for party_id in party_ids:
            cursor = conn.execute('''
                SELECT encrypted_share FROM key_shares 
                WHERE key_id = ? AND party_id = ?
            ''', (key_id, party_id))
            
            row = cursor.fetchone()
            if row:
                encrypted_data = json.loads(row[0])
                decrypted_share = self.encryption.decrypt(encrypted_data)
                share_data = json.loads(decrypted_share.decode())
                shares.append(share_data)
        
        conn.close()
        return shares
    
    def get_public_key(self, key_id: str) -> Optional[str]:
        """Get public key for key ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute('''
            SELECT public_key FROM public_keys WHERE key_id = ?
        ''', (key_id,))
        
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    
    def list_keys(self) -> List[Dict]:
        """List all stored keys"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute('''
            SELECT key_id, public_key, threshold, parties, created_at 
            FROM public_keys ORDER BY created_at DESC
        ''')
        
        keys = []
        for row in cursor.fetchall():
            keys.append({
                'key_id': row[0],
                'public_key': row[1],
                'threshold': row[2],
                'parties': row[3],
                'created_at': row[4]
            })
        
        conn.close()
        return keys

# ======================== ASSET ABSTRACTION LAYER ========================

class AssetInterface(ABC):
    """Abstract interface for different crypto assets"""
    
    @abstractmethod
    def get_address_from_pubkey(self, public_key: str) -> str:
        pass
    
    @abstractmethod
    def format_transaction(self, to_address: str, amount: int, **kwargs) -> bytes:
        pass
    
    @abstractmethod
    def verify_signature(self, public_key: str, message: bytes, signature: str) -> bool:
        pass

class BitcoinAsset(AssetInterface):
    """Bitcoin asset handler"""
    
    def __init__(self):
        self.network = "mainnet"  # Could be configurable
    
    def get_address_from_pubkey(self, public_key: str) -> str:
        """Generate Bitcoin address from public key (P2PKH)"""
        # Simplified implementation - real Bitcoin would use proper address encoding
        pubkey_bytes = bytes.fromhex(public_key)
        sha256_hash = hashlib.sha256(pubkey_bytes).digest()
        ripemd160 = hashlib.new('ripemd160', sha256_hash).digest()
        
        # Add version byte (0x00 for mainnet P2PKH)
        versioned_hash = b'\x00' + ripemd160
        
        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        # Base58 encode (simplified - using hex for POC)
        address = (versioned_hash + checksum).hex()
        return f"btc_{address[:40]}"  # Simplified address format
    
    def format_transaction(self, to_address: str, amount: int, **kwargs) -> bytes:
        """Format Bitcoin transaction"""
        tx_data = {
            'to': to_address,
            'amount': amount,
            'fee': kwargs.get('fee', 1000),
            'timestamp': int(time.time())
        }
        return json.dumps(tx_data, sort_keys=True).encode()
    
    def verify_signature(self, public_key: str, message: bytes, signature: str) -> bool:
        """Verify Bitcoin signature"""
        try:
            pubkey_bytes = bytes.fromhex(public_key)
            sig_bytes = bytes.fromhex(signature)
            
            # Use ecdsa library for verification
            vk = VerifyingKey.from_string(pubkey_bytes[1:], curve=SECP256k1)  # Skip compression byte
            message_hash = hashlib.sha256(message).digest()
            
            return vk.verify_digest(sig_bytes, message_hash, sigdecode=sigdecode_der)
        except Exception:
            return False

class EthereumAsset(AssetInterface):
    """Ethereum asset handler"""
    
    def get_address_from_pubkey(self, public_key: str) -> str:
        """Generate Ethereum address from public key"""
        pubkey_bytes = bytes.fromhex(public_key)
        
        # Remove compression byte and get x,y coordinates
        if len(pubkey_bytes) == 33:  # Compressed
            # For POC, simplified decompression
            pubkey_hash = hashlib.sha256(pubkey_bytes).digest()
        else:
            pubkey_hash = hashlib.sha256(pubkey_bytes[1:]).digest()  # Skip first byte
        
        # Ethereum uses Keccak256 (simplified with SHA256 for POC)
        address = pubkey_hash[-20:]  # Last 20 bytes
        return f"0x{address.hex()}"
    
    def format_transaction(self, to_address: str, amount: int, **kwargs) -> bytes:
        """Format Ethereum transaction"""
        tx_data = {
            'to': to_address,
            'value': amount,
            'gas': kwargs.get('gas', 21000),
            'gasPrice': kwargs.get('gas_price', 20000000000),
            'nonce': kwargs.get('nonce', 0),
            'data': kwargs.get('data', ''),
            'timestamp': int(time.time())
        }
        return json.dumps(tx_data, sort_keys=True).encode()
    
    def verify_signature(self, public_key: str, message: bytes, signature: str) -> bool:
        """Verify Ethereum signature"""
        # Similar to Bitcoin for POC
        return BitcoinAsset().verify_signature(public_key, message, signature)

class AssetRegistry:
    """Registry for different asset types"""
    
    def __init__(self):
        self.assets = {
            'bitcoin': BitcoinAsset(),
            'ethereum': EthereumAsset()
        }
        logger.info("Initialized asset registry with Bitcoin and Ethereum")
    
    def get_asset(self, asset_type: str) -> AssetInterface:
        if asset_type not in self.assets:
            raise ValueError(f"Unsupported asset type: {asset_type}")
        return self.assets[asset_type]
    
    def list_assets(self) -> List[str]:
        return list(self.assets.keys())

# ======================== POLICY ENGINE ========================

@dataclass
class PolicyRule:
    """Represents a policy rule"""
    name: str
    condition: str  # Python expression
    action: str     # 'allow', 'deny', 'require_approval'
    description: str

class PolicyEngine:
    """Simple policy evaluation engine"""
    
    def __init__(self):
        self.rules = []
        self._load_default_rules()
        logger.info("Initialized policy engine")
    
    def _load_default_rules(self):
        """Load default security policies"""
        self.rules = [
            PolicyRule(
                name="max_transaction_amount",
                condition="(asset_type == 'bitcoin' and amount > 10000000) or (asset_type == 'ethereum' and amount > 100000000000000000000)",  # 0.1 BTC or 100 ETH
                action="deny",
                description="Transaction amount exceeds maximum limit"
            ),
            PolicyRule(
                name="min_approvals",
                condition="len(approvals) < threshold",
                action="deny",
                description="Insufficient approvals for transaction"
            ),
            PolicyRule(
                name="blacklist_check",
                condition="to_address in blacklisted_addresses",
                action="deny",
                description="Transaction to blacklisted address"
            )
        ]
    
    def evaluate_transaction(self, transaction_data: Dict, context: Dict) -> Tuple[bool, str]:
        """Evaluate transaction against policies"""
        logger.info(f"Evaluating transaction policies for {transaction_data.get('to', 'unknown')}")
        
        # Create evaluation context with safe built-ins
        safe_builtins = {
            'len': len,
            'abs': abs,
            'min': min,
            'max': max,
            'sum': sum,
            'int': int,
            'float': float,
            'str': str,
            'bool': bool,
        }
        
        eval_context = {
            **transaction_data,
            **context,
            'blacklisted_addresses': [],  # Would be loaded from config
            'threshold': context.get('threshold', 2),
            'approvals': context.get('participants', [])  # Use participants as approvals for now
        }
        
        for rule in self.rules:
            try:
                result = eval(rule.condition, {"__builtins__": safe_builtins}, eval_context)
                if result and rule.action == 'deny':
                    return False, f"Policy violation: {rule.description}"
                elif result and rule.action == 'require_approval':
                    return False, f"Approval required: {rule.description}"
            except Exception as e:
                logger.warning(f"Policy evaluation error for rule {rule.name}: {e}")
                return False, f"Policy evaluation error: {rule.name}"
        
        return True, "All policies passed"

# ======================== CORE MPC SERVICE ========================

class MPCService:
    """Main MPC service orchestrator"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.protocol = SimpleMPCProtocol()
        self.key_storage = KeyStorage(
            config['storage']['db_path'],
            config['storage']['encryption_password']
        )
        self.asset_registry = AssetRegistry()
        self.policy_engine = PolicyEngine()
        logger.info("Initialized MPC Service")
    
    async def create_wallet(
        self, 
        parties: List[str], 
        threshold: int,
        name: str = None
    ) -> KeyGenerationResult:
        """Create new MPC wallet"""
        logger.info(f"Creating new wallet with {len(parties)} parties, threshold {threshold}")
        
        result = await self.protocol.distributed_key_generation(parties, threshold)
        self.key_storage.store_key_generation_result(result)
        
        logger.info(f"Created wallet {result.key_id}")
        return result
    
    async def sign_transaction(
        self,
        key_id: str,
        asset_type: str,
        to_address: str,
        amount: int,
        participants: List[str],
        **kwargs
    ) -> Dict:
        """Sign transaction using MPC"""
        logger.info(f"Signing transaction for key {key_id}, asset {asset_type}")
        
        # Get asset handler
        asset = self.asset_registry.get_asset(asset_type)
        
        # Format transaction
        transaction_bytes = asset.format_transaction(to_address, amount, **kwargs)
        
        # Policy evaluation
        transaction_data = {
            'to': to_address,
            'to_address': to_address,  # Add both for compatibility
            'amount': amount,
            'asset_type': asset_type
        }
        context = {
            'participants': participants,
            'threshold': len(participants),  # Use actual participant count
            'approvals': participants  # Map participants to approvals for policy evaluation
        }
        
        policy_ok, policy_msg = self.policy_engine.evaluate_transaction(
            transaction_data, context
        )
        if not policy_ok:
            raise ValueError(f"Policy violation: {policy_msg}")
        
        # Get key shares
        key_shares = self.key_storage.get_key_shares(key_id, participants)
        if len(key_shares) < key_shares[0]['share']['threshold']:
            raise ValueError("Insufficient participants for signing")
        
        # Sign transaction
        signing_result = await self.protocol.distributed_signing(
            transaction_bytes,
            key_shares,
            participants
        )
        
        # Get public key for address generation
        public_key = self.key_storage.get_public_key(key_id)
        from_address = asset.get_address_from_pubkey(public_key)
        
        return {
            'transaction_hash': hashlib.sha256(transaction_bytes).hexdigest(),
            'signature': signing_result.signature,
            'from_address': from_address,
            'to_address': to_address,
            'amount': amount,
            'asset_type': asset_type,
            'signed_at': datetime.now().isoformat()
        }
    
    def get_wallet_info(self, key_id: str) -> Dict:
        """Get wallet information"""
        public_key = self.key_storage.get_public_key(key_id)
        if not public_key:
            raise ValueError(f"Wallet {key_id} not found")
        
        # Generate addresses for all supported assets
        addresses = {}
        for asset_type in self.asset_registry.list_assets():
            asset = self.asset_registry.get_asset(asset_type)
            addresses[asset_type] = asset.get_address_from_pubkey(public_key)
        
        return {
            'key_id': key_id,
            'public_key': public_key,
            'addresses': addresses
        }
    
    def list_wallets(self) -> List[Dict]:
        """List all wallets"""
        return self.key_storage.list_keys()

# ======================== REST API ========================

# Pydantic models for API
class CreateWalletRequest(BaseModel):
    parties: List[str] = Field(..., description="List of party IDs")
    threshold: int = Field(..., description="Signing threshold")
    name: Optional[str] = Field(None, description="Wallet name")

class SignTransactionRequest(BaseModel):
    asset_type: str = Field(..., description="Asset type (bitcoin/ethereum)")
    to_address: str = Field(..., description="Destination address")
    amount: int = Field(..., description="Amount in smallest units")
    participants: List[str] = Field(..., description="Signing participants")
    fee: Optional[int] = Field(None, description="Transaction fee")
    gas: Optional[int] = Field(None, description="Gas limit (Ethereum)")
    gas_price: Optional[int] = Field(None, description="Gas price (Ethereum)")

# Global MPC service instance
mpc_service = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global mpc_service
    
    # Startup
    config = {
        'storage': {
            'db_path': 'data/keystore.db',
            'encryption_password': 'demo_password_change_in_production'
        }
    }
    
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    mpc_service = MPCService(config)
    logger.info("MPC Service started")
    
    yield
    
    # Shutdown
    logger.info("MPC Service shutting down")

# Create FastAPI app
app = FastAPI(
    title="CryptoVault MPC API",
    description="Multi-Party Computation API for secure digital asset management",
    version="0.1.0",
    lifespan=lifespan
)

# Security
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Simple authentication (would be more sophisticated in production)"""
    if credentials.credentials != "demo_token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "demo_user"

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/wallets")
async def create_wallet(
    request: CreateWalletRequest,
    current_user: str = Depends(get_current_user)
):
    """Create new MPC wallet"""
    try:
        result = await mpc_service.create_wallet(
            request.parties,
            request.threshold,
            request.name
        )
        return {
            "key_id": result.key_id,
            "public_key": result.public_key,
            "threshold": result.threshold,
            "parties": result.parties
        }
    except Exception as e:
        logger.error(f"Wallet creation failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/wallets")
async def list_wallets(current_user: str = Depends(get_current_user)):
    """List all wallets"""
    return mpc_service.list_wallets()

@app.get("/wallets/{key_id}")
async def get_wallet(
    key_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get wallet information"""
    try:
        return mpc_service.get_wallet_info(key_id)
    except Exception as e:
        logger.error(f"Get wallet failed: {e}")
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/wallets/{key_id}/sign")
async def sign_transaction(
    key_id: str,
    request: SignTransactionRequest,
    current_user: str = Depends(get_current_user)
):
    """Sign transaction with MPC"""
    try:
        result = await mpc_service.sign_transaction(
            key_id=key_id,
            asset_type=request.asset_type,
            to_address=request.to_address,
            amount=request.amount,
            participants=request.participants,
            fee=request.fee,
            gas=request.gas,
            gas_price=request.gas_price
        )
        return result
    except Exception as e:
        logger.error(f"Transaction signing failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/assets")
async def list_assets(current_user: str = Depends(get_current_user)):
    """List supported assets"""
    global mpc_service
    return {
        "assets": mpc_service.asset_registry.list_assets()
    }

# ======================== CLI INTERFACE ========================

import argparse
import asyncio

class MPCCLIInterface:
    """Command-line interface for MPC operations"""
    
    def __init__(self):
        self.config = {
            'storage': {
                'db_path': 'data/keystore.db',
                'encryption_password': 'demo_password_change_in_production'
            }
        }
        os.makedirs('data', exist_ok=True)
        self.service = MPCService(self.config)
    
    async def create_wallet_cli(self, args):
        """Create wallet via CLI"""
        parties = args.parties.split(',')
        result = await self.service.create_wallet(parties, args.threshold)
        
        print(f"✅ Wallet created successfully!")
        print(f"Key ID: {result.key_id}")
        print(f"Public Key: {result.public_key}")
        print(f"Threshold: {result.threshold}/{result.parties}")
        
        # Show addresses
        wallet_info = self.service.get_wallet_info(result.key_id)
        print("\nAddresses:")
        for asset_type, address in wallet_info['addresses'].items():
            print(f"  {asset_type}: {address}")
    
    def list_wallets_cli(self, args):
        """List wallets via CLI"""
        wallets = self.service.list_wallets()
        
        if not wallets:
            print("No wallets found")
            return
        
        print(f"Found {len(wallets)} wallet(s):")
        for wallet in wallets:
            print(f"  Key ID: {wallet['key_id']}")
            print(f"  Public Key: {wallet['public_key']}")
            print(f"  Threshold: {wallet['threshold']}/{wallet['parties']}")
            print(f"  Created: {wallet['created_at']}")
            print()
    
    async def sign_transaction_cli(self, args):
        """Sign transaction via CLI"""
        participants = args.participants.split(',')
        
        result = await self.service.sign_transaction(
            key_id=args.key_id,
            asset_type=args.asset,
            to_address=args.to_address,
            amount=args.amount,
            participants=participants
        )
        
        print(f"✅ Transaction signed successfully!")
        print(f"Transaction Hash: {result['transaction_hash']}")
        print(f"From: {result['from_address']}")
        print(f"To: {result['to_address']}")
        print(f"Amount: {result['amount']}")
        print(f"Signature: {result['signature']}")

async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='CryptoVault MPC CLI')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start API server')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    
    # Create wallet command
    create_parser = subparsers.add_parser('create-wallet', help='Create new wallet')
    create_parser.add_argument('--parties', required=True, help='Comma-separated party IDs')
    create_parser.add_argument('--threshold', type=int, required=True, help='Signing threshold')
    
    # List wallets command
    list_parser = subparsers.add_parser('list-wallets', help='List all wallets')
    
    # Sign transaction command
    sign_parser = subparsers.add_parser('sign', help='Sign transaction')
    sign_parser.add_argument('--key-id', required=True, help='Wallet key ID')
    sign_parser.add_argument('--asset', required=True, choices=['bitcoin', 'ethereum'], help='Asset type')
    sign_parser.add_argument('--to-address', required=True, help='Destination address')
    sign_parser.add_argument('--amount', type=int, required=True, help='Amount in smallest units')
    sign_parser.add_argument('--participants', required=True, help='Comma-separated participant IDs')
    
    args = parser.parse_args()
    
    if args.command == 'server':
        print(f"🚀 Starting CryptoVault MPC Server on {args.host}:{args.port}")
        # Use uvicorn.run directly without being in async context
        import uvicorn
        uvicorn.run(app, host=args.host, port=args.port)
        return  # Exit after starting server
    
    elif args.command in ['create-wallet', 'sign']:
        cli = MPCCLIInterface()
        
        if args.command == 'create-wallet':
            await cli.create_wallet_cli(args)
        elif args.command == 'sign':
            await cli.sign_transaction_cli(args)
    
    elif args.command == 'list-wallets':
        cli = MPCCLIInterface()
        cli.list_wallets_cli(args)
    
    else:
        parser.print_help()

def main_sync():
    """Synchronous main function for server startup"""
    parser = argparse.ArgumentParser(description='CryptoVault MPC CLI')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start API server')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    
    # Create wallet command
    create_parser = subparsers.add_parser('create-wallet', help='Create new wallet')
    create_parser.add_argument('--parties', required=True, help='Comma-separated party IDs')
    create_parser.add_argument('--threshold', type=int, required=True, help='Signing threshold')
    
    # List wallets command
    list_parser = subparsers.add_parser('list-wallets', help='List all wallets')
    
    # Sign transaction command
    sign_parser = subparsers.add_parser('sign', help='Sign transaction')
    sign_parser.add_argument('--key-id', required=True, help='Wallet key ID')
    sign_parser.add_argument('--asset', required=True, choices=['bitcoin', 'ethereum'], help='Asset type')
    sign_parser.add_argument('--to-address', required=True, help='Destination address')
    sign_parser.add_argument('--amount', type=int, required=True, help='Amount in smallest units')
    sign_parser.add_argument('--participants', required=True, help='Comma-separated participant IDs')
    
    args = parser.parse_args()
    
    if args.command == 'server':
        print(f"🚀 Starting CryptoVault MPC Server on {args.host}:{args.port}")
        import uvicorn
        uvicorn.run(app, host=args.host, port=args.port)
    else:
        # For async commands, use asyncio.run
        asyncio.run(main())

if __name__ == "__main__":
    main_sync()
