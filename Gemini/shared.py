import base64
import ecdsa
from ecdsa.curves import SECP256k1

# --- Curve Constants ---
CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order

# --- Serialization/Deserialization for REST ---

def serialize_point(point: ecdsa.ellipticcurve.Point) -> str:
    """Serializes an ecdsa Point into a base64 string for JSON transport."""
    if point == ecdsa.ellipticcurve.INFINITY:
        return "infinity"
    # Use uncompressed format (0x04 prefix)
    return base64.b64encode(point.to_string('uncompressed')).decode('utf-8')

def deserialize_point(s: str) -> ecdsa.ellipticcurve.Point:
    """Deserializes a base64 string back into an ecdsa Point."""
    if s == "infinity":
        return ecdsa.ellipticcurve.INFINITY
    return ecdsa.ellipticcurve.Point.from_string(
        base64.b64decode(s.encode('utf-8')),
        curve=CURVE
    )

# --- Mathematical Helper Functions ---

def inv(n, prime=N):
    """Calculates modular inverse."""
    return pow(n, prime - 2, prime)

def compute_lagrange_coeff(party_ids, target_id):
    """
    Computes the Lagrange coefficient lambda_i for a given party i at x=0.
    """
    numerator = 1
    denominator = 1
    for j in party_ids:
        if j != target_id:
            numerator = (numerator * j) % N
            denominator = (denominator * (j - target_id)) % N
    return (numerator * inv(denominator, N)) % N