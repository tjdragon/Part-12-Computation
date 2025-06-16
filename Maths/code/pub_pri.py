from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from ecdsa.curves import NIST256p

# Generate ECC key pair using SECP256R1 (also known as prime256v1)
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Display private key scalar (d)
private_value = private_key.private_numbers().private_value
print("Private Key (d):")
print(f"  d = {hex(private_value)}")

# Display public key point (Q = d*G)
public_numbers = public_key.public_numbers()
print("\nPublic Key (Q = d * G):")
print(f"  x = {hex(public_numbers.x)}")
print(f"  y = {hex(public_numbers.y)}")

# Get the Generator G from the curve using ecdsa (for direct G access)
curve = NIST256p
G = curve.generator
print("\nGenerator Point G (from NIST256p):")
print(f"  x = {G.x()}")
print(f"  y = {G.y()}")
