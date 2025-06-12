import hashlib

message = b"Hi"
msg_hash = hashlib.sha256(message).digest()

print("Message:", message)
print("Message Hash:", msg_hash.hex())
# 3639efcd08abb273b1619e82e78c29a7df02c1051b1820e99fc395dcaa3326b8

# echo -n "Hi" | sha256sum | awk '{print $1}'
# 3639efcd08abb273b1619e82e78c29a7df02c1051b1820e99fc395dcaa3326b8