from signature_verifier import signature_verifier
from hashlib import sha256

address = '04bfcab73bc...'
signature = b'\x01\x02\x03...'
message_hash = sha256(b"Hello").digest()

result = signature_verifier(address, signature, message_hash)
print(result)  # Should print True if the signature is valid
