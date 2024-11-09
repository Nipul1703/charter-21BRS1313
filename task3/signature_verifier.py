import ecdsa
from ecdsa import VerifyingKey, BadSignatureError
from hashlib import sha256

def signature_verifier(signer_address, signature_data, message_hash):
    try:
        # Check if the public key is in uncompressed format (65 bytes = 130 hex characters)
        if len(signer_address) != 130 or not signer_address.startswith('04'):
            raise ValueError("Invalid public key format. Must be uncompressed (130 hex chars starting with '04')")

        # Convert hex public key (uncompressed) to VerifyingKey object using SECP256k1 curve
        vk = VerifyingKey.from_string(bytes.fromhex(signer_address[2:]), curve=ecdsa.SECP256k1)
        
        # Verify the signature
        vk.verify(signature_data, message_hash)  # This will raise an exception if the verification fails
        return True

    except BadSignatureError:
        print("Bad signature")
        return False
    except ValueError as ve:
        print(f"Value error during verification: {ve}")
        return False
    except Exception as e:
        print(f"Error during verification: {e}")
        return False
