import unittest
from signature_verifier import signature_verifier
from hashlib import sha256

class TestSignatureVerifier(unittest.TestCase):

    def test_ecdsa_signature(self):
        # Replace this with a valid uncompressed public key (130 characters, starts with '04')
        address = '04a34b7fcf998cdaf2a196f1e6b23c3763eab64bde6d09d5e3b5f6ebd8b5794f9394e5c5fdba1f4fa0a1b69cc4dfaf149e965a89b8e7b7301234b2a1d9cf69f3e7'
        
        # Replace with a valid ECDSA signature
        signature = bytes.fromhex('3045022100f3b1ae532b74d04b9075a5733cfeb324cb6f582d43872bc452f95e36d4d83c26022044d8f20866057176b88241857e1f6f3e8b7e9b739b6ab3f23a2089944572b941')

        # Replace with the message hash that corresponds to the original signed message (SHA256 hash of message)
        message_hash = sha256(b"Hello").digest()

        # Call the signature_verifier function and check the result
        result = signature_verifier(address, signature, message_hash)

        # The test expects the result to be True for a valid signature
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()
