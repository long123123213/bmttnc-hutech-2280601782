import os
import ecdsa

class ECCCipher:
    def __init__(self):
        self.key_dir = 'cipher/ecc/keys'
        os.makedirs(self.key_dir, exist_ok=True)

    def generate_keys(self):
        """Tạo cặp khóa ECDSA và lưu vào file"""
        private_key = ecdsa.SigningKey.generate()
        public_key = private_key.get_verifying_key()

        with open(os.path.join(self.key_dir, 'privateKey.pem'), 'wb') as f:
            f.write(private_key.to_pem())
        with open(os.path.join(self.key_dir, 'publicKey.pem'), 'wb') as f:
            f.write(public_key.to_pem())

    def load_keys(self):
        """Tải cặp khóa từ file"""
        with open(os.path.join(self.key_dir, 'privateKey.pem'), 'rb') as f:
            private_key = ecdsa.SigningKey.from_pem(f.read())
        with open(os.path.join(self.key_dir, 'publicKey.pem'), 'rb') as f:
            public_key = ecdsa.VerifyingKey.from_pem(f.read())
        return private_key, public_key

    def sign(self, message, private_key):
        """Ký thông điệp bằng khóa riêng"""
        return private_key.sign(message.encode('utf-8'))

    def verify(self, message, signature, public_key):
        """Xác minh chữ ký bằng khóa công khai"""
        try:
            return public_key.verify(signature, message.encode('utf-8'))
        except ecdsa.BadSignatureError:
            return False
