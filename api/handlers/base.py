import json
from json import dumps, loads
from tornado.web import RequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64


class BaseHandler(RequestHandler):

    @property
    def db(self):
        return self.application.db

    @property
    def executor(self):
        return self.application.executor

    @property
    def AES_KEY(self):
        print("In BASE ")
        return self.application.AES_KEY
    
    def PEPPER(self):
        print("In BASE Getting Pepper")
        return self.application.pepper


    def prepare(self):
        if self.request.body:
            try:
                json_data = loads(self.request.body)
                self.request.arguments.update(json_data)
            except ValueError:
                self.send_error(400, message='Unable to parse JSON.')
        self.response = dict()

    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Methods', '*')
        self.set_header('Access-Control-Allow-Headers', '*')

    def write_error(self, status_code, **kwargs):
        if 'message' not in kwargs:
            if status_code == 405:
                kwargs['message'] = 'Invalid HTTP method.'
            else:
                kwargs['message'] = 'Unknown error.'
        self.response = kwargs
        self.write_json()

    def write_json(self):
        output = dumps(self.response)
        self.write(output)

    def options(self):
        self.set_status(204)
        self.finish()

    def encrypt_text(self, plaintext_str: str, key: bytes, aad: str) -> str:
        """
        Encrypt wth AES-GCM, return base64 string (nonce + ciphertext + tag)
        """
        try:
            aesgcm = AESGCM(key)
            
            print("Encrypt AAD " + aad)

            # only used once and strored in the database so can use random bytes 
            nonce = os.urandom(12)  # 12 bytes recommended for AES-GCM
            
            # Convert list to string if needed
            if isinstance(plaintext_str, list):
                plaintext_str = json.dumps(plaintext_str)
            
            plaintext_bytes = plaintext_str.encode("utf-8")

            #aad or Additional Authenticated Data has been added to the encrypt and decrypt functions so the text gets encrypted and authenticated
            # aad is the email address of the user and is used to authenticate the data
            aad_bytes = aad.encode("utf-8") if aad else None

            # Encrypt the plaintext using AES-GCM with the given nonce and AAD (authenticated but not encrypted)
            ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)

            # Combine the nonce and ciphertext so the nonce can be reused during decryption
            encrypted_combined = nonce + ciphertext

            # Return the full encrypted payload as a base64-encoded string for storage or transmission
            return base64.b64encode(encrypted_combined).decode("utf-8") 
        
        except Exception as e:
            print(f"Encryption failed for AAD={aad}: {e}")
            self.send_error(400, message="Encryption failed.")
        
    def decrypt_text(self, encoded_encrypted: str, key: bytes, aad: str) -> str:
        """
        Decrypt a base64-encoded AES-GCM encrypted name (nonce + ciphertext + tag)
        """
        aesgcm = AESGCM(key)

        #added in a check as the encoded_encrypted may be empty in the test cas
        if not encoded_encrypted or not isinstance(encoded_encrypted, str):
            self.send_error(400, message="Encoded encrypted string is empty.")

        try:
            print("Encoded encrypted input:", repr(encoded_encrypted))
            decoded = base64.b64decode(encoded_encrypted)


            print("DEncrypt AAD " + aad)

            nonce = decoded[:12]
            ciphertext = decoded[12:]

             #aad or Additional Authenticated Data has been added to the encrypt and decrypt functions so the text gets encrypted and authenticated
            # aad is the email address of the user and is used to authenticate the data           
            aad_bytes = aad.encode("utf-8") if aad else None

            # decrypt the ciphertext using AES-GCM with the extracted nonce and AAD (authenticated but not encrypted)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, aad_bytes)
            decrypted_str = decrypted_bytes.decode("utf-8")

            # Try to parse as JSON (Disabilities) (for lists, dicts, etc.), otherwise return plain string
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError:
                return decrypted_str
        except Exception as e:
            print(f"Decryption failed for AAD={aad}: {e}")
            self.send_error(400, message="Decryption failed.")
        
    #old code - was used to read the key from file when it was separate 
    def writeKeyOnce(self):     
        print("Current working directory:", os.getcwd())
        try:
            key = os.urandom(16)
            pepper = os.urandom(16)
            with open("config.key", "wb") as f:
                f.write(base64.b64encode(key))
            print("Key written successfully.")
        except Exception as e:
            print("Failed to write key:", e)
            
    #old code - was used to read the key from file when it was separate 
    def readKeyOLD(self) -> str:
        """  xxx don't continue if key not found, if no key write once ?
        Read the key in from the file 
        """
        print("Current working directory:", os.getcwd())
        try:
            key = os.urandom(16)
            with open("config.key", "rb") as f:
                key = base64.b64decode(f.read())
            print("Key read successfully.")
        except Exception as e:
            print("Failed to read key:", e)

        return key