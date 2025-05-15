from concurrent.futures import ThreadPoolExecutor
from motor import MotorClient
from tornado.ioloop import IOLoop
from tornado.testing import AsyncHTTPTestCase

from .conf import MONGODB_HOST, MONGODB_DBNAME, WORKERS, AES_KEY, PEPPER

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import json

class BaseTest(AsyncHTTPTestCase):

    @classmethod
    def setUpClass(self):
        self.my_app.db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]
        self.my_app.executor = ThreadPoolExecutor(WORKERS)
        #initially I had the salt and pepper in two seperate files. I combined them with the existing conf.py file
        #self.my_app.AES_KEY = self.readKey(self)
        #self.my_app.pepper = self.readPepper(self)
        self.my_app.AES_KEY = AES_KEY
        self.my_app.pepper = PEPPER

    def get_new_ioloop(self):
        return IOLoop.current()

    def get_app(self):
        return self.my_app

    def setUp(self):
        super().setUp()
        self.get_app().db.users.drop()

    def tearDown(self):
        super().tearDown()
        self.get_app().db.users.drop()

    def encrypt_text(self, plaintext_str: str, key: bytes, aad: str) -> str:
        """
        Encrypt a display name using AES-GCM, return base64 string (nonce + ciphertext + tag)
        """
        aesgcm = AESGCM(key)
        
        print("Encrypt AAD " + aad)

        nonce = os.urandom(12)  # 12 bytes recommended for AES-GCM
        
        # Convert list to string if needed
        if isinstance(plaintext_str, list):
            plaintext_str = json.dumps(plaintext_str)
        
        plaintext_bytes = plaintext_str.encode("utf-8")
        aad_bytes = aad.encode("utf-8") if aad else None

        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)
        encrypted_combined = nonce + ciphertext
        return base64.b64encode(encrypted_combined).decode("utf-8") 


    def decrypt_text(self, encoded_encrypted: str, key: bytes, aad: str) -> str:
            """
            Decrypt a base64-encoded AES-GCM encrypted name (nonce + ciphertext + tag)
            """
            aesgcm = AESGCM(key)

            if not encoded_encrypted or not isinstance(encoded_encrypted, str):
                # Return empty list if expecting 'disabilities'
                return [] if isinstance(encoded_encrypted, list) or encoded_encrypted == [] else ''

            print("Encoded encrypted input:", repr(encoded_encrypted))
            decoded = base64.b64decode(encoded_encrypted)


            print("DEncrypt AAD " + aad)

            nonce = decoded[:12]
            ciphertext = decoded[12:]
            aad_bytes = aad.encode("utf-8") if aad else None


            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, aad_bytes)
            decrypted_str = decrypted_bytes.decode("utf-8")

            # Try to parse as JSON (for lists, dicts, etc.), otherwise return plain string
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError:
                return decrypted_str
    #no longer needed as I combined the salt and pepper into one existing file       
    def readKey(self) -> str:
        """  xxx don't continue if key not found, if no key write once ?
        Read the key in from the file 
        """
        print("TEST - Current working directory:", os.getcwd())
        try:
            key = os.urandom(16)
            with open("conf.py", "rb") as f:
                key = base64.b64decode(f.read())
            print("Key read successfully.")
        except Exception as e:
            print("Failed to read key:", e)

        return key
    
    # not needed in the end as I just hardcoded the hash to make sure it was working
    def readPepper(self) -> str:
        """  xxx don't continue if pepper not found, if no key write once ?
        Read the key in from the file 
        """
        print("TEST Getting Pepprer - Current working directory:", os.getcwd())
        try:
            #have a value for first time access - if there is no file and no records in the db then first time they will have to be written 
            key = os.urandom(16)
            with open("confPepper.py", "rb") as f:
                key = base64.b64decode(f.read())
            print("Key read successfully.")
        except Exception as e:
            print("Failed to read key:", e)

        return key