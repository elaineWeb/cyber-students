from concurrent.futures import ThreadPoolExecutor
from motor import MotorClient
from tornado.web import Application

from .conf import MONGODB_HOST, MONGODB_DBNAME, WORKERS, AES_KEY, PEPPER

from .handlers.welcome import WelcomeHandler
from .handlers.registration import RegistrationHandler
from .handlers.login import LoginHandler
from .handlers.logout import LogoutHandler
from .handlers.user import UserHandler

import os
import base64

class Application(Application):

    def __init__(self):
        handlers = [
            (r'/students/?', WelcomeHandler),
            (r'/students/api/?', WelcomeHandler),
            (r'/students/api/registration', RegistrationHandler),
            (r'/students/api/login', LoginHandler),
            (r'/students/api/logout', LogoutHandler),
            (r'/students/api/user', UserHandler)
        ]

        settings = dict()

        super(Application, self).__init__(handlers, **settings)

        self.db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]

        self.executor = ThreadPoolExecutor(WORKERS)

        try:
            #initially I had the salt and pepper in two seperate files. I combined them with the existing conf.py file
            #print("zzz Current working directory:", os.getcwd())
            #with open("conf.py", "rb") as f:
            #    decoded = base64.b64decode(f.read())
            #    key = decoded[:16]     # first 16 bytes for AES key
            #    print("AES Key read successfully." + key.hex())

            #with open("confPepper.py", "rb") as f:
            #    decoded = base64.b64decode(f.read())
            #    pepper = decoded[:16]     # first 16 bytes for AES key
            #    print("Pepper read successfully." + pepper.hex())

            self.AES_KEY = AES_KEY
            self.pepper = PEPPER
            print("!! Key = " + self.AES_KEY.hex() + " Pepper = " + self.pepper.hex())

        except Exception as e:
                print("Failed to read config.key:", e)


