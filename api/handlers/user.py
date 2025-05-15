from tornado.web import authenticated

from .auth import AuthHandler

class UserHandler(AuthHandler):

    @authenticated
    def get(self):


        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.decrypt_text(self.current_user['display_name'], self.AES_KEY, self.response['email'])  
        self.response['disabilities'] = self.decrypt_text(self.current_user.get('disabilities', ''), self.AES_KEY, self.response['email'])       
        self.response['fullName'] = self.decrypt_text(self.current_user['fullName'], self.AES_KEY, self.response['email'])     
        self.response['dob'] = self.decrypt_text(self.current_user['dob'], self.AES_KEY, self.response['email'])     
        self.response['phoneNumber'] = self.decrypt_text(self.current_user['phoneNumber'], self.AES_KEY, self.response['email'])     
        self.response['address'] = self.decrypt_text(self.current_user['address'], self.AES_KEY, self.response['email'])     

        self.write_json()

