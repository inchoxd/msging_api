import os
import json
import uuid
import requests
import jwt
from jwt.algorithms import RSAAlgorithm
import time
from datetime import datetime as dt
import base64
import hashlib
import hmac
from dotenv import load_dotenv


class AccessToken:
    def __init__(self):
        load_dotenv(override=True)
        self.base_domain = 'https://api.line.me'
        self.data_domain = 'https://api-data.line.me'
        self.auth_uri = f'{self.base_domain}/oauth2/v2.1'
        self.short_auth_uri = f'{self.base_domain}/v2/oauth'
        self.channel_id = os.environ['channel_id']
        self.client_secret = os.environ['client_secret']


    def encode_jwt(self, token_exp=60*60*24*30):
        private_key = {
                'alg':os.environ['alg'],
                'd':os.environ['d'],
                'dp':os.environ['dp'],
                'dq':os.environ['dq'],
                'e':os.environ['e'],
                'kty':os.environ['kty'],
                'n':os.environ['n'],
                'p':os.environ['p'],
                'q':os.environ['q'],
                'qi':os.environ['qi'],
                'use':os.environ['use']
                }
        
        headers = {
                'alg':'RS256',
                'typ':'JWT',
                'kid':os.environ['kid']
                }

        payload = {
                'iss':self.channel_id,
                'sub':self.channel_id,
                'aud':'https://api.line.me/',
                'exp':int(time.time())+(60*30),
                'token_exp':token_exp
                }

        key = RSAAlgorithm.from_jwk(private_key)
        JWT = jwt.encode(payload, key, algorithm='RSA256', headers=headers, json_encoder=None)

        return JWT


    def issue_access_token(self, JWT):
        uri = f'{self.auth_uri}/token'
        headers = {
                'Content-Type':'application/x-www-form-urlencoded'
                }
        data = {
                'grant_type':'client_credentials',
                'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion':JWT
                }

        r = requests.post(url=uri, headers=headers, data=data)
        r_json = r.json()

        if not 'error' in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = r.status_code
            return r_json


    def verify_access_token(self, access_token):
        uri = f'{self.auth_uri}/verify?access_token={access_token}'

        r = requests.get(url=uri)
        r_json = r.json()

        if not 'error' in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = status_code
            return r_json


    def get_valid_access_token(self, JWT):
        uri = f'{self.auth_uri}/tokens/kid?client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={JWT}'

        r = requests.get(url=uri)
        r_json = r.json()

        if not 'error' in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = status_code
            return r_json

    def revoke_access_token(self, access_token):
        uri = f'{self.auth_uri}/revoke'
        data = {
                'client_id':self.channel_id,
                'client_secret':self.client_secret,
                'access_token':access_token
                }

        r = requests.post(url=uri, data = data)

    
    def issue_short_access_token(self):
        uri = f'{self.short_auth_uri}/accessToken'
        headers = {
                'Content-Type':'application/x-www-form-urlencoded'
                }
        data = {
                'grant_type':'client_credentials',
                'client_id':self.channel_id,
                'client_secret':self.client_secret
                }
        
        r = requests.post(url=uri, headers=headers, data=data)
        r_json = r.json()

        if 'error' not in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = status_code
            return r_json


    def verify_short_access_token(self, access_token):
        uri = f'{self.short_auth_uri}/verify'
        headers = {
                'Content-Type':'application/x-www-form-urlencoded'
                }
        data = {
                'access_token':access_token
                }

        r = requests.post(url=uri, headers=headers, data=data)
        r_json = r.json()

        if 'error' not in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = status_code
            return r_json

    def revoke_short_access_token(self, access_token):
        uri = f'{self.short_auth_uri}/revoke'
        headers = {
                'Content-Type':'application/x-www-form-urlencoded'
                }
        data = {
                'access_token':access_token
                }

        r = requests.post(url=uri, headers=headers, data=data)


class VerifySignature(AccessToken):
    def __init__(self):
        super().__init__()


    def verify_signature(self, l_signature, data):
        client_secret = self.client_secret
        hash_ = hmac.new(client_secret.encode('utf-8'), data, hashlib.sha256).digest()
        b_signature = base64.b64encode(hash_)
        signature = b_signature.decode('utf-8')

        if l_signature == signature:
            return True

        else:
            return False


class Message(AccessToken):
    def __init__(self):
        super().__init__()
        self.msg_uri = f'{self.base_domain}/v2/bot/message'


    def _gen_retry_key(self):
        retry_key = str(uuid.uuid4())

        return retry_key


    def send_messages(self, access_token, messages, send_type, retry_key=False, reply_token=None, to=None, narrows=None):
        uri = f'{self.msg_uri}/{send_type}'
        headers = {
                'Content-Type':'application/json',
                'Authorization':f'Bearer {access_token}'
                }

        data = {
                'messages':messages
                }

        if retry_key:
            x_line_retry_key = self._gen_retry_key()
            headers['X-Line-Retry-Key'] = x_line_retry_key

        if reply_token:
            data['replyToken'] = reply_token

        if to:
            data['to'] = to

        if narrows:
            data['recipient'] = narrows['recipient']
            data['filter'] = narrows['filter']
            data['limit'] = narrows['limit']

        r = requests.post(url=uri, headers=headers, data=json.dumps(data))
        r_json = r.json()

        if not 'error' in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = r.status_code
            return r_json


class Richmenu(AccessToken):
    def __init__(self):
        super().__init__()
        self.base_richmenu_uri = f'{self.base_domain}/v2/bot/richmenu'
        self.data_richmenu_uri = f'{self.data_domain}/v2/bot/richmenu'

    
    def create_richmenu(self, access_token, data):
        uri = f'{self.base_richmenu_uri}'
        headers = {
                'Authorization':f'Bearer {access_token}',
                'Content-Type':'application/json'
                }

        r = requests.post(url=uri, headers=headers, data=json.dumps(data))
        r_json = r.json()

        if not 'error' in r_json:
            richmenu_id = r_json['richMenuId']
            return richmenu_id

        else:
            status_code = r.status_code
            r_json['status_code'] = r.status_code
            return r_json


    def upload_richmenu(self, access_token, richmenu_id, f_path):
        uri = f'{self.data_richmenu_uri}/{richmenu_id}/content'
        headers = {
                'Authorization':f'Bearer {access_token}',
                'Content-Type':'image/jpeg'
                }
        with open(f_path, 'rb') as f:
            data = f.read()

        r = requests.post(url=uri, headers=headers, data=data)


    def download_richmenu(self, access_token, richmenu_id, dl_path):
        uri = f'{self.data_richmenu_uri}/{richmenu_id}/content'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }

        r = requests.get(url=uri, headers=headers)
        status_code  = r.status_code

        if status_code == 200:
            now = dt.now()
            t_stamp = now.strftime('%Y%m%d%H%M%S')
            with open(f'{dl_path}/richmenu_{t_stamp}.jpg', 'wb') as f:
                f.write(r.content)


    def get_richmenu_array(self, access_token):
        uri = f'{self.base_richmenu_uri}/list'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }

        r = requests.get(url=uri, headers=headers)
        r_json = r.json()

        if 'error' not in r_json:
            richmenus = r_json['richmenus']
            return richmenus

        else:
            status_code = r.status_code
            r_json['status_code'] = r.status_code
            return r_json


    def get_richmenu(self, access_token, richmenu_id):
        uri = f'{self.base_richmenu_uri}/{richmenu_id}'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }

        r = requests.get(url=uri, headers=headers)
        r_json = r.json()
        
        if not 'error' in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = r.status_code
            return r_json


    def delete_richmenu(self, access_token, richmenu_id):
        uri = f'{self.base_richmenu_uri}/{richmenu_id}'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }

        r = requests.delete(url=uri, headers=headers)

        status_code = r.status_code
        if status_code != 200:
            r_json = r.json()
            r_json['status_code'] = status_code

            return r_json


    def default_richmenu(self, access_token, richmenu_id):
        uri = f'{self.base_domain}/v2/bot/user/all/richmenu/{richmenu_id}'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }

        r = requests.post(url=uri, headers=headers)
        
        status_code = r.status_code
        if status_code != 200:
            r_json = r.json()
            r_json['status_code'] = status_code

            return r_json


    def create_richmenu_alias(self, access_token, richmenu_id, richmenu_alias):
        uri = f'{self.base_domain}/v2/bot/richmenu/alias'
        headers = {
                'Authorization':f'Bearer {access_token}',
                'Content-Type':'application/json'
                }
        data = {
                'richMenuAliasId':richmenu_alias,
                'richMenuId':richmenu_id
                }

        r = requests.post(url=uri, headers=headers, data=json.dumps(data))

        status_code = r.status_code
        if status_code != 200:
            r_json = r.json()
            r_json['status_code'] = status_code

            return r_json


    def delete_richmenu_alias(self, access_token, richmenu_alias):
        uri = f'{self.base_domain}/v2/bot/richmenu/alias/{richmenu_alias}'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }

        r = requests.delete(url=uri, headers=headers)

        status_code = r.status_code
        if status_code != 200:
            r_json = r.json()
            r_json['status_code'] = status_code

            return r_json


    def update_richmenu_alias(self, access_token, richmenu_id, richmenu_alias):
        uri = f'{self.base_domain}/v2/bot/richmenu/alias/{richmenu_alias}'
        headers = {
                'Authorization':f'Bearer {access_token}',
                'Content-Type':'application/json'
                }
        data = {
                'richMenuId':richmenu_id
                }

        r = requests.post(url=uri, headers=headers, data=json.dumps(data))

        status_code = r.status_code
        if status_code != 200:
            r_json = r.json()
            r_json['status_code'] = status_code

            return r_json


    def get_richmenu_alias(self, access_token, richmenu_alias):
        uri = f'{self.base_domain}/v2/bot/richmenu/alias/{richmenu_alias}'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }
            
        r = requests.get(url=uri, headers=headers)

        status_code = r.status_code
        r_json = r.json()
        if status_code != 200:
            r_json['status_code'] = status_code

            return r_json
        
        else:
            return r_json


    def get_richmenu_alias_list(self, access_token):
        uri = f'{self.base_domain}/v2/bot/richmenu/alias/list'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }

        r = requests.get(url=uri, headers=headers)
        status_code = r.status_code
        r_json = r.json()

        if status_code != 200:
            r_json['status_code'] = status_code

            return r_json

        else:
            alias_list = r_json['aliases']

            return alias_list


class GetUserData(AccessToken):
    def __init__(self):
        super().__init__()
        self.base_prof_uri = f'{self.base_domain}/v2/bot/profile'
    

    def get_user_prof(self, access_token, user_id):
        uri = f'{self.base_prof_uri}/{user_id}'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }

        r = requests.get(url=uri, headers=headers)
        status_code = r.status_code
        r_json = r.json()

        if status_code != 200:
            r_json['status_code'] = status_code

            return r_json

        return r_json


    def get_users_list(self, access_token, limit):
        user_ids = list()
        uri = f'{self.base_domain}/v2/bot/followers/ids'
        headers = {
                'Authorization':f'Bearer {access_token}'
                }
        data = {
                'limit':limit
                }


        while True:
            r = requests.get(url=uri, headers=headers, data=json.dumps(data))
            status_code = r.status_code
            r_json = r.json()

            if status_code != 200:
                r_json['status_code'] = status_code

                return r_json

            user_ids.append(r_json['userIds'])
            
            if 'next' in r_json:
                start_id = r_json['next']
                data['start'] = start_id
            
            else:
                break

        return user_ids
