import json
import time
import asyncio
import urllib.parse
from hashlib import sha256
from base64 import b64encode, b64decode

import flask
from flask import Flask, request, redirect, render_template
import requests
from prisma import Prisma, errors
from cryptography.fernet import Fernet
from config import load_config, BasicConfig

# MCDC config
MCDC_CONFIG_FILE = 'mcdc_config.json'
class McDcConfig(BasicConfig):
    port: int = 5555
    bot_token: str = 'discord_bot_token'
    bot_client_id: str = 'xxxxxxxxxxxxxxx'
    bot_client_secret: str = 'xxxxxxxxxxxxxxx'
    dc_api: str = 'https://discord.com/api/v10'
    domain: str = 'http://your.domain'
    channel_id: str = 'xxxxxxxxxxxxxxx'

    @property
    def url(self) -> str:
        return urllib.parse.quote_plus(self.domain)

TOKEN_STORE_KEY = 'mcUser'
LINK_TOKEN_STORE_KEY = 'mcdc'
TOKEN_EXPIRES_IN = 300



# init config
config: McDcConfig = load_config(MCDC_CONFIG_FILE, McDcConfig)

# init Discord settings
DISCORD_2OAUTH_URL = "https://discord.com/oauth2/authorize?client_id={}&response_type=code&redirect_uri={}%2Flink&scope=identify".format(config.bot_client_id, config.url)
REDIRECT_URI = '{}/link'.format(config.domain)

# init cipher suite
KEY = b64encode(bytes.fromhex(sha256(config.secret.encode()).hexdigest())).decode()
cipher_suite = Fernet(KEY)



# 
# Mojang API
# 
def id_2_uuid(id: str) -> str:
    r = requests.get(f'https://api.mojang.com/users/profiles/minecraft/{id}')
    r.raise_for_status()
    return r.json()['id']

# 
# Discord 2OAuth
# 
def exchange_code(code: str):
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post('%s/oauth2/token' % config.dc_api, data=data, headers=headers, auth=(config.bot_client_id, config.bot_client_secret))
    r.raise_for_status()
    return r.json()

def refresh_token(refresh_token):
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post('%s/oauth2/token' % config.dc_api, data=data, headers=headers, auth=(config.bot_client_id, config.bot_client_secret))
    r.raise_for_status()
    return r.json()

def get_token():
    data = {
        'grant_type': 'client_credentials',
        'scope': 'identify connections'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post('%s/oauth2/token' % config.dc_api, data=data, headers=headers, auth=(config.bot_client_id, config.bot_client_secret))
    r.raise_for_status()
    return r.json()

def get_user(token):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    r = requests.get('%s/users/@me' % config.dc_api, headers=headers)
    r.raise_for_status()
    return r.json()

def get_guild_user(user_id: str):
    headers = {
        'Authorization': f'Bot {config.bot_token}'
    }
    r = requests.get('%s/guilds/%s/members/%s' % (config.dc_api, config.channel_id, user_id), headers=headers)
    r.raise_for_status()
    return r.json()

def get_guild():
    headers = {
        'Authorization': f'Bot {config.bot_token}'
    }
    r = requests.get('%s/guilds/%s' % (config.dc_api, config.channel_id), headers=headers)
    r.raise_for_status()
    return r.json()

app = Flask('mcdc')

# 
# DB
# 
prisma = Prisma()
prisma.connect()
def get_mcdc(mcname: str):
    return prisma.mcdc.find_first(
        where={
            'mcname': mcname
        }
    )

def get_all_mcdc():
    return prisma.mcdc.find_many(
        include={}
    )

def del_mcdc_by_mc(mcname: str):
    return prisma.mcdc.delete(
        where={
            'mcname': mcname
        }
    )

def del_mcdc_by_dc(dcid: str):
    return prisma.mcdc.delete(
        where={
            'dcid': dcid
        }
    )

def add_mcdc(mcid: str, mcname: str, dcid: str, dcname: str):
    return prisma.mcdc.create(
        data={
            'mcid': mcid,
            'mcname': mcname,
            'dcid': dcid,
            'dcname': dcname
        }
    )

# 
# Flask route
# 
@app.route('/', methods=['GET'])
def dc2OAuth():
    # handle JWT
    cipher = request.args.get('i', type=str)
    try:
        token = cipher_suite.decrypt_at_time(cipher, TOKEN_EXPIRES_IN, int(time.time()))
    except:
        res = flask.make_response(render_template('index.html',
        info='請再次進入伺服器拿取連結', infotype='token_timeout'))
        return res

    # Set token for linking
    token = cipher_suite.encrypt(token)
    hashed_token = b64encode(bytes.fromhex(sha256(token).hexdigest())).decode()
    hashed_token = hashed_token.replace('+', '')

    res = flask.make_response(redirect(DISCORD_2OAUTH_URL + '&state=%s' % hashed_token, code=302))
    res.set_cookie(TOKEN_STORE_KEY, value=token.decode(), max_age=TOKEN_EXPIRES_IN, secure=True, httponly=True)

    return res

@app.route('/link', methods=['GET'])
def link():
    # handle JWT
    code = request.args.get('code', type=str)
    state = request.args.get('state', type=str)
    token = request.cookies.get(TOKEN_STORE_KEY)
    try:
        token = token.encode()
        # check state param in redirect url
        hashed_token = b64encode(bytes.fromhex(sha256(token).hexdigest())).decode()
        hashed_token = hashed_token.replace('+', '')
        if hashed_token != state:
            raise Exception('invalid token')
        # decode token
        token = cipher_suite.decrypt(token)
        token = token.decode()
        mc_user = json.loads(token)
        token = exchange_code(code)['access_token']
    except:
        res = flask.make_response(render_template('index.html',
        info='請再次進入伺服器拿取連結', infotype='token_timeout'))
        return res

    # Fetch DC user data
    dc_user = get_user(token)
    dc_guild_user = get_guild_user(dc_user['id'])

    # Set new token for comfirm the link (`POST /link`)
    link_token = json.dumps({
        'mcname': mc_user['id'],
        'mcuuid': mc_user['uuid'],
        'dcid': dc_user['id'],
        'dcname': dc_guild_user['nick'] if dc_guild_user['nick'] else dc_user['global_name'],
    }).encode()
    link_token = cipher_suite.encrypt(link_token).decode()

    res = flask.make_response(render_template('index.html',
        link=True,
        dcid=dc_user['id'], dcavatar=dc_user['avatar'], dcnick=dc_guild_user['nick'] if dc_guild_user['nick'] else dc_user['global_name'],
        mcname=mc_user['id']))
    res.set_cookie(LINK_TOKEN_STORE_KEY, value=link_token, max_age=TOKEN_EXPIRES_IN, secure=True, httponly=True)
    return res

@app.route('/link', methods=['POST'])
def link_submit():
    token = request.cookies.get(LINK_TOKEN_STORE_KEY)
    try:
        token = cipher_suite.decrypt(token).decode()
    except:
        res = flask.make_response(render_template('index.html',
        info='請再次進入伺服器拿取連結', infotype='token_timeout'))
        return res

    token = json.loads(token)
    try:
        add_mcdc(token['mcuuid'], token['mcname'], token['dcid'], token['dcname'])
    except errors.UniqueViolationError:
        res = flask.make_response(render_template('index.html',
        info='您已經連接過您的帳號了', infotype='already_linked'))
        return res

    res = flask.make_response(render_template('index.html',
    info='您已經成功連接，可以關閉此頁面', infotype='linked_successfully'))
    return res

@app.route('/linked', methods=['GET'])
def is_linked():
    mcname = request.args.get('id', type=str)
    mcdc = get_mcdc(mcname)

    res = {
            'linked': False,
            'roles': []
        }

    if (mcdc == None):
        return json.dumps(res, sort_keys=True, indent=2)
    
    res['linked'] = True
    res['roles'] = get_guild_user(mcdc.dcid)['roles']

    return json.dumps(res, sort_keys=True, indent=2)


@app.route('/linked/all', methods=['GET'])
def linked_all():
    return json.dumps(get_all_mcdc(), default=lambda obj: obj.__dict__, ensure_ascii=False)

@app.route('/unlink', methods=['DELETE'])
def delete():
    account_type = request.args.get('account_type', type=str)
    account = cipher_suite.decrypt(request.data)
    del_func = del_mcdc_by_dc if account_type == 'dc' else del_mcdc_by_mc
    
    res = del_func(account.decode())
    
    return json.dumps(res, default=lambda obj: obj.__dict__, sort_keys=True, indent=2)

if __name__ == '__main__':
    app.run(port=config.port, debug=True,)





