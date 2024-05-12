import threading
import time
import json
import os
from typing import List
from hashlib import sha256
from base64 import b64encode, b64decode

from mcdreforged.api.all import *
from serializer import NoMissingFieldSerializable
from cryptography.fernet import Fernet
import requests
from config import load_config, BasicConfig

class Rcon(NoMissingFieldSerializable):
    proxy_server_name: str
    host: str
    port: int
    password: str

WHITELIST_SPOON_CONFIG_FILE: str
class WhitelistSpoonConfig(BasicConfig):
    lobby_rcon: Rcon = Rcon(
        proxy_server_name = 'lobby',
        host = '127.0.0.1',
        port = 25575,
        password = 'rcon_passwd')
    main_rcon: Rcon = Rcon(
        proxy_server_name = 'main',
        host = '127.0.0.1',
        port = 25575,
        password = 'rcon_passwd')
    whitelist_roles: List[str] = ['xxxxxxxxxxxxxxx']
    dcmc_api: str = 'http://mcdc.api.url'
    unlinked_kick_message: str = '\n§7您尚未將您的 §9Discord§7 和 §2Minecraft§7 綁定'
    no_role_kick_message: str = '\n§7您需要身分組才能進入此伺服器'
    link_helper: str = 'your json raw text {{TOKEN}}'

KICK_TIME_OUT = 30

config: WhitelistSpoonConfig
MESSAGE_REPLACE_TOKEN = '{{TOKEN}}'

# init cipher suite
KEY: str
cipher_suite: Fernet

# init whitelist
KICK_STACK = {}

# init Rcon
LOBBY_RCON: RconConnection
MAIN_RCON: RconConnection

# 
# External API
# 
def id_2_uuid(id: str) -> str:
    r = requests.get(f'https://api.mojang.com/users/profiles/minecraft/{id}')
    r.raise_for_status()
    return r.json()['id']

# Fetch if player linked
def player_linked(id: str):
    r = requests.get(f'{config.dcmc_api}/linked?id={id}')
    r.raise_for_status()
    return r.json()

# Compare user's roles with valid roles
def valid_role(role: list) -> bool:
    for _ in role:
        if config.whitelist_roles.count(_): return True
    return False

# Encrypt uuid in order to place it in url
def encrypt_uuid(id: str) -> str:
    uuid = id_2_uuid(id)
    plain_text = json.dumps({
        "id": id,
        "uuid": uuid
    })
    cipher = cipher_suite.encrypt_at_time(plain_text.encode(), int(time.time()))
    
    return cipher.decode()

def till_player_join(server: PluginServerInterface, rcon: RconConnection, player: str):
    while str(rcon.send_command(f'list')).find(player) == -1:
        time.sleep(0.1)

# Kick function for count down
def kick(server: PluginServerInterface, player: str):
    if (player_linked(player)['linked']): 
        MAIN_RCON.send_command(f'whitelist add {player}')
        return
    server.execute(f'send {player} {config.lobby_rcon.proxy_server_name}')
    till_player_join(server, LOBBY_RCON, player)
    LOBBY_RCON.send_command(f'kick {player} {config.unlinked_kick_message}')

def on_player_joined(server: PluginServerInterface, player: str, info: Info):
    # fetch player's discord role
    dcmc = player_linked(player)
    if (dcmc['linked']):
        if (valid_role(dcmc['roles'])):
            # Passed 
            MAIN_RCON.send_command(f'whitelist add {player}')
            return
        # Linked player without valid role
        server.execute(f'send {player} {config.lobby_rcon.proxy_server_name}')
        MAIN_RCON.send_command(f'whitelist remove {player}')
        till_player_join(server, LOBBY_RCON, player)
        LOBBY_RCON.send_command(f'kick {player} {config.no_role_kick_message}')
    # Show link helper
    server.execute(f'send {player} {config.lobby_rcon.proxy_server_name}')
    MAIN_RCON.send_command(f'whitelist remove {player}')

    cipher = encrypt_uuid(player)
    message = config.link_helper.replace(MESSAGE_REPLACE_TOKEN, cipher)
    till_player_join(server, LOBBY_RCON, player)
    LOBBY_RCON.send_command("tellraw {} {}".format(player, message))

    # Player will be kicked after 60 sec
    KICK_STACK[player] = threading.Timer(KICK_TIME_OUT, kick, (server, player))
    KICK_STACK[player].start()

# Canel the 30 sec kick
def on_player_left(server: PluginServerInterface, player: str):
    if (KICK_STACK.get(player) == None): return
    KICK_STACK[player].cancel()
    del KICK_STACK[player]

def on_load(server: PluginServerInterface, prev_module):
    builder = SimpleCommandBuilder()

    global config, WHITELIST_SPOON_CONFIG_FILE
    WHITELIST_SPOON_CONFIG_FILE = os.path.join(server.get_data_folder(), 'config.json')
    config = server.load_config_simple(WHITELIST_SPOON_CONFIG_FILE, in_data_folder=False, target_class=WhitelistSpoonConfig)

    # init cipher suite
    global KEY, cipher_suite
    KEY = b64encode(bytes.fromhex(sha256(config.secret.encode()).hexdigest())).decode()
    cipher_suite = Fernet(KEY)

    builder.register(server)

    # init Rcon
    global LOBBY_RCON, MAIN_RCON
    LOBBY_RCON = RconConnection(config.lobby_rcon.host, config.lobby_rcon.port, config.lobby_rcon.password)
    MAIN_RCON = RconConnection(config.main_rcon.host, config.main_rcon.port, config.main_rcon.password)

    if LOBBY_RCON.connect() and MAIN_RCON.connect(): server.logger.info('Rcon connected')