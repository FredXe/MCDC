import os
import json
import logging
from hashlib import sha256
from base64 import b64encode, b64decode
from typing import Optional, List

import discord
import requests
from config import load_config, BasicConfig
from cryptography.fernet import Fernet

# Discord bot config
DCBOT_CONFIG_FILE = 'dcbot_config.json'
class DcBotConfig(BasicConfig):
    mcdc_api: str = 'http://mcdc.api.url'
    bot_token: str = 'discord_bot_token'
    admin_roles: List[str] = ['xxxxxxxxxxxx']

# init config
config: DcBotConfig = load_config(DCBOT_CONFIG_FILE, DcBotConfig)

# init cipher suite
KEY = b64encode(bytes.fromhex(sha256(config.secret.encode()).hexdigest())).decode()
cipher_suite = Fernet(KEY)

# init bot
intents = discord.Intents.default()
bot = discord.Client(intents = intents)
tree = discord.app_commands.CommandTree(bot)
_log = logging.getLogger('discord.MCDC')

def acc_type(account: str) -> str:
    return 'dc' if account.find('<@') != -1 else 'mc'

def acc_md(account: str) -> str:
    if acc_type(account) == 'dc':
        return account
    return f'`{account}`'

def is_admin(interaction: discord.Interaction) -> bool:
    user_roles = interaction.user.roles
    for _user_role in user_roles:
        if config.admin_roles.count(str(_user_role.id)): return True
    return False

@tree.command(name = 'list', description = 'List all linked account')
@discord.app_commands.describe(account = 'Minecraft name or Discord @user')
async def list_all(interaction: discord.Interaction, account: Optional[str]):
    if is_admin(interaction) == False:
        await interaction.response.send_message('只有管理員能使用此指令', ephemeral=True)
        return

    all_mcdc = requests.get('%s/linked/all' % config.mcdc_api).json()

    embed = discord.Embed(title='Linked Accounts', color=discord.Color.green())
    mcname = ''
    dcid = ''

    # make table
    if account:
        account_type = acc_type(account)
        account = account.removeprefix('<@').removesuffix('>')

        if account_type == 'dc':
            for mcdc in all_mcdc:
                if mcdc['dcid'] == account:
                    dcid = f"<@{mcdc['dcid']}>"
                    mcname = mcdc['mcname']
                    break
        else:
            for mcdc in all_mcdc:
                if mcdc['mcname'].lower() == account:
                    dcid = f"<@{mcdc['dcid']}>"
                    mcname = mcdc['mcname']
                    break
        
        if not mcname:
            embed = discord.Embed(title='No Linked Account', color=discord.Color.red())
    else:
        for mcdc in all_mcdc: mcname += f"**`{mcdc['mcname']}`**\n"
        for mcdc in all_mcdc: dcid += f"<@{mcdc['dcid']}>\n"

    embed.add_field(name='Minecraft', value=mcname, inline=True)
    embed.add_field(name='Discord', value=dcid, inline=True)

    await interaction.response.send_message(embed=embed, ephemeral=True)

@tree.command(name = 'unlink', description = 'unlink account')
@discord.app_commands.describe(account = 'Minecraft name or Discord @user')
async def unlink(interaction: discord.Interaction, account: str):
    if is_admin(interaction) == False:
        await interaction.response.send_message('只有管理員能使用此指令', ephemeral=True)
        return

    account_type = acc_type(account)
    
    origin_acc = account

    account = account.removeprefix('<@').removesuffix('>')

    account = cipher_suite.encrypt(account.encode()).decode()

    del_account = requests.delete('%s/unlink?account_type=%s' % (config.mcdc_api, account_type) , data=account).text

    res = f'{acc_md(origin_acc)} 已經解除連結'

    if del_account == 'null':
       res = f'無法刪除 {acc_md(origin_acc)}，此帳號尚未連結' 

    await interaction.response.send_message(content=res, ephemeral=True)

@bot.event
async def on_ready():
    await tree.sync()
    _log.info('MCDC Discord bot ready')

bot.run(config.bot_token)