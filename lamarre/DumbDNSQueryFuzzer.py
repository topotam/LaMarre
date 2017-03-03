from scapy.all import *

# Petit dumb fuzzer de requetes DNS, sur tout fields possible
# Il suffit de retirer/ajouter un ou plusieurs parametres a -requete- pour que ceux ci soit fuzzes




conf.L3socket=L3RawSocket # sans ce tricks, le server dns local ne prend pas en compte les requetes, contrairement a vavec dig

#DNSQR FIELDS
qname = 'www.google.fr'	#DNSStrField                         = ('www.example.com')
qtype = 1    		#ShortEnumField                      = (1)
qclass = 1  		#ShortEnumField                      = (1)

#DNS FIELDS
id = 0 			#ShortField
qr = 0 			#BitField (1 bit)
opcode = 0 		#BitEnumField (4 bits)
aa = 0 			#BitField (1 bit)
tc = 0 			#BitField (1 bit)
rd = 1 			#BitField (1 bit)
ra = 0 			#BitField (1 bit)
z = 0 			#BitField (1 bit)
ad = 0 			#BitField (1 bit)
cd = 0 			#BitField (1 bit)
rcode = 0 		#BitEnumField (4 bits)

qdcount = '' 		#DNSRRCountField
ancount = '' 		#DNSRRCountField
nscount = '' 		#DNSRRCountField
arcount = '' 		#DNSRRCountField

qd = ''			#DNSQRField

an = '' 		#DNSRRField
ns = '' 		#DNSRRField
ar = '' 		#DNSRRField


 

#fuzz = IP(src="192.168.1.47",dst="192.168.1.47")/UDP(dport=53)/fuzz(DNS(id=id,qr=qr,opcode=opcode,aa=aa,tc=tc,rd=rd,ra=ra,z=z,ad=ad,cd=cd,rcode=rcode,qd=DNSQR(qname=qname)))
requete = IP(src="192.168.1.47",dst="192.168.1.47")/UDP(dport=53)/fuzz(DNS(id=id,opcode=opcode,qr=qr,aa=aa,tc=tc,rd=rd,ra=ra,z=z,ad=ad,cd=cd,rcode=rcode,qd=fuzz(DNSQR(qname=qname,qclass=qclass,qtype=qtype))))
print requete.show()
for i in range(0,100000):

	send(requete)
	print requete.show(),
	hexdump(requete)
	print "REQUETE NUMERO: "+str(i)



