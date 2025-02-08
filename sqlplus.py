# -*- coding: utf-8 -*-

'''
v0.1	
Simple class for AspenTech IP21 SQLPlus

Usage:
import sqlplus
s = sqlplus.SQLplus('INFO',10014)
query = "SELECT TS_START, AVG FROM aggregates WHERE name='00AAA01CT001:av' AND 
   ts between '01-FEB-13 00:00' AND '28-FEB-13 00:00'AND period = 864000;"
code, length, res = s.query(query.encode())
if (code!=sqlplus.SQLPLUS_SUCCESS): 
  raise Exception("Query error {}: {}".format(code,res))
print(res.decode())

Python 3.5.4
author: xabrs

'''
import socket, logging, time
from json.encoder import JSONEncoder
from advapi32 import decrypt,encrypt
from struct import pack, unpack

SOCKET_TIMEOUT = 60
BUFFER_SIZE = 4000
BUFFER_SIZE2 = 4004
SQLPLUS_SUCCESS = 0x53
SQLPLUS_ERROR = "\x40"

class SQLplus(object):
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.connect(host,port)

	def __del__(self):
		self.sock.close()

	def connect(self, host, port):
		self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
		self.sock.settimeout(SOCKET_TIMEOUT)
		self.sock.connect( (host, port))
		log.info("Connected to {}:{}".format(host,port))

		self.sock.send(b"\x4a\x00\x00\x02\x00")
		buf = b""
		buf = self.sock.recv(BUFFER_SIZE)
		while (len(buf)<75):
			buf += self.sock.recv(BUFFER_SIZE)

		d = buf[:12],buf[13:23],buf[24:33],buf[34:-1]

		self.token = d[3][4:]
		self.seq = unpack(">L",d[3][:4])[0]
		log.info("Server={0}, Version={1}, SEQ={2},token={3}".format(d[0].decode('utf-8'),d[1].decode('utf-8'),self.seq,self.token.decode('utf-8')))
		return

	def disconnect(self):
		try:
			self.sock.close()
			self.sock.shutdown(socket.SHUT_WR)
		except Exception as e:
			pass
			print(e)
		finally:
			return
	
	def recv(self,first=False):
		def subrecv():
			buf = self.sock.recv(BUFFER_SIZE+4)
			l = unpack(">L",decrypt(buf[:4]))[0]
			while (len(buf)<l):
				buf += self.sock.recv(l-len(buf))
			return buf

		buf = decrypt(subrecv()[4:])
		bufLen = unpack(">L",buf[1:5])[0]
		returnCode = buf[0]
		while (len(buf)<bufLen):
			buf += decrypt(subrecv()[4:])
		return returnCode,bufLen,buf[5:]

	def send(self,data):
		buf = decrypt(pack(">L",len(data)+4))
		buf +=decrypt(data)
		self.sock.send(buf)

	def query(self,q):
		log.debug(q)
		self.seq+=1
		length = len(q)
		buf = b""
		buf+= pack(">L",self.seq)
		buf+= self.token
		buf+= b"\x00\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb4"
		buf+= pack(">L",length)
		buf+= q
		self.send(buf)
		r,l,out = self.recv()
		# log.debug(out.decode("utf-8"))
		return r,l,out

def datetimeconvert(t):
	return time.strftime("%Y-%m-%d %H:%M:%S.000",time.strptime(t,"%d-%b-%y %H:%M:%S.%f"))

def todictarray(data):
		""
		data = data.decode()
		if (data.find("No rows selected")!=-1):
			return []
		d = data.split("\r\n")[:-1]
		lengthlist = [0]
		i = 0
		while (i<len(d[1])):
			i = d[1].find(" ",i+1)
			if (i==-1): break
			lengthlist.append(i+1)
		lengthlist.append(len(d[1])+1) 
		result = list((None) for x in range(len(d)-2))
		keys = list(filter(lambda x:x!='', d[0].split(' ')))
		for i in range(2,len(d)):
			values = list(d[i][lengthlist[j]:lengthlist[j+1]].strip() for j in range(len(lengthlist)-1))
			result[i-2] = dict((keys[j], values[j]) for j in range(len(keys)))
			for k in keys:
				try:
					if (k=="DT"):
						result[i-2][k] = datetimeconvert(result[i-2][k])
					else:
						result[i-2][k] = float(result[i-2][k])
				except Exception as e:
					result[i-2][k] = result[i-2][k]
					
		return result

def tojson(data):
	return jsonencoder.encode(todictarray(data))

def tohex(data):
    log.info(" ".join("%02x" % a for a in data))
    return 

def log_init():
	log = logging.getLogger('pysqlplus')
	log.setLevel(logging.DEBUG)
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	#file log
	tofile = logging.FileHandler('pysqlplus.log','a')
	tofile.setLevel(logging.DEBUG)
	tofile.setFormatter(formatter)
	#console log
	toconsole = logging.StreamHandler()
	toconsole.setLevel(logging.INFO)
	toconsole.setFormatter(formatter)
	log.addHandler(tofile)
	log.addHandler(toconsole)
	log.info('')
	log.info("New log started")
	return log

log = log_init()
jsonencoder = JSONEncoder()
if __name__ == '__main__':
	pass
	
