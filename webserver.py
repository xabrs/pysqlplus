# -*- coding: utf-8 -*-

'''
Simple http server for SQLPlus queries
Python 3.6
author: xabrs

'''

VERSION='v0123'
HOST, PORT='', 8000

IPHOST, IPPORT = "A1-INFO", 10014
CONTENT_TYPE = {
	# '.cfg':	'application/xml',
	'.css': 'text/css',
	#'.gif': 'image/gif',
	#'.htm': 'text/html',
	'.html': 'text/html',
	'.jpg': 'image/jpg',
	'.js': 'application/javascript',
	'.png': 'image/png',
	#'.txt': 'text/plain',
	'.xml':'application/xml'
}

import os, cgi, re, logging, time, threading, sys, ssl
from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import parse_qs
 
import sqlplus


re_tags = re.compile("^[0-9A-Za-z\:\,\-\_\.]+$")
# 2018-03-08 00:00
re_date = re.compile("^[0-9\-\s\:]{16}$")


def parseargs1(args):
	args = parse_qs(args)
	tstart = args['tstart'][0]
	tend = args['tend'][0]
	period = args['period'][0]
	tags = args['tags'][0]
	if ((re.match(re_date,tstart)==None)|(re.match(re_date,tend)==None)):
		raise Exception("Wrong date format")
	if (re.match(re_tags,tags)==None):
		raise Exception("Wrong tags format")
	tstart = datetimeconvert(tstart)
	tend = datetimeconvert(tend)
	period = periodconvert(period)
	tags = tags.split(",")
	return tags, tstart tend, period

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

class webServerHandler(BaseHTTPRequestHandler):
	server_version = VERSION
	sqlsocket = sqlplus.SQLplus(IPHOST,IPPORT)
	def log_message(self,format,*args):
		log.info("%s: %s",self.client_address[0],' '.join(args))
		pass

	def sqlquery(self, query):
		try:
			code, length, res = self.sqlsocket.query(query)
			if (code!=sqlplus.SQLPLUS_SUCCESS): raise Exception("Query error {}: {}".format(code,res))
			return code, length, res
		except Exception as e:
			print(e)
			self.sqlsocket.disconnect()
			try:
				self.sqlsocket.connect(IPHOST,IPPORT)
				code, length, res = self.sqlsocket.query(query)
				if (code!=sqlplus.SQLPLUS_SUCCESS): raise Exception("Query error {}: {}".format(code,res))
				return code, length, res
			except Exception as e:
				raise e
		finally:
			raise Exception("Some eroor")

	def avg(self,args):
		"""
		Sample of average values by periods
		"""
		tags, tstart tend, period = parseargs1(args)
		query = "SELECT TS_START AS \"DT\", AVG(AVG) BY NAME FROM aggregates WHERE name IN ('{}') AND ts>='{}' AND ts<='{}' AND period = {} GROUP BY \"DT\" ORDER BY \"DT\";\x00".format("','".join(tags),tstart,tend,period).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res

	def history(self,args):
		"""
		Sampling instantaneous values by time intervals
		"""
		tags, tstart tend, period = parseargs1(args)
		query = "SELECT TS AS \"DT\", AVG(VALUE) BY NAME FROM HISTORY WHERE name IN ('{}') AND ts>='{}' AND ts<='{}' AND period = {} GROUP BY \"DT\" ORDER BY \"DT\";\x00".format("','".join(tags),tstart,tend,period).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res

	def max(self,args):
		# Sampling maximum values by time intervals
		tags, tstart tend, period = parseargs1(args)
		query = "SELECT TS_START AS \"DT\", MAX(MAX) BY NAME FROM aggregates WHERE name IN ('{}') AND ts>='{}' AND ts<='{}' AND period = {} GROUP BY \"DT\" ORDER BY \"DT\";\x00".format("','".join(tags),tstart,tend,period).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res

	def sum(self,args):
		# Sampling of the integral over time intervals
		tags, tstart tend, period = parseargs1(args)
		query = "SELECT TS_START AS \"DT\", SUM(SUM/3600) BY NAME FROM aggregates WHERE name IN ('{}') AND ts>='{}' AND ts<='{}' AND period = {} GROUP BY \"DT\" ORDER BY \"DT\";\x00".format("','".join(tags),tstart,tend,period).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res

	def sumstepped(self,args):
		# Sampling of the stepped integral over time intervals
		atags, tstart tend, period = parseargs1(args)
		query = "SELECT TS_START AS \"DT\", SUM(SUM/3600) BY NAME FROM aggregates WHERE name IN ('{}') AND ts>='{}' AND ts<='{}' AND stepped=1 AND period = {} GROUP BY \"DT\" ORDER BY \"DT\";\x00".format("','".join(tags),tstart,tend,period).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res

	def motors(self,args):
		# Sampling the running time of the time engine
		tags, tstart tend, period = parseargs1(args)
		query = "SELECT TS_START AS \"DT\", SUM(SUM/7200) BY NAME FROM aggregates WHERE name IN ('{}') AND ts>='{}' AND ts<='{}' AND stepped=1 AND period = {} GROUP BY \"DT\" ORDER BY \"DT\";\x00".format("','".join(tags),tstart,tend,period).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res

	def discrete(self,args):
		# Only 1 tag
		args = parse_qs(args)
		tstart = args['tstart'][0]
		tend = args['tend'][0]
		tags = args['tag'][0]
		if ((re.match(re_date,tstart)==None)|(re.match(re_date,tend)==None)):
			raise Exception("Неверный формат даты")
		if (re.match(re_tags,tags)==None):
			raise Exception("Неверный формат")
		tstart = datetimeconvert(tstart)
		tend = datetimeconvert(tend)
		tags = tags.split(",")
		query = "SELECT IP_TREND_TIME AS \"DT\", IP_TREND_VALUE as \"V\" from IP_DISCRETEDEF where NAME IN ('{}') and IP_TREND_TIME between '{}' and '{}' ORDER BY \"DT\";\x00".format("','".join(tags),tstart,tend).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res
		
	def trend(self,args):
		"""
		Selection from raw records in the database. Regular intervals + records by aperture
		Only 1 tag
		"""
		args = parse_qs(args)
		tstart = args['tstart'][0]
		tend = args['tend'][0]
		tags = args['tag'][0]
		if ((re.match(re_date,tstart)==None)|(re.match(re_date,tend)==None)):
			raise Exception("Wrong date format")
		if (re.match(re_tags,tags)==None):
			raise Exception("Wrong tags format")
		tstart = datetimeconvert(tstart)
		tend = datetimeconvert(tend)
		tags = tags.split(",")
		query = "SELECT IP_TREND_TIME AS \"DT\", IP_TREND_VALUE as \"V\" from IP_ANALOGDEF where NAME IN ('{}') and IP_TREND_TIME between '{}' and '{}' ORDER BY \"DT\";\x00".format("','".join(tags),tstart,tend).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res

	def analogdef(self,args):
		"""
		latest values
		"""
		args = parse_qs(args)
		tags = args['tags'][0]
		if (re.match(re_tags,tags)==None):
			raise Exception("Wrong tags format")
		tags = tags.split(",")

		query = "SELECT name as \"tag\", IP_INPUT_VALUE as \"V\", IP_VALUE_TIME as \"DT\", IP_VALUE_QUALITY as \"Q\" FROM IP_AnalogDef WHERE name in ('{}');\x00".format("','".join(tags)).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res)
		res=res.replace("\"Good\"","192").replace("\"Bad Tag\"","0").replace("\"Bad\"","16").replace("\"Suspect\"","3000")
		res=res.encode('utf-8')
		
		return res

	def discretedef(self,args):
		"""
		latest values
		"""
		args = parse_qs(args)
		tags = args['tags'][0]
		if (re.match(re_tags,tags)==None):
			raise Exception("Wrong tags format")
		tags = tags.split(",")

		query = "SELECT name as \"tag\", IP_INPUT_VALUE as \"V\", IP_VALUE_TIME as \"DT\", IP_VALUE_QUALITY as \"Q\" FROM IP_DiscreteDef WHERE name in ('{}');\x00".format("','".join(tags)).encode()
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res)
		res=res.replace("\"Good\"","192").replace("\"Bad Tag\"","0").replace("\"Bad\"","16").replace("\"Suspect\"","3000")
		res=res.replace("\"Running\"","3").replace("\"Run\"","4").replace("\"Opened\"","4").replace("\"Opening\"","3").replace("\"Stopping\"","1").replace("\"Closing\"","1").replace("\"Stop\"","0").replace("\"Closed\"","0")
		res=res.encode('utf-8')
		return res

	def query(self,args):
		"""
		raw query for future use
		http://127.0.0.1/query?query=SELECT 1
		"""
		args = parse_qs(args)
		query = (args['query'][0]+";\x00").encode()
		log.info(query)
		code, length, res = self.sqlquery(query)
		res = sqlplus.tojson(res).encode('utf-8')
		return res

	def do_GET(self):
		if (self.path == "/favicon.ico"):
			self.send_response(404)
			self.send_header('Content-type', 'text/plain, charset=utf-8')
			self.end_headers()
			self.wfile.write(b"..!..")
			return
		try:
			p = self.path.split("?")
			if (not hasattr(self,p[0][1:])): raise AttributeError("Method not allowed "+p[0][1:])
			method_to_call = getattr(self, p[0][1:])
			result = method_to_call(p[1])
			self.send_response(200)
			self.send_header('Content-type', 'application/json, charset=utf-8')
			self.end_headers()
			self.wfile.write(result)
		except AttributeError as e:
			self.send_response(405)
			self.send_header('Content-type', 'text/plain')
			self.end_headers()
			self.wfile.write(e.args[0].encode())
			# log.debug(e)
			raise e
		except TimeoutError as e:
			self.send_response(523)
			self.send_header('Content-type', 'text/plain')
			self.end_headers()
			self.wfile.write(b"Database TimeoutError")
			# log.debug(e)
			raise e
		except Exception as e:
			self.send_response(500)
			self.send_header('Content-type', 'text/plain')
			self.end_headers()
			self.wfile.write(b"")
			raise e

	def do_POST(self):
		pass

def log_init():
	log = logging.getLogger('webserver')
	log.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	#file log
	tofile = logging.FileHandler('webserver.log','a')
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

def datetimeconvert(t):
	return time.strftime("%d-%b-%y %H:%M",time.strptime(t,"%Y-%m-%d %H:%M"))

def periodconvert(period): # period conversion for web
	if (period=="1"): return "18000" 	#30 min
	if (period=="2"): return "36000"	#1 hour
	if (period=="3"): return "864000"	#1 day

	#UPD 2019-10 add periods for future use
	if (period=="4"): return "10"		#1 second
	if (period=="5"): return "600"		#1 min
	if (period=="6"): return "3000"		#5 min
	raise AttributeError("Incorrect period value")

try:
	log = log_init()
	if (len(sys.argv)>1) :PORT = int(sys.argv[1])
	webserver = ThreadedHTTPServer((HOST,PORT),webServerHandler)
	# webserver.socket = ssl.wrap_socket(webserver.socket, server_side=True, certfile='key.pem', ssl_version=ssl.PROTOCOL_TLS)
	log.info("Listen %s:%d",HOST, PORT)
	# os.startfile("http://127.0.0.1:%d" % PORT)
	webserver.serve_forever()
except KeyboardInterrupt as e:
	sys.exit()
except Exception as e:
	log.error("Error: %s",e.args)

