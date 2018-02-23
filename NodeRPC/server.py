import threading, BaseHTTPServer, ssl, json
from globals import Globals


StatusCodes = {
	'200': 'accepted',
	'400': 'bad request',
	'401': 'unauthorized',
	'404': 'not found',
	'500': 'refused'}

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_HEAD(self):
		print 'Received a new HTTPS HEADER request'
		self.send_error(404)

	def do_GET(self):
		print 'Received a new HTTPS GET request'
		self.send_error(404)

	def do_PUT(self):
		self.do_POST()

	def do_POST(self):
		print 'Received a new HTTPS POST request'
		print self.path
		if self.path == Globals.NEW_ITEM_PATH:
			# try:
			print 'new submission'
			#new item request
			length = int(self.headers['Content-Length'])
			print length
			request = json.loads(self.rfile.read(length).decode('utf-8'))
			print request
			if 'resource' in request and 'entity' in request and 'data' in request and 'signature' in request:
				#valid request
				print 'valid request'
				resource = request['resource'].upper()
				entity = request['entity'].upper()
				hash = self.server.CRYPTO.hash(request['data'])
				if type(request['data']) == 'dict' or type(request['data']) == 'list':
					message = json.dumps(request['data'])
				else:
					message = request['data']
				if self.server.CRYPTO.verify(resource, entity, message, request['signature'], 'base64'):
					#identity confirmed
					print 'identity confirmed'
					block = self.DATABASE.check_item(resource, hash)
					if block:
						self.send_response(200)
						self.send_header('Content-Type', 'application/json')
						self.end_headers()
						self.wfile.write('{"item":"'+data+'","block":"'+block+'","status":"duplicate","node":'+self.server.CONFIG['id']+'}')
						return

					if (request['data'][:1] == '{' and request['data'][-1:] == '}') or (request['data'][:1] == '[' and request['data'][-1:] == ']'):
						print '1'
						item = '{"data":'+request['data']+',"entity":"'+entity+'","signature":"'+request['signature']+'"}'
					else:
						print '2'
						item = '{"data":"'+request['data']+'","entity":"'+entity+'","signature":"'+request['signature']+'"}'
					print '3'
					if self.server.BLOCKS_MANAGER.new_item(resource, hash, item):
						print 'item inserted'
						#item inserted
						self.send_response(200, hash)
					else:
						print 'item was not inserted'
						#item not saved to a block
						self.send_response(500, hash)
					print '4'
				else:
					#invalid signature
					self.send_response(401, hash)
			else:
				#incomplete request
				self.set_response(400, json.dumps(request))
			# except Exception as ex:
			# 	print 'exception:', ex
			# 	#error while reading bad request
			# 	self.send_error(400)
		print '5'
		#request type not found
		self.send_error(404)

	def set_response(self, code, data):
		self.send_response(code)
		self.send_header('Content-Type', 'application/json')
		self.end_headers()
		self.wfile.write('{"item":"'+data+'","status":"'+StatusCodes[str(code)]+'","node":'+self.server.CONFIG['id']+'}')


class Server(threading.Thread):

	def __init__(self, CONFIG, DATABASE, CRYPTO):
		threading.Thread.__init__(self)
		self.CONFIG = CONFIG
		self.DATABASE = DATABASE
		self.CRYPTO = CRYPTO
		print 'Server created'

	def shutdown(self):
		print 'shutting down server'
		self.httpd.shutdown()

	def set_blocks_manager(self, BLOCKS_MANAGER):
		print 'Server received block manager'
		self.BLOCKS_MANAGER = BLOCKS_MANAGER

	def run(self):
		#create http server
		self.httpd = BaseHTTPServer.HTTPServer((self.CONFIG['hostname'], int(self.CONFIG['server_port'])), Handler)
		print 'rest server created'
		#add SSL, all certificates must be in PEM format
		# ssl_options = {
		# 	'keyfile': self.CONFIG['private_key'],
		# 	'certfile': self.CONFIG['certificate'],
		# 	'server_side': True,
		# 	'ssl_version': ssl.PROTOCOL_TLSv1_2,
		# 	'ca_certs': self.CONFIG['ca_certificate'],
		# 	'ciphers': 'DHE-RSA-AES256-CCM8:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DH-RSA-AES256-GCM-SHA384:DH-RSA-AES256-SHA256:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-CAMELLIA256-SHA384:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:ECDH-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-RSA-CAMELLIA256-SHA384'
		# }
		# self.httpd.socket = ssl.wrap_socket(self.httpd.socket, **ssl_options)
		#pass variables to handler
		self.httpd.CONFIG = self.CONFIG
		self.httpd.CRYPTO = self.CRYPTO
		self.httpd.DATABASE = self.DATABASE
		self.httpd.BLOCKS_MANAGER = self.BLOCKS_MANAGER
		#run server
		print 'serving forever'
		self.httpd.serve_forever()



