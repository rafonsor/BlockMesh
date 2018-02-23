import threading, BaseHTTPServer, ssl
from globals import Globals


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_HEAD(self):
		self.send_response(404)
		self.end_headers()

	def do_GET(self):
		self.send_response(404)
		self.end_headers()

	def do_PUT(self):
		self.do_POST()

	def do_POST(self):
		if self.path == Globals.NEW_ITEM_PATH:
			#new item request
			length = self.headers['Content-Length']
			request = json.load(self.rfile.read(length).decode('utf-8'))
			if 'resource' in request and 'entity' in request and 'data' in request and 'signature' in request:
				#valid request
				resource = request['resource'].upper()
				entity = request['resource'].upper()
				hash = self.server.CRYPTO.hash(request['data'])
				if encoded_key and self.server.CRYPTO.verify(resource, entity, hash, signature, 'base64'):
					#identity confirmed
					if (request['data'][:1] == '{' and request['data'][-1:] == '}') or (request['data'][:1] == '[' and request['data'][-1:] == ']'):
						item = '{"Data":'+request['data']+',"Entity":"'+entity+'","Signature":"'+signature+'"}'
					else:
						item = '{"Data":"'+request['data']+'","Entity":"'+entity+'","Signature":"'+signature+'"}'
					if self.server.BLOCKS_MANAGER.new_item(resource, hash, item):
						#item inserted
						self.send_response(200)
						self.send_header('Content-Type', 'application/json')
						self.end_headers()
						self.wfile.write('{"item":"'+hash+'","status":"accepted","node":'+self.server.CONFIG['id']+'}')
					else:
						#item not saved to a block
						self.send_response(500)
						self.send_header('Content-Type', 'application/json')
						self.end_headers()
						self.wfile.write('{"item":"'+hash+'","status":"refused","node":'+self.server.CONFIG['id']+'}')
				else:
					#invalid signature
					self.send_response(401)
					self.send_header('Content-Type', 'application/json')
					self.end_headers()
					self.wfile.write('{"item":"'+hash+'","status":"unauthorized","node":'+self.server.CONFIG['id']+'}')
			else:
				#incomplete request
				self.send_response(400)
				self.send_header('Content-Type', 'application/json')
				self.end_headers()
				self.wfile.write('{"item":"'+json.dumps(request)+'","status":"bad request","node":'+self.server.CONFIG['id']+'}')
		else:
			#request type not found
			self.send_response(404)
			self.end_headers()


class Server(threading.Thread):

	def __init__(self, CONFIG, CRYPTO):
		threading.Thread.__init__(self)
		self.CONFIG = CONFIG
		self.CRYPTO = CRYPTO
		print 'Server created'

	def shutdown(self):
		print 'shutting down server'
		self.running = False

	def set_blocks_manager(self, BLOCKS_MANAGER):
		print 'Server received block manager'
		self.BLOCKS_MANAGER = BLOCKS_MANAGER

	def run(self):
		#create http server
		self.httpd = BaseHTTPServer.HTTPServer((self.CONFIG['hostname'], int(self.CONFIG['server_port'])), Handler)
		#add SSL, all certificates must be in PEM format
		ssl_options = {
			'keyfile': self.CONFIG['ssl_private_key'],
			'certfile': self.CONFIG['ssl_certificate'],
			'server_side': True,
			'ssl_version': ssl.PROTOCOL_TLSv1_2,
			'ca_certs': self.CONFIG['ca_certificate'],
			'ciphers': 'DHE-RSA-AES256-CCM8:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DH-RSA-AES256-GCM-SHA384:DH-RSA-AES256-SHA256:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-CAMELLIA256-SHA384:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:ECDH-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-RSA-CAMELLIA256-SHA384'
		}
		self.httpd.socket = ssl.wrap_socket(self.httpd.socket, **ssl_options)
		#pass variables to handler
		self.httpd.CONFIG = self.CONFIG
		self.httpd.CRYPTO = self.CRYPTO
		self.httpd.BLOCKS_MANAGER = self.BLOCKS_MANAGER
		#run server
		self.running = True
		while self.running:
			self.httpd.handle_request()



