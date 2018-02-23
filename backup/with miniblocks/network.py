from __future__ import with_statement
import socket, struct, os, threading, random, SocketServer, socket, time
from globals import Globals
from crypto import Crypto

class NetworkCodes:
	IDENTIFY= 0x0001
	NEW_BLOCK= 0xB000
	GET_BLOCK= 0xB001
	SEND_BLOCK= 0xB002
	NEXT_WORKER= 0xB100

class NetworkFieldsSize:
	MESSAGE_TYPE= 2
	TIMESTAMP= 10
	LENGTH= 4
	SIGNATURE_LENGTH= 2
	BLOCK_HASH= 32
	STATUS= 1
	NEXT_BLOCK= 1
	COMPLETE_BLOCK= 1
	NODE_ID= 1

class NetworkStatus:
	LATEST= 2
	FOUND= 1
	NOT_FOUND= 0

class NodeLink(threading.Thread):

	def __init__(self, CONFIG, DATABASE, CRYPTO, BLOCK_MANAGER, node, open_connection=True, new_socket=None):
		threading.Thread.__init__(self)
		self.CONFIG = CONFIG
		self.DATABASE = DATABASE
		self.CRYPTO = CRYPTO
		self.BLOCK_MANAGER = BLOCK_MANAGER
		self.LOCK = threading.Lock()
		self.node = node['node']
		self.host = node['host']
		self.port = node['port']
		print 'Node link created for node:',self.node
		if open_connection:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				print 'attempting to connect'
				self.socket.settimeout(5)
				self.socket.connect((self.host, self.port))
				self.socket.settimeout(None)
				print 'socket is open, starting identification process'
				now = int(time.time())
				signature = self.CRYPTO.sign(str(self.node)+str(now))
				message = struct.pack('H', NetworkCodes.IDENTIFY) + self.CONFIG['id'] + str(now) + struct.pack('H', len(signature)) + signature
				self.socket.send(message)
				self.connected = True
			except (socket.error, socket.timeout):
				print 'Timeout, could not connect to node:', self.node
				self.connected = False
		else:
			print 'Reusing existing socket'
			self.socket = new_socket
			self.connected = True
		self.start()


	def run(self):
		print '\nStarted thread for node link:', self.node
		while self.connected:
			code = self.socket.recv(NetworkFieldsSize.MESSAGE_TYPE)
			if code == '':
				with self.LOCK:
					self.connected = False
					break
			code = struct.unpack('H', code)

			if code == NEW_BLOCK:
				message = self.socket.recv(NetworkFieldsSize.BLOCK_HASH+NetworkFieldsSize.LENGTH)
				if len(message) != (NetworkFieldsSize.BLOCK_HASH+NetworkFieldsSize.LENGTH):
					with self.LOCK:
						self.connected = False
						break
				hash = message[:NetworkFieldsSize.BLOCK_HASH]
				#save incomming block
				length = struct.unpack('L', message[NetworkFieldsSize.BLOCK_HASH+1:])
				if length < Globals.MIN_BLOCK_SIZE:
					with self.LOCK:
						self.connected = False
						break
				block = open(self.CONFIG['blocks_dir']+hash+'.temp', 'wb+')
				received = 0
				while received < length:
					if (length - received) < 4096:
						buffer = self.socket.recv((length - received))
					else:
						buffer = self.socket.recv(4096)
					if buffer == '':
						with self.LOCK:
							self.connected = False
							break
					block.write(buffer)
					received += len(buffer)
				block.flush()
				os.fsync(block)
				file_hash = self.CRYPTO.hash_file(block)
				block.close()
				#retrieve signature
				length = self.socket.recv(NetworkFieldsSize.SIGNATURE_LENGTH)
				if length != NetworkFieldsSize.SIGNATURE_LENGTH:
					with self.LOCK:
						self.connected = False
						break
				length = struct.unpack('H',length)
				signature = self.socket.recv(length)
				if len(signature) != length:
					with self.LOCK:
						self.connected = False
						break
				#verify message
				if self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+self.node, hash+file_hash, signature, 'hex'):
					os.rename(self.CONFIG['blocks_dir']+hash+'.temp', self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
				else:
					os.remove(self.CONFIG['blocks_dir']+hash+'.temp')
				side_thread = threading.Thread(self.BLOCK_MANAGER.register_header, self.node, hash)
				side_thread.start()
				#end of NEW_BLOCK

			elif code == GET_BLOCK:
				message = self.socket.recv(NetworkFieldsSize.NEXT_BLOCK +NetworkFieldsSize.COMPLETE_BLOCK +NetworkFieldsSize.BLOCK_HASH)
				if len(message) != (NetworkFieldsSize.NEXT_BLOCK +NetworkFieldsSize.COMPLETE_BLOCK +NetworkFieldsSize.BLOCK_HASH):
					with self.LOCK:
						self.connected = False
						break
				next_block = int(message[:NetworkFieldsSize.NEXT_BLOCK])
				complete_block = int(message[NetworkFieldsSize.NEXT_BLOCK+1:NetworkFieldsSize.NEXT_BLOCK+1+NetworkFieldsSize.COMPLETE_BLOCK])
				hash = message[NetworkFieldsSize.NEXT_BLOCK+NetworkFieldsSize.COMPLETE_BLOCK+2:]

				if not self.CONFIG['synchronized']:
					[next_hash, response] = self.DATABASE.next_block(hash)
					#his block is either our latest known block or we don't have it
					if next_hash == hash or not response:
						if not self.send_message(NetworkCodes.SEND_BLOCK, message+NetworkStatus.LATEST, True):
							with self.LOCK:
								self.connected = False
								break
						if response and self.send_message(NetworkCodes.GET_BLOCK, '10'+hash):
							print 'sent request with last known block:', to_send
							self.CONFIG['synchronized'] = True
						else:
							with self.LOCK:
								self.connected = False
								break
					#we have the next block, so we're synchronized, respond to node and start our server
					else:
						self.CONFIG['synchronized'] = True
						self.send_file(NetworkCodes.SEND_BLOCK, message+NetworkStatus.FOUND, self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION, True)
						self.BLOCK_MANAGER.synchronized(hash)
				else:
					if next_block:
						[next_hash, response] = self.DATABASE.next_block(hash)
						if not response:
							if not self.send_message(NetworkCodes.SEND_BLOCK, message+NetworkStatus.NOT_FOUND, True):
								with self.LOCK:
									self.connected = False
									break
							continue
						elif next_hash == hash:
							if not self.send_message(NetworkCodes.SEND_BLOCK, message+NetworkStatus.LATEST, True):
								with self.LOCK:
									self.connected = False
									break
							continue
						else:
							hash = next_hash

					if complete_block:
						block = self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION
					else:
						block = self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION
					self.send_file(NetworkCodes.SEND_BLOCK, message+NetworkStatus.FOUND, block, True)
				#end of GET_BLOCK

			elif code == SEND_BLOCK:
				message = self.socket.recv(NetworkFieldsSize.NEXT_BLOCK + NetworkFieldsSize.COMPLETE_BLOCK + NetworkFieldsSize.BLOCK_HASH + NetworkFieldsSize.STATUS)
				if len(message) != (NetworkFieldsSize.NEXT_BLOCK + NetworkFieldsSize.COMPLETE_BLOCK + NetworkFieldsSize.BLOCK_HASH + NetworkFieldsSize.STATUS):
					with self.LOCK:
						self.connected = False
						break
				next_block = int(message[:NetworkFieldsSize.NEXT_BLOCK])
				complete_block = int(message[NetworkFieldsSize.NEXT_BLOCK+1:NetworkFieldsSize.NEXT_BLOCK+NetworkFieldsSize.COMPLETE_BLOCK+1])
				hash = message[NetworkFieldsSize.NEXT_BLOCK+NetworkFieldsSize.COMPLETE_BLOCK+2:NetworkFieldsSize.NEXT_BLOCK+NetworkFieldsSize.COMPLETE_BLOCK+NetworkFieldsSize.BLOCK_HASH+2]
				status = int(message[NetworkFieldsSize.NEXT_BLOCK+NetworkFieldsSize.BLOCK_HASH+3:])

				if status == NetworkStatus.FOUND:
					#save incomming block
					length = self.socket.recv(NetworkFieldsSize.LENGTH)
					if len(message) != NetworkFieldsSize.LENGTH:
						with self.LOCK:
							self.connected = False
							break
					length = struct.unpack('L', length)
					if length < Globals.MIN_BLOCK_SIZE:
						with self.LOCK:
							self.connected = False
							break
					#verify that we don't already have the same block
					if complete_block:
						extension = Globals.BLOCK_EXTENSION
					else:
						extension = Globals.SIMPLIFIED_BLOCK_EXTENSION
					if not os.path.isfile(self.CONFIG['blocks_dir']+hash+extension) or os.path.getsize(self.CONFIG['blocks_dir']+hash+extension) != length:
						block = open(self.CONFIG['blocks_dir']+hash+'.temp', 'wb+')
						received = 0
						while received < length:
							if (length - received) < 4096:
								buffer = self.socket.recv((length - received))
							else:
								buffer = self.socket.recv(4096)
							if buffer == '':
								with self.LOCK:
									self.connected = False
									break
							block.write(buffer)
							received += len(buffer)
						block.flush()
						os.fsync(block)
						message += self.CRYPTO.hash_file(block)
						block.close()
						existing_block = False
					else:
						block = open(self.CONFIG['blocks_dir']+hash+extension, 'rb')
						message += self.CRYPTO.hash_file(block)
						block.close()
						existing_block = True

				#retrieve signature
				length = self.socket.recv(NetworkFieldsSize.SIGNATURE_LENGTH)
				if length != NetworkFieldsSize.SIGNATURE_LENGTH:
					with self.LOCK:
						self.connected = False
						break
				length = struct.unpack('H',length)
				signature = self.socket.recv(length)
				if len(signature) != length:
					with self.LOCK:
						self.connected = False
						break

				#verify message
				if self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+self.node, message, signature, 'hex'):
					if status == NetworkStatus.FOUND:
						if complete_block and not existing_block:
							os.rename(self.CONFIG['blocks_dir']+hash+'.temp', self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
						else:
							#inform we have a new block, as to register header
							if not existing_block:
								os.rename(self.CONFIG['blocks_dir']+hash+'.temp', self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION)
							side_thread = threading.Thread(self.BLOCK_MANAGER.register_header, self.node, hash)
							side_thread.start()
						if next_block:
							#fetch next block, since this wasn't a specific request for a missing block
							message = str(next_block)+str(complete_block)+hash
							if not self.send_message(NetworkCodes.GET_BLOCK, message):
								with self.LOCK:
									self.connected = False
									break
					elif status == NetworkStatus.LATEST:
						#signal we have the latest block and can therefore start server
						self.CONFIG['synchronized'] = True
						self.BLOCK_MANAGER.synchronized(hash)
				else:
					if status == NetworkStatus.FOUND:
						os.remove(self.CONFIG['blocks_dir']+hash+'.temp')
					with self.LOCK:
						self.connected = False
						break
				#end of SEND_BLOCK

			elif code == NEXT_WORKER:
				message = self.socket.recv(NetworkFieldsSize.SIGNATURE_LENGTH)
				if message != NetworkFieldsSize.SIGNATURE_LENGTH:
					with self.LOCK:
						self.connected = False
						break
				timestamp = int(message[:NetworkFieldsSize.TIMESTAMP])

				#retrieve signature
				length = struct.unpack('H',message[NetworkFieldsSize.TIMESTAMP+1:])
				signature = self.socket.recv(length)
				if len(signature) != length:
					with self.LOCK:
						self.connected = False
						break
				#verify message
				if self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+self.node, timestamp, signature, 'hex'):
					#send timestamp and node to block manager
					self.BLOCK_MANAGER.update_worker(self.node, timestamp)
				else:
					with self.LOCK:
						self.connected = False
						break
				#end of NEXT_WORKER

			else:
				#message type not recognized, terminate connection
				with self.LOCK:
					self.connected = False
		with self.LOCK:					
			self.socket.close()
		print 'Connection closed for node:', self.node

	def send_message(self, type, message, sign=False):
		to_send = struct.pack('H', type)
		to_send += message
		if sign:
			signature = self.CRYPTO.sign(message)
			to_send += struct.pack('H', len(signature))
			to_send += signature

		total_sent = 0
		with self.LOCK:
			while total_sent < len(to_send):
				sent = self.socket.send(to_send[total_sent:])
				if not sent:
					return False
				total_sent += sent
		return True


	def send_file(self, type, message, file, sign=False):
		to_send = struct.pack('H', type)
		to_send += message
		with self.LOCK:
			try:
				#retrieve file's data
				file_size = os.path.getsize(file)
				to_send += file_size
				file_data = open(file, 'rb')
				to_send += file_data.read(4096 - len(to_send))

				#start sending data
				total_sent = 0
				while total_sent < len(to_send)+file_size:
					sent = self.socket.send(to_send[total_sent:])
					if not sent:
						return False
					total_sent += sent
					if total_sent % 4096 == 0:
						to_send = file_data.read(4096)
			except IOError:
				return False
			finally:
				file_data.close()

			if sign:
				#send data's signature
				file_hash = self.CRYPTO.hash_file(file)
				signature = self.CRYPTO.sign(message+file_hash)
				to_send = struct.pack('H', len(signature))
				to_send += signature

				total_sent = 0
				while total_sent < len(to_send):
					sent = self.socket.send(to_send[total_sent:])
					if not sent:
						return False
					total_sent += sent
		return True


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class NetworkManager():

	def __init__(self, CONFIG, DATABASE, CRYPTO):
		self.CONFIG = CONFIG
		self.DATABASE = DATABASE
		self.CRYPTO = CRYPTO
		self.LOCK = threading.Lock()
		print 'Network Manager created'

	def shutdown(self):
		with self.LOCK:
			self.monitoring.cancel()
			print 'shutting down network server'
			self.server.shutdown()
			for node in self.nodes:
				print 'closing connection with node', node
				self.nodes[node].socket.close()
				self.nodes[node].connected = False

	def connect_to_all(self, BLOCK_MANAGER):
		self.BLOCK_MANAGER = BLOCK_MANAGER
		self.nodes = {}
		print 'Initializing individual connections'
		for node in self.CONFIG['nodes']:
			#instantiate nodelink and start listening
			print '\nCreating node link for node:',node['node']
			self.nodes[node['node']] = NodeLink(self.CONFIG, self.DATABASE, self.CRYPTO, self.BLOCK_MANAGER, node)
		print '\nAll nodes have been tried, starting synchronization process'
		#request next block
		to_send = '1'
		#request header only
		to_send += '0'
		#add lastest known block
		to_send += self.DATABASE.current_block()
		#synchronize blocks
		if self.new_request(NetworkCodes.GET_BLOCK, to_send):
			print 'sent request with last known block:', to_send
			self.CONFIG['synchronized'] = True
		elif self.CONFIG['debug']:
			#proceed
			self.CONFIG['synchronized'] = True
		else:
			self.CONFIG['synchronized'] = False

		#start listening to connections
		print 'Starting Network server'
		self.server = ThreadedTCPServer((self.CONFIG['hostname'], self.CONFIG['network_port']), SocketHandler)
		self.server.CONFIG = self.CONFIG
		self.server.DATABASE = self.DATABASE
		self.server.CRYPTO = self.CRYPTO
		self.server.BLOCK_MANAGER = self.BLOCK_MANAGER
		self.server.nodes = self.nodes
		#start links monitoring
		print 'Network Server created, serving forever'
		self.server_thread = threading.Thread(target=self.server.serve_forever)
		self.server_thread.start()
		print 'Starting connections monitoring task'
		self.monitoring = threading.Timer(30.0, self.check_links)
		self.monitoring.start()
		if self.CONFIG['debug'] and	self.CONFIG['synchronized']:
			self.BLOCK_MANAGER.synchronized(self.DATABASE.current_block())

	def is_connected(self, node):
		if self.nodes[node].connected:
			return True
		return False

	def check_links(self):
		print '\nMonitoring connections\n'
		with self.LOCK:
			for id in self.nodes:
				if not self.nodes[id].connected:
					host = self.nodes[id].host
					port = self.nodes[id].port
					node = {"node": id, "host": host, "port": port}
					del self.nodes[id]
					self.nodes[id] = NodeLink(self.CONFIG, self.DATABASE, self.CRYPTO, self.BLOCK_MANAGER, node)

	def new_request(self, type, message):
		#check connected nodes
		connected_nodes = []
		with self.LOCK:
			for node in self.nodes:
				if self.nodes[node].connected:
					connected_nodes.append(node)
			#randomly pick a node
			while 1:
				if len(connected_nodes) == 0:
					break
				random_node = random.choice(connected_nodes)
				if self.nodes[random_node].send_message(type, message):
					return True
				connected_nodes.remove(random_node)
		return False

	def broadcast_duty(self):
		timestamp = int(time.time())
		signature = self.CRYPTO.sign(str(timestamp))
		to_send = str(timestamp)+str(len(signature))+signature
		with self.LOCK:
			for node in self.nodes:
				if self.nodes[node].connected:
					self.nodes[node].send_message(NetworkCodes.NEXT_WORKER, to_send)

	#lacks performance since the file reading/hashing and signing is being repeated n times....
	def broadcast_block(self, hash):
		#send simplified block first
		with self.LOCK:
			for node in self.nodes:
				if self.nodes[node].connected:
					self.nodes[node].send_file(NetworkCodes.NEW_BLOCK, hash, self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION, True)
		#then complete block
		with self.LOCK:
			for node in self.nodes:
				if self.nodes[node].connected:
					self.nodes[node].send_file(NetworkCodes.NEW_BLOCK, hash, self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, True)


class SocketHandler(SocketServer.BaseRequestHandler):
	def handle(self):	
		print '\nIncomming connection request from:',self.request.getpeername()
		try:
			self.request.settimeout(5)
			message = self.request.recv(NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID+NetworkFieldsSize.TIMESTAMP+NetworkFieldsSize.SIGNATURE_LENGTH)
			if len(message) != NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID+NetworkFieldsSize.TIMESTAMP+NetworkFieldsSize.SIGNATURE_LENGTH:
				return
			code = struct.unpack('H', message[0:NetworkFieldsSize.MESSAGE_TYPE])
			if code != NetworkCodes.IDENTIFY:
				return
			id = int(message[NetworkFieldsSize.MESSAGE_TYPE+1:NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID+1])
			timestamp = int(message[NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID+2:NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID+NetworkFieldsSize.TIMESTAMP+2])
			length = struct.unpack('H', message[-NetworkFieldsSize.SIGNATURE_LENGTH:])

			if int(time.time()) - timestamp > Globals.MAXIMUM_IDENTIFICATION_DELAY:
				return
			print 'Message format validated, verifying signature'
			signature = self.request.recv(length)
			if len(signature) == length and self.server.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+id, self.server.CONFIG['id']+timestamp, signature, 'hex'):
				print 'connection authenticated, creating node link'
				LOCK = threading.Lock()
				with LOCK:
					for node in self.server.CONFIG['nodes']:
						if node['node'] == id:
							self.server.nodes[node['node']] = NodeLink(self.server.CONFIG, self.server.DATABASE, self.server.CRYPTO, self.server.BLOCK_MANAGER, node, False, self.request)
							break
				while self.server.nodes[node['node']].connected:
					time.sleep(0.5)
		except socket.timeout:
			print 'connection timeout reached'


