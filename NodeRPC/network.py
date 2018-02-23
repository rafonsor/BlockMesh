from __future__ import with_statement
import socket, struct, os, threading, random, SocketServer, socket, time
from globals import Globals
from crypto import Crypto

class NetworkCodes:
	IDENTIFY= 0xA001
	NEW_BLOCK= 0xB000
	GET_BLOCK= 0xB001
	SEND_BLOCK= 0xB002
	NEXT_WORKER= 0xB100

class NetworkFieldsSize:
	MESSAGE_TYPE= 2
	TIMESTAMP= 10
	LENGTH= 4
	SIGNATURE_LENGTH= 2
	BLOCK_HASH= 64
	STATUS= 1
	NEXT_BLOCK= 1
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
				signature = self.CRYPTO.sign(str(self.node)+str(now), 'hex')
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
		print 'connected: ', self.connected
		while self.connected:
			try:
				print 'waiting for next message'
				code = self.socket.recv(NetworkFieldsSize.MESSAGE_TYPE)
				if len(code) != NetworkFieldsSize.MESSAGE_TYPE:
					with self.LOCK:
						self.connected = False
						break
				code = struct.unpack('H', code)[0]
				print 'new message received: ', code
				if code == NetworkCodes.NEW_BLOCK:
					print 5
					message = self.socket.recv(NetworkFieldsSize.BLOCK_HASH+NetworkFieldsSize.LENGTH)
					if len(message) != (NetworkFieldsSize.BLOCK_HASH+NetworkFieldsSize.LENGTH):
						print 1
						with self.LOCK:
							self.connected = False
							break
					print 2
					hash = message[:NetworkFieldsSize.BLOCK_HASH]
					#save incomming block
					print message
					print hash
					length = struct.unpack('I', message[-NetworkFieldsSize.LENGTH:])[0]
					if length < Globals.MIN_BLOCK_SIZE:
						print 3
						with self.LOCK:
							self.connected = False
							break
					print length
					block = open(self.CONFIG['blocks_dir']+hash+'.temp', 'wb+')
					print 4
					received = 0
					while received < length:
						print 77
						if (length - received) < 4096:
							buffer = self.socket.recv((length - received))
						else:
							buffer = self.socket.recv(4096)
						if buffer == '':
							with self.LOCK:
								self.connected = False
								break
						print 'writting:', buffer
						block.write(buffer)
						received += len(buffer)
					print 8
					block.flush()
					os.fsync(block)
					print 9
					file_hash = self.CRYPTO.hash_file(block)
					block.close()
					print 10
					#retrieve signature
					length = self.socket.recv(NetworkFieldsSize.SIGNATURE_LENGTH)
					print 11
					print length
					if length != NetworkFieldsSize.SIGNATURE_LENGTH:
						with self.LOCK:
							print 12
							self.connected = False
							break
					print 13
					length = struct.unpack('H',length)[0]
					signature = self.socket.recv(length)
					print 14
					if len(signature) != length:
						with self.LOCK:
							print 15
							self.connected = False
							break
					#verify message
					if self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+str(self.node), hash+file_hash, signature, 'hex'):
						print 16
						os.rename(self.CONFIG['blocks_dir']+hash+'.temp', self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
					else:
						print 17
						os.remove(self.CONFIG['blocks_dir']+hash+'.temp')
					print 18
					side_thread = threading.Thread(self.BLOCK_MANAGER.register_header, self.node, hash)
					side_thread.start()
					#end of NEW_BLOCK

				elif code == NetworkCodes.GET_BLOCK:
					print 6
					message = self.socket.recv(NetworkFieldsSize.NEXT_BLOCK+NetworkFieldsSize.BLOCK_HASH)
					if len(message) != (NetworkFieldsSize.NEXT_BLOCK+NetworkFieldsSize.BLOCK_HASH):
						print 7
						with self.LOCK:
							self.connected = False
							break
					next_block = int(message[:NetworkFieldsSize.NEXT_BLOCK])
					print 8
					hash = message[-NetworkFieldsSize.BLOCK_HASH:]

					if not self.CONFIG['synchronized']:
						print 'a'
						[next_hash, response] = self.DATABASE.next_block(hash)
						#his block is either our latest known block or we don't have it
						if next_hash == hash or not response:
							print 'c'
							if not self.send_message(NetworkCodes.SEND_BLOCK, message+str(NetworkStatus.LATEST), True):
								with self.LOCK:
									self.connected = False
									break
							if response and self.send_message(NetworkCodes.GET_BLOCK, '1'+hash):
								print 'sent request with last known block:', hash
								self.CONFIG['synchronized'] = True
							else:
								print 'o'
								with self.LOCK:
									self.connected = False
									break
						#we have the next block, so we're synchronized, respond to node and start our server
						else:
							print't'
							self.CONFIG['synchronized'] = True
							self.send_file(NetworkCodes.SEND_BLOCK, message+str(NetworkStatus.FOUND), self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, True)
							self.BLOCK_MANAGER.synchronized(hash)
					else:
						print 'b'
						if next_block:
							print 'z'
							[next_hash, response] = self.DATABASE.next_block(hash)
							print 'z2'
							if not response:
								print 'e'
								if not self.send_message(NetworkCodes.SEND_BLOCK, message+str(NetworkStatus.NOT_FOUND), True):
									print 'e2'
									with self.LOCK:
										self.connected = False
										break
								continue
							elif next_hash == hash:
								print 'r'
								if not self.send_message(NetworkCodes.SEND_BLOCK, message+str(NetworkStatus.LATEST), True):
									print 'r2'
									with self.LOCK:
										self.connected = False
										break
								continue
							else:
								hash = next_hash
						print'y'
						self.send_file(NetworkCodes.SEND_BLOCK, message+str(NetworkStatus.FOUND), self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, True)
					#end of GET_BLOCK

				elif code == NetworkCodes.SEND_BLOCK:
					print 9
					message = self.socket.recv(NetworkFieldsSize.NEXT_BLOCK + NetworkFieldsSize.BLOCK_HASH + NetworkFieldsSize.STATUS)
					if len(message) != (NetworkFieldsSize.NEXT_BLOCK + NetworkFieldsSize.BLOCK_HASH + NetworkFieldsSize.STATUS):
						print 10
						with self.LOCK:
							self.connected = False
							break
					print 11
					next_block = int(message[:NetworkFieldsSize.NEXT_BLOCK])
					hash = message[NetworkFieldsSize.NEXT_BLOCK:NetworkFieldsSize.NEXT_BLOCK+NetworkFieldsSize.BLOCK_HASH]
					status = int(message[-NetworkFieldsSize.STATUS:])
					print 12
					existing_block = False
					if status == NetworkStatus.FOUND:
						print 13
						#save incomming block
						length = self.socket.recv(NetworkFieldsSize.LENGTH)
						if len(message) != NetworkFieldsSize.LENGTH:
							print 14
							with self.LOCK:
								self.connected = False
								break
						length = struct.unpack('I', length)[0]
						if length < Globals.MIN_BLOCK_SIZE:
							print 15
							with self.LOCK:
								self.connected = False
								break
						#verify that we don't already have the same block
						print 16
						if not os.path.isfile(self.CONFIG['blocks_dir']+hash+extension) or os.path.getsize(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION) != length:
							print 17
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
						else:
							print 18
							block = open(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, 'rb')
							message += self.CRYPTO.hash_file(block)
							block.close()
							existing_block = True

					print 19
					#retrieve signature
					length = self.socket.recv(NetworkFieldsSize.SIGNATURE_LENGTH)
					if len(length) != NetworkFieldsSize.SIGNATURE_LENGTH:
						print '199'
						with self.LOCK:
							self.connected = False
							break
					length = struct.unpack('H',length)[0]
					print 40
					signature = self.socket.recv(length)
					if len(signature) != length:
						print '200'
						with self.LOCK:
							self.connected = False
							break
					print 14

					#verify message
					if self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+self.node, message, signature, 'hex'):
						print 20
						print self.CONFIG['synchronized']
						print status
						if status == NetworkStatus.FOUND:
							print 205
							if not existing_block:
								print 21
								os.rename(self.CONFIG['blocks_dir']+hash+'.temp', self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION)
								side_thread = threading.Thread(self.BLOCK_MANAGER.register_header, self.node, hash)
								side_thread.start()
							if next_block:
								#fetch next block, since this wasn't a specific request for a missing block
								print 22
								if not self.send_message(NetworkCodes.GET_BLOCK, str(next_block)+hash):
									with self.LOCK:
										self.connected = False
										break
						elif status == NetworkStatus.LATEST or (status == NetworkStatus.NOT_FOUND and self.CONFIG['synchronized']):
							print 23
							#signal we have the latest block and can therefore start server
							self.CONFIG['synchronized'] = True
							self.BLOCK_MANAGER.synchronized(hash)
					else:
						print 24
						if status == NetworkStatus.FOUND:
							os.remove(self.CONFIG['blocks_dir']+hash+'.temp')
						with self.LOCK:
							self.connected = False
							break
					#end of SEND_BLOCK

				elif code == NetworkCodes.NEXT_WORKER:
					print 13
					message = self.socket.recv(NetworkFieldsSize.TIMESTAMP+NetworkFieldsSize.SIGNATURE_LENGTH)
					if message != NetworkFieldsSize.TIMESTAMP+NetworkFieldsSize.SIGNATURE_LENGTH:
						with self.LOCK:
							self.connected = False
							break
					timestamp = int(message[:NetworkFieldsSize.TIMESTAMP])

					#retrieve signature
					length = struct.unpack('H',message[-NetworkFieldsSize.SIGNATURE_LENGTH:])[0]
					signature = self.socket.recv(length)
					if len(signature) != length:
						with self.LOCK:
							self.connected = False
							break
					#verify message
					if self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+str(self.node), timestamp, signature, 'hex'):
						#send timestamp and node to block manager
						self.BLOCK_MANAGER.update_worker(self.node, timestamp)
					else:
						with self.LOCK:
							self.connected = False
							break
					#end of NEXT_WORKER

				else:
					#message type not recognized, terminate connection
					print 12
					with self.LOCK:
						self.connected = False
			except Exception as e:
				print 'exception raised at connection with node', self.node
				print e
				with self.LOCK:
					self.connected = False

		with self.LOCK:					
			self.socket.close()
		print 'Connection closed for node:', self.node

	def send_message(self, code, message, sign=False):
		to_send = struct.pack('H', code)
		to_send += message
		if sign:
			signature = self.CRYPTO.sign(message, 'hex')
			to_send += struct.pack('H', len(signature))
			to_send += signature

		print 'sending message to node',self.node,':',to_send
		total_sent = 0
		with self.LOCK:
			while total_sent < len(to_send):
				sent = self.socket.send(to_send[total_sent:])
				if not sent:
					return False
				total_sent += sent
		return True


	def send_file(self, code, message, file, sign=False):
		print 'sending file', file
		to_send = struct.pack('H', code)
		to_send += message
		with self.LOCK:
			print 'a'
			try:
				print 'b'
				#retrieve file's data
				file_size = os.path.getsize(file)
				to_send += struct.pack('I', file_size)
				print 'new block size: ', file_size, 'which packs to', struct.pack('I', file_size)
				print 'so far the message is: ', to_send
				file_data = open(file, 'rb')
				to_send += file_data.read(4096 - len(to_send))
				print len(to_send)
				print 'c'
				#start sending data
				total_sent = 0
				while total_sent < len(to_send)+file_size:
					print 'total sent', total_sent
					print to_send[total_sent:]
					sent = self.socket.send(to_send[total_sent:])
					print sent
					if not sent:
						print 'bb'
						return False
					total_sent += sent
					if total_sent % 4096 == 0:
						to_send = file_data.read(4096)

				print 'd'
				file_data.close()
			except IOError:
				print 'e'
				file_data.close()
				return False

			print 'f'
			if sign:
				print 'g'
				#send data's signature
				file_hash = self.CRYPTO.hash_file(file)
				signature = self.CRYPTO.sign(message+file_hash, 'hex')
				to_send = struct.pack('H', len(signature))
				to_send += signature
				print 'h'

				total_sent = 0
				while total_sent < len(to_send):
					print 'i'
					sent = self.socket.send(to_send[total_sent:])
					if not sent:
						print 'ff'
						return False
					total_sent += sent
		print 'j'
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
		#add lastest known block
		to_send += self.DATABASE.current_block()
		#synchronize blocks
		if self.online_count() and self.new_request(NetworkCodes.GET_BLOCK, to_send):
			print 'sent request with last known block:', to_send
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
		if self.CONFIG['debug'] and	self.online_count():
			self.CONFIG['synchronized'] = True
			self.BLOCK_MANAGER.previous_worker = self.CONFIG['id']
			self.BLOCK_MANAGER.next_worker = self.CONFIG['id']
			self.BLOCK_MANAGER.synchronized(self.DATABASE.current_block())

	def online_count(self):
		count = 0
		for node in self.nodes:
			if self.nodes[node].connected:
				count += 1
		return count

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
				else:
					print 'Already connected to node', id

	def new_request(self, code, message):
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
				if self.nodes[random_node].send_message(code, message):
					return True
				connected_nodes.remove(random_node)
		return False

	def broadcast_duty(self):
		timestamp = int(time.time())
		signature = self.CRYPTO.sign(str(timestamp), 'hex')
		to_send = str(timestamp)+str(len(signature))+signature
		with self.LOCK:
			for node in self.nodes:
				if self.nodes[node].connected:
					self.nodes[node].send_message(NetworkCodes.NEXT_WORKER, to_send)


	def broadcast_block(self, hash):
		#send latest block 
		print 1
		with self.LOCK:
			print 2
			for node in self.nodes:
				print 3
				if self.nodes[node].connected:
					print 'sending new block'
					self.nodes[node].send_file(NetworkCodes.NEW_BLOCK, hash, self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, True)


class SocketHandler(SocketServer.BaseRequestHandler):
	def handle(self):	
		print '\nIncomming connection request from:',self.request.getpeername()
		try:
			self.request.settimeout(5)
			message = self.request.recv(NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID+NetworkFieldsSize.TIMESTAMP+NetworkFieldsSize.SIGNATURE_LENGTH)
			self.request.settimeout(None)
			print message
			if len(message) != NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID+NetworkFieldsSize.TIMESTAMP+NetworkFieldsSize.SIGNATURE_LENGTH:
				return
			code = struct.unpack('H', message[:NetworkFieldsSize.MESSAGE_TYPE])[0]
			if code != NetworkCodes.IDENTIFY:
				return
			id = message[NetworkFieldsSize.MESSAGE_TYPE:NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID]
			timestamp = message[NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID:NetworkFieldsSize.MESSAGE_TYPE+NetworkFieldsSize.NODE_ID+NetworkFieldsSize.TIMESTAMP]
			length = struct.unpack('H', message[-NetworkFieldsSize.SIGNATURE_LENGTH:])[0]
			if time.time() - int(timestamp) > Globals.MAXIMUM_IDENTIFICATION_DELAY:
				return
			print 'Message format validated, verifying signature'
			signature = self.request.recv(length)
			if len(signature) == length and self.server.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+id, self.server.CONFIG['id']+str(timestamp), signature, 'hex'):
				print 'connection authenticated, creating node link'
				LOCK = threading.Lock()
				with LOCK:
					for node in self.server.CONFIG['nodes']:
						if node['node'] == id:
							self.server.nodes[node['node']] = NodeLink(self.server.CONFIG, self.server.DATABASE, self.server.CRYPTO, self.server.BLOCK_MANAGER, node, False, self.request)
							break
				while self.server.nodes[node['node']].connected:
					time.sleep(0.5)
			else:
				print "signature invalid"
		except socket.timeout:
			print 'connection timeout reached'


