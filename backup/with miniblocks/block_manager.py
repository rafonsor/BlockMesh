from __future__ import with_statement
import threading, random, string, json, time
from globals import Globals, Patterns
from network import NetworkCodes
from block import Block
from server import Server


class BlockManager(threading.Thread):

	def __init__(self, CONFIG, CRYPTO, DATABASE, NETWORK_MANAGER, SERVER):
		threading.Thread.__init__(self)
		self.CONFIG = CONFIG
		self.CRYPTO = CRYPTO
		self.DATABASE = DATABASE
		self.NETWORK_MANAGER = NETWORK_MANAGER
		self.SERVER = SERVER
		self.LOCK = threading.Lock()
		self.SYNC = False
		self.running = False
		self.next_worker = None
		self.previous_worker = None
		self.takeover_count = 0
		self.next_timestamp = 0
		print '\nBlock Manager created'

	def run(self):
		#set when is the next block due
		self.next_timestamp = (int(time.time()/Globals.BLOCK_CREATION_INTERVAL)+1)*Globals.BLOCK_CREATION_INTERVAL
		while self.running:
			now = int(time.time())
			if now >= self.next_timestamp:
				if self.next_worker == self.CONFIG['id']:
					created = False
					retries = 0
					while not created and retries < Globals.MAXIMUM_RETRIES:
						self.blocks[0].closed = True
						new_block = self.blocks[0].create_block(self.next_timestamp)
						#new block successfully created
						if new_block:
							created = True
							self.NETWORK_MANAGER.broadcast_block(new_block)
							self.blocks.pop(0)
							#no open blocks, create a new one
							if len(self.blocks) == 0 or sum(1 for block in self.blocks if block.connected) == 0:
								self.new_block()
							#add items to database							
							self.DATABASE.new_block(hash, self.load_header(hash))
						retries += 1
					if not created:
						#failure to create block, migrate to next try
						if len(self.blocks) == 1:
							self.new_block()
						self.blocks[1].migrate(self.blocks[0])
						self.blocks.pop(0)
				self.next_timestamp += Globals.BLOCK_CREATION_INTERVAL

			elif self.next_timestamp - now < Globals.BLOCK_CREATION_TAKEOVER and self.next_worker != self.CONFIG['id'] and not self.NETWORK_MANAGER.is_connected(self.next_worker) and check_next_worker(self.next_worker, self.CONFIG['id']):
				#if predecessor is offline, takeover his duty
				self.takeover_count += 1
				if self.takeover_count == Globals.BLOCK_TAKEOVER_COUNT:
					self.next_worker = self.CONFIG['id']
					self.NETWORK_MANAGER.broadcast_duty()
					self.takeover_count = 0
			time.sleep(0.5)


	def new_block(self):
		folder = ''.join(random.sample(string.lowercase, 10))+'\\'
		with self.LOCK:
			self.blocks.append(Block(self.CONFIG, self.CRYPTO, folder))
			self.blocks[len(self.blocks)-1].latest_block(self.DATABASE.current_block())


	def new_item(self, resource, hash, item):
		with self.LOCK:
			for block in self.blocks:
				if not block.closed:
					if block.new_item(resource, hash, item):
						return True
			#all blocks are closed, create a new one
			self.new_block()
			if self.blocks[len(block)-1].new_item(resource, hash, item):
				return True
			return False


	def register_header(self, node, hash):
		#fetch file
		try:
			size = os.path.getsize(self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION)
			block = open(self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION, 'rb')
			if size < psutil.virtual_memory().available / Globals.JSON_MEMORY_MULTIPLIER:
				#enough memory to load header
				block_json = json.loads(block.read())
				block.close()
				#verify data fields
				previous_hash = block_json['previousBlockHash']
				signature =  block_json['signature']
				if not Patterns.validate(Patterns.HASH, previous_hash) or not Patterns.validate(Patterns.TIMESTAMP, block_json['date']) or block_json['workerNode'] not in Globals.NODES or not Patterns.validate(Patterns.SIGNATURE, signature) or type(block_json['header']) is not dict:
					raise ValueError()
				header = block_json['header']
				del block_json
			else:
				#read previous block's hash
				block.seek(104,0)
				previous_hash = block.read(64)
				#read block's date
				block.seek(9,1)
				timestamp = block.read(10)
				#read block's creator
				block.seek(15,1)
				node = block.read(1)
				#read block's signature
				block.seek(14,1)
				signature = ''
				c = ''
				while 1:
					c = block.read(1)
					if c == '"' or c == '':
						#reached end of file
						break
					signature += c
				#read header
				block.seek(11,1)
				header_json = ''
				while 1:
					c = block.read(1)
					if c == '}' or c == '':
						#reached end of file
						break
					header_json += c
				block.close()

				#verify data fields
				if not Patterns.validate(Patterns.HASH, previous_hash) or not Patterns.validate(Patterns.TIMESTAMP, timestamp) or node not in Globals.NODES	or not Patterns.validate(Patterns.SIGNATURE, signature) or len(header_json) < 2 or (header_json[:1] != '{' and header_json[-1:] != '}'):
					raise ValueError()
				header = json.load(header_json)

			#verify block's signature
			message = '{"previousBlockHash":"'+previous_hash+'","date":'+timestamp+',"header":'+json.dumps(header, sort_keys=True)+'}'
			if not self.CRYPTO.verify(Globals.NETWORK_RESOURCE_CODE, Globals.NODE_ID_PREFIX+node, message, signature, 'base64'):
				raise ValueError()

			#save to database
			self.DATABASE.new_block(hash, header, previous_hash)
			#remove duplicates from block
			with self.LOCK:
				for b in self.blocks:
					b.remove_duplicates(header)

				self.previous_worker = node
				if self.check_next_worker(node, self.CONFIG['id']):
					self.NETWORK_MANAGER.broadcast_duty()
		except:
			print 'Invalid block received: ', hash
			print 'Deleting and sending a new request'
			to_send = '0'+'0'+hash
			self.NETWORK_MANAGER.new_request(NetworkCodes.GET_BLOCK, to_send)


	def load_header(self, hash):
		size = os.path.getsize(self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION)
		block = open(self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION, 'rb')
		if size < psutil.virtual_memory().available / Globals.JSON_MEMORY_MULTIPLIER:
			block_json = json.loads(block.read())
			return block_json['header']
		else:
			block.seek(400,0)
			c = ''
			while 1:
				c = block.read(1)
				if c == '{':
					break
			header_json = c
			while 1:
					c = block.read(1)
					header_json += c
					if c == '}':
						break
			block.close()
			return json.loads(header_json)

	def check_next_worker(self, previous, next):
		active_nodes = self.NETWORK_MANAGER.active_nodes()
		active_nodes.append(self.CONFIG['id'])
		active_nodes.sort()
		index = active_nodes.index(next)
		if index == 0:
			if active_nodes[len(active_nodes)-1] <= previous:
				print active_nodes[len(active_nodes)-1]
				return True
		elif active_nodes[pos-1] <= previous:
			return True
		return False


	def update_worker(self, node, timestamp): 
		now = int(time.time())
		if now - timestamp > 300 or now - timestamp < 0:
			return
		with self.LOCK:
			if self.check_next_worker(self.previous_worker, node):
				self.next_worker = node
			elif self.next_worker != None and not self.NETWORK_MANAGER.is_connected(self.next_worker) and self.check_next_worker(self.next_worker, node):
				self.next_worker = node


	def synchronized(self, hash):
		with self.LOCK:
			if not self.SYNC:
				self.SYNC = True
				self.running = True
				self.blocks = []
				self.new_block()
				self.blocks[0].latest_block(hash)
				#node synchronized, can start working
				self.SERVER.set_blocks_manager(self)
				self.SERVER.start()
				self.start()


