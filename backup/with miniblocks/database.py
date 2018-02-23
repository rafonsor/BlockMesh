import leveldb, json, os, psutil, time
from globals import Globals

class Database():
	def __init__(self, CONFIG):
		options = {
			'create_if_missing': False,			
			'error_if_exists': False,
			'paranoid_checks': True,
			'block_cache_size': 8 * (2 << 20),
			'write_buffer_size': 2 * (2 << 20),
			'block_size': 4096,
			'max_open_files': 1000,
			'block_restart_interval': 16,
			'comparator': 'bytewise'
		}

		try:
			self.db = leveldb.LevelDB(CONFIG['database_dir'],  **options)
		except leveldb.LevelDBError:
			print 'Database not found, recreating from blocks'
			options['create_if_missing'] = True
			self.db = leveldb.LevelDB(CONFIG['database_dir'],  **options)
			#read block index file
			try:
				print 'Opening blocks index file'
				index = open(CONFIG['blocks_index_file'], 'r')
				previous_block = Globals.GENESIS_BLOCK
				next_block = index.readline()
				#register blocks in database
				while next_block != '':
					self.db.Put(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+previous_block, next_block)
					previous_block = next_block
					next_block = index.readline()
				index.close()
			except IOError:
				print 'Blocks index file not found'
				index.close()

			print self.db.Get(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+Globals.GENESIS_BLOCK)

			#register items in database
			print 'Loading known blocks onto database'
			hash = Globals.GENESIS_BLOCK
			while 1:
				try:
					#retrieve next block's hash
					hash = self.db.Get(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+hash)
					print '\nLoading block', hash
					#check block size and available memory
					size = os.path.getsize(CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
					block = open(CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, 'rb')
					if size < psutil.virtual_memory().available / Globals.JSON_MEMORY_MULTIPLIER:
						#directly load the block
						block_json = json.loads(block.read())
						for resource in block_json['header']:
							print 'Loading ', resource, 'items'
							for item in block_json['header'][resource]:
								self.db.Put(resource+Globals.DATABASE_KEY_SEPARATOR+item, block_json['blockHash'])
								print 'inserted:',item

						#load latest public keys of the network's entities
						if Globals.NETWORK_RESOURCE_CODE in block_json['header']:
							print 'Loading network entities'
							for item in block_json['header'][Globals.NETWORK_RESOURCE_CODE]:
								if block_json['data'][item]['data']['role'] == 'controller' or block_json['data'][item]['data']['role'] == 'worker':
									self.db.Put(Globals.DATABASE_KEY_PREFIX+Globals.DATABASE_KEY_SEPARATOR+Globals.NETWORK_RESOURCE_CODE+Globals.DATABASE_KEY_SEPARATOR+block_json['data'][item]['data']['identification'], block_json['data'][item]['data']['publicKey'])
									print 'Inserted public key of',block_json['data'][item]['data']['role'],block_json['data'][item]['data']['identification']

						#load resources' authorities public keys
						if Globals.RESOURCES_RESOURCE_CODE in block_json['header']:
							print "Loading resources' authorities"
							for item in block_json['header'][Globals.RESOURCES_RESOURCE_CODE]:
								self.db.Put(Globals.DATABASE_KEY_PREFIX+Globals.DATABASE_KEY_SEPARATOR+block_json['data'][item]['data']['designation']+Globals.DATABASE_KEY_SEPARATOR+block_json['data'][item]['data']['authority'], block_json['data'][item]['data']['publicKey'])
								print 'Inserted public key of',block_json['data'][item]['data']['authority'],'for the resource',block_json['data'][item]['data']['designation']
						del block_json
					else:
						#parse block data instead
						block.seek(400,0)
						while c != '{':
							if c == '':
								#corrupt block file, raise an exception
								raise ValueError()
								break
							c = block.read(1)
						header = c
						while c != '}':
							if c == '':
								#corrupt block file, raise an exception
								raise ValueError()
								break
							c = block.read(1)
							header += c
						json_header = json.load(header)

						network_items = []
						resources_items = []
						for resource in json_header:
							for item in json_header[resource]:
								self.db.Put(resource+Globals.DATABASE_KEY_SEPARATOR+item, hash)
							#verify if there are any new entities or updates
							if resource == Globals.NETWORK_RESOURCE_CODE:
								network_items = json_header[resource]
							elif resource == Globals.RESOURCES_RESOURCE_CODE:
								resources_items = json_header[resource]

						end_of_header = block.tell()

						#register network public keys
						block.seek(8,1)
						for entry in network_items:	
							#check next entry hash
							block.seek(2,1)
							buffer = block.read(64)
							while buffer != entry:
								#pass unneeded entry data
								block.seek(3,1)
								counter = 1
								while counter > 0:
									c = block.read(1)
									if c == '{':
										counter += 1
									elif c == '}':
										counter -= 1
									elif c == '':
										raise ValueError()
								block.seek(2,1)
								#read following hash
								buffer = block.read(64)
							block.seek(3,1)
							#read correct entry data
							c = block.read(1)
							buffer = c
							while c != '}':							
								if c == '':
									#corrupt block file, raise an exception
									raise ValueError()
									break
								buffer += c
							buffer = json.loads(buffer)
							if buffer['role'] == 'controller' or buffer['role'] == 'worker':
								self.db.Put(Globals.DATABASE_KEY_PREFIX+Globals.DATABASE_KEY_SEPARATOR+Globals.NETWORK_RESOURCE_CODE+Globals.DATABASE_KEY_SEPARATOR+buffer['entity'], buffer['publicKey'])

						#return to beginning of data
						block.seek(end_of_header+8, 0)
						#register resources' public keys
						for entry in resources_items:
							#check next entry hash
							block.seek(2,1)
							buffer = block.read(64)
							while buffer != entry:
								#pass unneeded entry data
								block.seek(3,1)
								counter = 1
								while counter > 0:
									c = block.read(1)
									if c == '{':
										counter += 1
									elif c == '}':
										counter -= 1
									elif c == '':
										raise ValueError()
								block.seek(2,1)
								#read following hash
								buffer = block.read(64)
							block.seek(3,1)
							#read correct entry data
							c = block.read(1)
							buffer = c
							while c != '}':							
								if c == '':
									#corrupt block file, raise an exception
									raise ValueError()
									break
								buffer += c
							buffer = json.loads(buffer)
							self.db.Put(Globals.DATABASE_KEY_PREFIX+Globals.DATABASE_KEY_SEPARATOR+items[buffer]['designation']+Globals.DATABASE_KEY_SEPARATOR+items[buffer]['authority'], items[buffer]['publicKey'])
					block.close()
				except (leveldb.LevelDBError, KeyError):
					#loaded all blocks
					block.close()
					break
				except OSError:
					#block file not found
					self.purge_blocks(hash)
					break
				except:
					#delete currupt block file
					block.close()
					os.remove(CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
					self.purge_blocks(hash)
					break
		print 'Database loaded'


	def purge_blocks(self, hash):
		if hash == '':
			return
		#remove this and following blocks from database
		try:
			next = Globals.GENESIS_BLOCK
			while next != hash:
				prev = next
				next = self.db.Get(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+prev)
			to_delete = [prev, next]
			while 1:
				prev = next
				next = self.db.Get(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+prev)
				to_delete.append(next)
		except (leveldb.LevelDBError, KeyError):
			for block in to_delete:
				self.db.Delete(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+block)


	def new_block(self, block, header, previous_block=None):
		if previous_block is None:
			previous_block = self.current_block()
		#insert hash link
		self.db.Put(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+previous_block, block)
		#insert items
		for resource in header:
			for item in header[resource]:
				self.db.Put(resource+Globals.DATABASE_KEY_SEPARATOR+item, block)
		#insert hash in index file
		if os.path.isfile(self.CONFIG['blocks_index_file']):
			index = open(self.CONFIG['blocks_index_file'], 'a')
		else:
			index = open(self.CONFIG['blocks_index_file'], 'w')
		index.write(block+'\n')
		index.flush()
		index.close()

	def current_block(self):
		searching = True
		block = Globals.GENESIS_BLOCK
		while searching:
			try:
				next_block = self.db.Get(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+block)
				if block == next_block:
					raise Exception()
				block = next_block
			except:
				searching = False
		return block

	def next_block(self, hash):
		if hash == self.current_block():
			return hash, True
		try:
			next_block = self.db.Get(Globals.DATABASE_BLOCK_PREFIX+Globals.DATABASE_KEY_SEPARATOR+block)
			return next_block, True
		except (leveldb.LevelDBError, KeyError):
			return hash, False

	def get_key(self, resource, id):
		try:
			encoded_key = self.db.Get(Globals.DATABASE_KEY_PREFIX+Globals.DATABASE_KEY_SEPARATOR+resource+Globals.DATABASE_KEY_SEPARATOR+id)
			return encoded_key
		except (leveldb.LevelDBError, KeyError):
			return False

	def check_item(self, resource, hash):
		try:
			block = self.db.Get(resource+Globals.DATABASE_KEY_SEPARATOR+hash)
			return block
		except (leveldb.LevelDBError, KeyError):
			return False
