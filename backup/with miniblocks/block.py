from __future__ import with_statement
import os, shutil, base64
from globals import Globals
from threading import Lock

class Block():

	def __init__(self, CONFIG, CRYPTO, folder):
		print '\nCreating new block'
		self.CONFIG = CONFIG
		self.CRYPTO = CRYPTO
		self.LOCK = Lock()
		#initialize next Block 
		self.closed = False
		self.header = {}
		self.folder = self.CONFIG['blocks_dir']+folder
		if not os.path.exists(self.folder):
			os.makedirs(self.folder)
			print 'New block folder created: ',self.folder


	def __del__(self):
		#delete data files after block is created
		shutil.rmtree(self.folder)


	def latest_block(self, hash):
		self.previous_hash = hash


	def new_item(self, resource, hash, item):
		with self.LOCK:
			if resource not in self.header:
				self.header[resource] = []
			if hash in self.header[resource]:
				#duplicate entry, return True since it will be included in the next block
				return True
		try:
			self.data_file = open(self.folder+hash+'.'+resource, 'wb')
			self.data_file.write(item)
		except IOError:
			print "Could not save item to file"
			return False
		finally:
			self.close()
			self.header[resource].append(hash)
			return True


	def remove_duplicates(self, last_block):
		self.latest_block(last_block)
		#iterates over all the resources of the last block
		with self.LOCK:
			for key in last_block:
				#verifies if there's at least one entry for that resource in the current block
				if key in self.header:
					for entry in last_block[key]:
						if entry in self.header[key]:
							#remove duplicate from header and delete its data file
							self.header[key].remove(entry)
							os.remove(self.folder+entry+'.'+key)
					if len(self.header[key]) == 0:
						del self.header[key]


	def create_block(self, timestamp):
		self.closed = True
		header = json.dumps(self.header, sort_keys=True)
		hash = self.CRYPTO.hash('{"previousBlocKHash":"'+self.previous_hash+'","date":'+timestamp+',"header":'+header+'}')
		signature = base64.standard_b64encode(self.CRYPTO.sign(hash))
		meta = '{"blockHash":"'+hash+'","previousBlocKHash":"'+self.previous_hash+'","date":'+timestamp+',"workerNode":"'+self.CONFIG['id']+'","signature":"'+signature+'","header":'

		try:
			#create simplified block
			block = open(self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION, 'wb')
			block.write(meta)
			block.write(header)
			block.write('}')
			block.flush()
			os.fsync(block)
			block.close()
			#create complete block
			shutil.copyfile(self.CONFIG['blocks_dir']+hash+Globals.SIMPLIFIED_BLOCK_EXTENSION, self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION)
			block = open(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, 'r+b')
			block.seek(-1, os.SEEK_END)
			block.write(',"data":{')
			for resource in self.header:
				for item in self.header[resource]:
					block.write('"')
					block.write(item)
					block.write('":')
					temp = open(self.folder+item,'rb')
					block.write(temp.read())
					temp.close()
					block.write(',')
			block.seek(-1, os.SEEK_END)
			block.write('}}')
		except IOError:
			print "Failed to create block"
			return False
		finally:			
			block.flush()
			os.fsync(block)
			block.close()
			return hash


	def migrate(self, block):
		#copy items to the most recent block, keeping them in chronological order
		with self.LOCK:
			for resource in self.header:
				if resource not in block.header:
					block.header[resource] = self.header[resource]
				else:
					for item in self.header[resource]:
						block.header[resource].append(item)
			self.header = block.header

		#move items' files to this block's folder
		items = os.listdir(block.folder)
		for item in items:
			os.rename(block.folder+item, self.folder+item)
