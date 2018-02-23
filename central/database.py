from __future__ import with_statement
import psycopg2, system
from globals import Globals


class Database():

	def __init__(self, CONFIG):
		try:
			self.conn = psycopg2.connect(host=CONFIG['db_host'], port=CONFIG['db_port'], database=CONFIG['db_name'], user=CONFIG['db_user'], password=CONFIG['db_password'])
		except Exception as e:
			print "Could not connect to the database"
			print e
			system.exit(2)

	def new_block(self, hash):
		with self.conn, open(self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION, 'rb') as block:
			with self.conn.cursor() as cursor:
				try:
					c = block.read(1)
					metadata = ''
					while c != ',':
						metadata += c
						c = block.read(1)
					metadata += '}'
					metadata = json.loads(metadata)

					cursor.execute('INSERT INTO blocks VALUES (%s, %s, %s, %s, %s, %s, %s)',(metadata['blockHash'], metadata['previousBlockHash'], metadata['date'], metadata['workerNode'], metadata['signature'], self.CONFIG['blocks_dir']+hash+Globals.BLOCK_EXTENSION))

					for resource in metadata['header']:
						for item in metadata['header'][resource]:
							cursor.execute('INSERT INTO headers(block, resource, hash) VALUES (%s, %s, %s)', (hash, resource, item))

					#read entries
					block.seek(7,1)
					while block.read(2) != '}}':
						item = block.read(64)
						block.seek(10,1)
						data = ''
						count = 0
						while c != '':
							c = block.read(1)
							data += c
							if c == '{':
								count += 1
							elif c == '}':
								count -= 1
								if count == 0:
									break
						block.seek(11,1)
						entity = block.read(20)
						block.seek(15,1)
						c = block.read(1)
						signature = ''
						while c != '"':
							signature += c
							c = block.read(1)
						block.seek(1,1)

						for resource in metadata['header']:
							if item in metadata['header'][resource]:
								if Globals.RESOURCES_RESOURCE_CODE in metadata['header'] and item in metadata['header'][Globals.RESOURCES_RESOURCE_CODE]:
									data = json.loads(data)
									cursor.execute('INSERT INTO res_resource VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', (item, data['designation'], data['description'], data['accessibility'], data['authority'], data['publicKey'], data['meta']['entryType'], data['meta']['date'], data['meta']['version'], data['meta']['status']))
				
								elif Globals.IDENTIFICATION_RESOURCE_CODE in metadata['header'] and item in metadata['header'][Globals.IDENTIFICATION_RESOURCE_CODE]:
									data = json.loads(data)
									cursor.execute('INSERT INTO res_identification VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)', (item, data['identification'], data['commonName'], data['company'], data['certificate'], data['meta']['entryType'], data['meta']['date'], data['meta']['version'], data['meta']['status']))

								elif Globals.NETWORK_RESOURCE_CODE in metadata['header'] and  item in metadata['header'][Globals.NETWORK_RESOURCE_CODE]:
									data = json.loads(data)
									cursor.execute('INSERT INTO res_network VALUES(%s, ...)', (item, ))

								else:
									cursor.execute('INSERT INTO res_'+resource+' VALUES(%s, %s, %s, %s, %s)', (item, data, entity, signature, len(data)))
				except IOError:
					print 'Could not register block',hash,'into database'
					self.conn.rollback()
