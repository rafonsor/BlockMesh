import sys, json, threading, signal
from database import Database
from crypto import Crypto
from network import NetworkManager
from block_manager import BlockManager
from server import Server
from globals import Globals


def check_configuration(CONFIG):
	config_items = ["id","key_encoding","private_key","ssl_private_key","ssl_certificate","ca_certificate","database_dir","blocks_dir","blocks_index_file","nodes","hostname","network_port","server_port"]
	for item in config_items:
		if item not in CONFIG:
			raise ValueError()

def main(argv):
	#load configuration
	try:
		configuration_file = open('config.json','r')
		CONFIG = json.loads(configuration_file.read())
		check_configuration(CONFIG)
		configuration_file.close()
		print 'Configuration loaded.'
	except IOError:
		print 'missing configuration file'
		sys.exit(2)
	except ValueError:
		print 'configuration file is corrupt'
		sys.exit(2)

	print Globals.RESOURCES_RESOURCE_CODE

	#Load database
	print '\nLoading Database'
	DATABASE = Database(CONFIG)

	#Load encryption key
	print '\nLoading encryption key'
	CRYPTO = Crypto(CONFIG, DATABASE)

	#Create network manager
	print '\nCreating network manager'
	NETWORK_MANAGER = NetworkManager(CONFIG, DATABASE, CRYPTO)

	#Create server
	print '\nCreating server'
	SERVER = Server(CONFIG, CRYPTO)

	#Create block manager
	print '\nCreating block manager'
	BLOCK_MANAGER = BlockManager(CONFIG, DATABASE, CRYPTO, NETWORK_MANAGER, SERVER)
	SERVER.set_blocks_manager(BLOCK_MANAGER)

	#Connect to nodes
	print '\nConnecting to network'
	NETWORK_MANAGER.connect_to_all(BLOCK_MANAGER)

	print '\nStartup complete, waiting for synchronization'

	while True:
		try:
			cmd = raw_input()
			if cmd in ['shutdown', 'SHUTDOWN', '^C', '^Z', 'exit', 'EXIT', 'close', 'CLOSE']:
				break
		except KeyboardInterrupt:
			break

	print 'Shutdown signal received, stopping everything'
	SERVER.shutdown()
	NETWORK_MANAGER.shutdown()
	print 'All was correctly stopped, exiting'
	sys.exit(0)

if __name__ == '__main__':
	main(sys.argv[1:])