import sys, json, threading, signal, time, os, xmlrpclib
from database import Database
from crypto import Crypto
from rpc import RPCManager
from block_manager import BlockManager
from server import Server
from globals import Globals


def load_configuration():
	config_items = ["id","key_encoding","private_key","certificate","ca_certificate","database_dir","blocks_dir","blocks_index_file","nodes","hostname","network_port","server_port"]
	try:
		configuration_file = open('config.json','r')
		CONFIG = json.loads(configuration_file.read())
		configuration_file.close()
		#check if the configuration file is valid
		for item in config_items:
			if item not in CONFIG:
				raise ValueError()
		#change unicode encodings
		CONFIG['id'] = str(CONFIG['id'])
		CONFIG['blocks_dir'] = str(CONFIG['blocks_dir'])
		CONFIG['blocks_index_file'] = str(CONFIG['blocks_index_file'])
	except IOError:
		print 'missing configuration file'
		sys.exit(2)
	except ValueError:
		print 'configuration file is corrupt'
		sys.exit(2)
	print 'Configuration loaded.'
	return CONFIG

def main(argv):

	#Load configuration
	print '\nLoading Configuration'
	CONFIG = load_configuration()

	#Load database
	print '\nLoading Database'
	DATABASE = Database(CONFIG)

	#Load encryption key
	print '\nLoading encryption key'
	CRYPTO = Crypto(CONFIG, DATABASE)

	#Create RPC manager
	print '\nCreating RPC manager'
	RPC_MANAGER = RPCManager(CONFIG, DATABASE, CRYPTO)

	#Create server
	print '\nCreating server'
	SERVER = Server(CONFIG, DATABASE, CRYPTO)

	#Create block manager
	print '\nCreating block manager'
	BLOCK_MANAGER = BlockManager(CONFIG, DATABASE, CRYPTO, RPC_MANAGER, SERVER)
	SERVER.set_blocks_manager(BLOCK_MANAGER)

	#Connect to nodes
	print '\nConnecting to network'
	RPC_MANAGER.connect(BLOCK_MANAGER)

	while True:
		try:
			time.sleep(1)
			os.system('clear')
			print 'Ready for Interruption'
			cmd = raw_input()
			if cmd in ['shutdown', 'SHUTDOWN', '^C', '^Z', 'exit', 'EXIT', 'close', 'CLOSE']:
				break
		except KeyboardInterrupt:
			break

	print '\nShutdown signal received, stopping everything'
	SERVER.shutdown()
	RPC_MANAGER.shutdown()
	BLOCK_MANAGER.shutdown()
	print 'All was correctly stopped, exiting'
	sys.exit(0)

if __name__ == '__main__':
	main(sys.argv[1:])