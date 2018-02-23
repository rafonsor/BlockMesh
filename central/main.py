from database import Database
import central


def load_config():
	try:
		configuration_file = open('config.json','r')
		CONFIG = json.loads(configuration_file.read())
		configuration_file.close()
		return CONFIG
	except IOError:
		print 'missing configuration file'
		sys.exit(2)
	except ValueError:
		print 'configuration file is corrupt'
		sys.exit(2)


def main():
	CONFIG = load_config()
	DATABASE = Database(CONFIG)
	SERVER = RPCServer(DATABASE, "localhost", CONFIG['rpc_port'])

	server_thread = threading.Thread(SERVER.serve_forever)
	server_thread.start()

if __name__ == '__main__':
	main()