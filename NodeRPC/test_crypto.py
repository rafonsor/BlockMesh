import sys, json, threading, signal, time, os
from database import Database
from crypto import Crypto
from network import NetworkManager
from block_manager import BlockManager
from server import Server
from globals import Globals, Patterns



nod = {"1": 'node', '0': 'node','3': 'node','4': 'node'}

def online_nodes():
	n = []
	for a in nod:
		n.append(a)
	return n

def check(o, p, n):
	index = o.index(n)
	if p == n:
		print False, 1
	elif p < n:
		if index == 0:
			print True, 3
		elif o[index-1] <= p:
			#anterior node is smaller or equal to previous
			print True, 2
		else:
			print False, 2
	elif index == 0 and o[len(o)-1] <= p:
		print True, 1
	else:
		print False, 3

def main():
	#load configuration
	try:
		configuration_file = open('config.json','r')
		CONFIG = json.loads(configuration_file.read())
		#convert id to string instead of remaining as unicode
		configuration_file.close()
		print 'Configuration loaded.'
	except IOError:
		print 'missing configuration file'
		sys.exit(2)
	except ValueError:
		print 'configuration file is corrupt'
		sys.exit(2)
	#Load database
	print '\nLoading Database'
	DATABASE = Database(CONFIG)

	#Load encryption key
	print '\nLoading encryption key'
	CRYPTO = Crypto(CONFIG, DATABASE)

	
	previous = '3'
	next = '1'
	active_nodes = ['0', '1', u'3']
	check(active_nodes, previous, next)





if __name__ == '__main__':
	main()