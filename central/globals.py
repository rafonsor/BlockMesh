import re
from cryptography.hazmat.primitives.asymmetric import ec

class Globals:
	NODES= [0,1,2,3,4,5,6,7,8,9]

	NEW_ITEM_PATH= '/submit'
	RPC_PATH= '/network'

	BLOCK_EXTENSION= '.blk'
	
	RESOURCES_RESOURCE_CODE = 'RESOURCES'
	NETWORK_RESOURCE_CODE = 'NETWORK'
	IDENTIFICATION_RESOURCE_CODE = 'IDENTIFICATION'

	NETWORK_ROLES = ['worker', 'controller']
	POSITIVE_ENTRY_TYPE = ['creation', 'renewal', 'update']
	NEGATIVE_ENTRY_TYPE= ['cancellation']
	NODE_ID_PREFIX = 'BLOCKMESHWORKERNODE'
	CONTROLLER_ID_PREFIX = 'BLOCKMESHCONTROLLER'

class Patterns:
	WORKER= r'^[0-9]$'
	HASH= r'^[a-f0-9]{64}$'
	SIGNATURE= r'^([A-F0-9]{100,}|[a-zA-Z0-9+=/]{50,})$'
	TIMESTAMP= r'^\d{10,20}$'

	@staticmethod
	def validate(pattern, data):
		return (re.match(pattern, data) != None)
