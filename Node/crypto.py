import sys, hashlib, binascii, base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from globals import Globals

class Crypto():

	def __init__(self, CONFIG, DATABASE):
		try:
			key_file = open(CONFIG['private_key'],'r')
		except IOError:
			print 'Private key not found'
			sys.exit(1)

		if 'key_password' in CONFIG:
			password = CONFIG['key_password']
		else:
			password = None

		self.DATABASE = DATABASE
		if CONFIG['key_encoding'] == 'PEM':
			self.private_key = serialization.load_pem_private_key(key_file.read(), password, default_backend())
		elif CONFIG['key_encoding'] == 'DER':
			self.private_key = serialization.load_der_private_key(key_file.read(), password, default_backend())
		else:
			print 'Private key encoding not supported'
			sys.exit(1)
		print 'Encryption key loaded'


	@staticmethod
	def hash(message):
		return hashlib.sha256(message).hexdigest()

	@staticmethod
	def hash_file(file):
		hasher = hashlib.sha256()
		file.seek(0,0)
		buffer = file.read(65536)
		while len(buffer) > 0:
			hasher.update(buffer)
			buffer = file.read(65536)
		return hasher.hexdigest()

	def sign(self, message):
		#return signature in hexstring format
		signer = self.private_key.signer(ec.ECDSA(hashes.SHA256()))
		signer.update(message)
		signature = signer.finalize()
		return binascii.hexlify(signature)


	def verify(self, resource, id, message, signature, encoding=None):
		if type(message) != 'str':
			message = str(message)
		#decode signature if necessary
		if encoding == 'hex':
			signature = binascii.unhexlify(signature)
		elif encoding == 'base64':
			signature = base64.standard_b64decode(signature)
		#retrieve DER encoded key from database
		encoded_key = self.DATABASE.get_key(resource, id)
		if encoded_key:
			#load public key
			key_bytes = binascii.unhexlify(encoded_key)
			public_key = serialization.load_der_public_key(key_bytes, default_backend())
			#retrieve verifier and feed data
			verifier = public_key.verifier(signature, ec.ECDSA(hashes.SHA256()))
			verifier.update(message)
			try:
				verifier.verify()
				return True
			except:
				return False
		return False

