# COMP90043 Cryptography and Security
# Auxillary Functions Skeleton
#
# Instructions to candidates:
#	As usual, do not modify function declarations, you may add additional helper functions.
#
# Any enquiries, please email `renlordy[at]unimelb.edu.au`. This code is maintained by Renlord.


# ============== ADD HELPER FUNCTIONS HERE =========================

# ============== END HELPER FUNCTIONS ==============================

# TODO
def parityWordChecksum(key):
	# assert(type(key) == type(1L))
	# assert(key < (2 ** 2048))
	"""
	parityWordChecksum, takes a 2048 bit key and applies a word by word XOR to yield a 64 bit result at the end.
	INPUT:
		key, 2048bit Integer from Part A1 Diffie Hellman Key Exchange
	OUTPUT:
		result, 64bit Integer
	"""
	result = 0
	i = 1
	# ======== IMPLEMENTATION GOES HERE =========
	for i in range(32):
		#save former key to get the minus.
		fkey = key
		key = key>>64
		#generate parity for XOR.
		parity = fkey - (key<<64)
		#XOR operation.
		result = result^parity
	# ======== END IMPLEMENTATION ===============
	return result


# TODO
def deriveSupplementaryKey(key, p):
	assert(type(key) == type(1L))
	assert(type(p) == type(1))
	assert(key < (2 ** 2048))
	assert(p < (2 ** 64))
	"""
	deriveSupplementaryKeyA, takes a 2048 bit key and applies the modulo operation to yield the modulo of `p1`.
	INPUT:
		key, 2048bit Integer from Part A1 Diffie Hellman Key Exchange
		p1, 64bit random prime number
	OUTPUT:
		keyA, 64bit Integer for use as `a` key for Stream Cipher
	"""
	# ======== IMPLEMENTATION GOES HERE =========
	subKey = key % p
	# ======== END IMPLEMENTATION ===============
	assert(type(subKey) == type(1) or type(subKey) == type(1L))
	return subKey


# ============== ADD HELPER FUNCTIONS HERE =========================
#TODO
def msb(fstream):
	if fstream.bit_length() <=8:
		return fstream
	else:
		fstream = fstream >> (fstream.bit_length()-8)
	return fstream
# ============== END HELPER FUNCTIONS ==============================
