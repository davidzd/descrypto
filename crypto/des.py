# COMP90043 Cryptography and Security
# Skeleton for Stream Cipher
# BONUS Credits Work. Not required for Full Credits.
# 
# Instructions to candidates:
# 	- You may add additional helper functions prior to the declaration of the 
#	class. But I'd advise you to import it from a different file.
#	- Do not modify class declaraction, function declarations or method 
#	declarations.
#   - If you decided not to implement this, please remove this file from the 
#   directory and submit.
#
# Sample Test Case
# Plaintext: 0x02468aceeca86420
# Ciphertext: 0xda02ce3a89ecac3b
# Key: 0x0f1571c947d9e859


# TODO, You will need to instantiate quite a number of DES variables, such as the 
# permutation blocks and etc etc...
class DESCiphers:
    # CLASS VARIABLES GO HERE
    
	# TODO
    def __init__(self, key):
        self.key = None

    # TODO
    def cipher_function(self, r, k):
    	assert(type(r) == type(1) or type(r) == type(1L))
        assert(type(k) == type(1) or type(k) == type(1L))
        assert(r < (2 ** 32))
        assert(k < (2 ** 48))
        """
            The DES Cipher Function
            
            INPUTS:
                r, Integer or Long (32bit)
                k, Int or Long (48bit)
            OUTPUT:
                Integer or Long (32bit)
        """

        return 0

    # TODO
    def key_schedule(self):
    	assert(type(self.key) == type(1L) or type(self.key) == type(1))
        """
        Key Schedule Generation. 
        INPUT:
            None
        OUTPUT:
            [key], LIST of Integer or LONG 48 Bits
        """
        key_schedule_list = []
        return key_schedule_list

    # TODO
    def crypt(self, input_block, encrypt_mode):
    	assert(type(input_block) == type(1) or type(input_block) == type(1L))
        assert(type(self.key) == type(1) or type(self.key) == type(1L))
        assert(input_block < (2 ** 64))
        assert(type(encrypt_mode) == type(True))
        """
        DES Encrypt 
        INPUT:
            input_block, Int or Long (64bit)
            encrypt_mode, Bool (True = Encrypt Mode; False = Decrypt Mode)
        OUTPUT:
            output_block, Int or Long (64bit)
        """
        output_block = 0
        return output_block

    def encrypt(self, input_block):
        return self.crypt(input_block, True)

    def decrypt(self, input_block):
        return self.crypt(input_block, False)