# COMP90043 Cryptography and Security
# Author: Da Zhang 665442
# Cryptography Skeleton Function for Project
#
# Candidates will have to implement the following skeleton functions.
# Candidates may create additional skeleton functions by importing the skeleton functions from a seperate file.
# Do not alter the function declarations in this file, or add additional helper functions in this file.

import random

# TO DO.
def diffie_hellman_private(numbits):
    """
        diffie_hellman_private

        generate a private key whose size will depend
        on the numbits as inputed. if numbits equals 4
        the private key will be in the range of (1,16).


    """

    # private = 0
    # """
    #     using random.randint(a,b) to generate private
    #     key with changing the numbits. if the numbits
    #     = 8 then (1,2^8-1) will be the range the private
    #     key can be generated.
    # """
    # for i in range(1,numbits+1):
    # #left shift and add the random integer at the end of he private key;
    #     private = private << 1

    #     #generate integer between 0 and 1.

    #     private = private + random.randint(0,1)
    # return private
    # more easy method to generate random num.
    private = random.getrandbits(numbits)
    return private


# TODO
def diffie_hellman_pair(generator, modulus, private):
    """
        diffie_hellman_pair

        Given a generator, prime modulus and a private
        integer, produce the public integer. Return a
        tuple of (Private Integer, Public Integer)
        the result of the biginteger calculation,
        utilizing the modexp() below, should
        be the public key.

    """
    public = modexp(generator,private,modulus)
    return (private, public)

# TODO
def diffie_hellman_shared(private, public, modulus):
    """
        diffie_hellman_shared

        Given a private integer, public integer and
        prime modulus. Compute the shared key for
        the communication channel, then return it.
        the result of the biginteger calculation,
         utilizing the modexp() below.  should
        be the shared key, which cannot be monitored or
        detected from the two public keys from both sides.


    """
    shared_key = modexp(public,private,modulus)
    return shared_key

# TODO
def modexp(base, exponent, modulo):
    """
        modexp
        function modular_pow(base, exponent, modulus)
            c := 1
        for e_prime = 1 to exponent
            c := (c * base) mod modulus
        return c
        The function above is the memory-efficient method from
        Given a base, exponent and modulo. Compute
         the modular exponentiation.
        function modular_pow(base, exponent, modulus)

        result := 1
        base := base mod modulus
        while exponent > 0
            if (exponent mod 2 == 1):
                result := (result * base) mod modulus
            exponent := exponent >> 1
            base := (base * base) mod modulus
        return result
        The function  is another function
        "Right to left binary method" which is absolutely
        more efficient than the memory-efficient method
        due to the operation times should be obviously e
        however, the second method shoul be at most
        sqrt(exponent)
    """
    result = 1
    base = base % modulo
    while exponent > 0:
        if (exponent &1 ==1):
            result = (result*base) % modulo
        exponent = exponent >> 1
        base = (base * base) % modulo
    return result
