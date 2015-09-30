class InvalidDHComputation(Exception):

    def errorMessage(self):
        return "Client DH Computation Error."