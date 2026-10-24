'''This file contains the function to crack.
An unmodified version of this file will be used to check your code.'''
import random
import string

VALID_CHARS = string.digits + string.ascii_letters + string.punctuation

class Server():

    def __init__(self, seed, L):
        """This simulates the user's registration in the server with a certain password, stored in self.password"""
        random.seed(seed)
        self.password = ''.join(random.choices(VALID_CHARS, k=L))
        self._calls = 0 # Do not access this variable from the outside!

    def _random_delay(self):
        p = random.random()
        if p < 0.02:
            return 4
        elif p < 0.05:
            return 3
        elif p < 0.06:
            return 2
        else:
            return 1
        
    def check_password(self, password: str) -> tuple[bool, int]:
        """This simulates the server checking if the provided password matches the one stored in self.password"""
        self._calls += 1
        virtual_time = 0
        if len(password) != len(self.password):
            return False, virtual_time
        for i, char in enumerate(password):
            virtual_time += self._random_delay() 
            if char != self.password[i]:
                return False, virtual_time            
        return True, virtual_time
