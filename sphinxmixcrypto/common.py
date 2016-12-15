
import os


class RandReader:
    def __init__(self):
        pass

    def read(self, n):
        return os.urandom(n)
