
class IP_Flags():
    def __init__(self, integer):
        self.more_fragments_flag = (integer & 1) > 0
        self.dont_fragment_flag = (integer & 2) > 0

    def set_dont_fragment_flag(self, value):
        self.dont_fragment_flag = value

    def set_more_fragments_flag(self, value):
        self.more_fragments_flag = value

    def get_dont_fragment_flag(self):
        return self.dont_fragment_flag

    def get_more_fragments_flag(self):
        return self.more_fragments_flag

    def get_integer(self):
        integer = 0
        if (self.more_fragments_flag):
            integer = integer | 1
        if (self.dont_fragment_flag):
            integer = integer | 2
        return integer

