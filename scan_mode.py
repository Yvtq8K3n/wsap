import enum

class ScanMode(enum.IntEnum):
    FULL = 1
    APIONLY = 2
    TRADITIONAL = 3
    AJAX = 4

    def __str__(self):
        return self.name.upper()

    def __repr__(self):
        return str(self)

    @staticmethod
    def argparse(s):
        try:
            return ScanMode[s.upper()]
        except KeyError:
            return s