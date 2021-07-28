from insiderCLI import InsiderScanner
from urllib.parse import urlparse
import time
import sys
import os
import logging

#Files
TMP_DIRECTORY =  os.path.dirname(__file__) + "/tmp"

class ScannersSast:
    def __init__(self):
        os.makedirs(TMP_DIRECTORY, exist_ok=True)
        print ('Launching Insider...')
        
        #Initializing Scanners
        self.insider = InsiderScanner() #Insider

         #Creating inner classes     
        self.scanner = self.Scanner(self)
       

    class Scanner:
        def __init__(self, scanners):
            self.insider = scanners.insider

        def start(self, target):
            print("Insider: Starting scan")
            self.insider.scan.start(target)