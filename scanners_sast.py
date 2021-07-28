from insiderCLI import InsiderScanner
from urllib.parse import urlparse
import time
import sys
import os
import logging

TMP_DIRECTORY =  os.path.dirname(__file__) + "/tmp/"

class ScannersSast:
    def __init__(self, target_url, current_time):
        PATH = TMP_DIRECTORY + urlparse(target_url).netloc + "_" + current_time.strftime("%Y/%m/%d/")

        os.makedirs(PATH, exist_ok=True)
        print ('Launching InsiderCLI...')
        
        #Initializing Scanners
        self.insider = InsiderScanner(PATH)

         #Creating inner classes     
        self.scanner = self.Scanner(self)
       

    class Scanner:
        def __init__(self, scanners):
            self.insider = scanners.insider

        def start(self, target):
            print("Insider: Starting scan")
            self.insider.scan.start(target)