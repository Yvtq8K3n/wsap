import subprocess
import logging
import os
from urllib.parse import urlparse

#Files
TMP_DIRECTORY =  os.path.dirname(__file__) + "/tmp"
REPORT_PATH = TMP_DIRECTORY + "/insider_report.json"
INSIDER_LOG = TMP_DIRECTORY + "/insider.log"

#Properties
TARGET_LANG = "java"
#insider --tech java --target /home/jenkins/vulnado/src

class InsiderScanner:
    def __init__(self):
        self.scan = self.Scan(self)
        
        self.target_lang = "--tech {} ".format(TARGET_LANG)

    class Scan:
        def __init__(self, insiderscanner):
            self.insiderscanner = insiderscanner

        def start(self, target_proj_dir):
            logging.info("Setting up the pre-defined constrains")
            insider_cmd = "insider "
            
            logging.info("Setting up the scan custom properties")
            insider_cmd += self.insiderscanner.target_lang
            insider_cmd += "--target {} ".format(target_proj_dir)

            logging.info('Launching Insider scanner for target {}'.format(self.insiderscanner.target_lang))
            with open(INSIDER_LOG, "a+") as insider_log:
                insider_log.write(insider_cmd)
                subprocess.call(insider_cmd,stdout=insider_log, shell=True, cwd=TMP_DIRECTORY)
                os.rename(os.path.join(TMP_DIRECTORY,"report.json"), REPORT_PATH)