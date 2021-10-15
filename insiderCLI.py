import subprocess
import logging
import os
import shlex
from urllib.parse import urlparse

#Files
REPORT_PATH = "insider_report.json"
INSIDER_LOG =  "insider.log"

#Properties
TARGET_LANG = "java"
#insider --tech java --target /home/jenkins/vulnado/src

class InsiderScanner:
    def __init__(self, TMP_DIRECTORY):
        self.TMP_DIRECTORY = TMP_DIRECTORY
        self.scan = self.Scan(self)
        
        self.target_lang = "--tech {} ".format(TARGET_LANG)

    class Scan:
        def __init__(self, insiderscanner):
            self.insiderscanner = insiderscanner

        def start(self, target_proj_dir):
            logging.info("Setting up the pre-defined constrains")
            #insider_cmd = "~/.local/bin/insider "
            insider_cmd = "insider "
            
            logging.info("Setting up the scan custom properties")
            insider_cmd += self.insiderscanner.target_lang
            insider_cmd += "--target {} ".format(target_proj_dir)

            logging.info('Launching Insider scanner for target {}'.format(self.insiderscanner.target_lang))

            #Subprocess failed
            with open(os.path.join(self.insiderscanner.TMP_DIRECTORY, INSIDER_LOG), "a+") as insider_log:
                insider_log.write(insider_cmd)
                #subprocess.call(insider_cmd, stdout=insider_log, shell=True, cwd=self.insiderscanner.TMP_DIRECTORY)
                process = subprocess.run(shlex.split(insider_cmd),stdout=insider_log, cwd=self.insiderscanner.TMP_DIRECTORY)
                #raise Exception ("check_returncode ="+str(process.check_returncode())+"code:"+str(process.returncode)+" stderr: "+str(process.stderr)+"stdout "+str(process.stdout))

                #subprocess.call(insider_cmd, stdout=insider_log, shell=True, cwd=self.insiderscanner.TMP_DIRECTORY)
                os.rename(os.path.join(self.insiderscanner.TMP_DIRECTORY,"report.json"), os.path.join(self.insiderscanner.TMP_DIRECTORY, REPORT_PATH))