import subprocess
import logging
import os
from urllib.parse import urlparse

#Files
REPORT_PATH = "/wapiti_report"
URL_ENTRIES = "/api_endpoints.txt"
STORE_SESSION = "/wapiti"
WAPITI_LOG = "/wapiti.log"

#Properties
INVALID_MODULE = "\"\""
INVALID_SCAN = 0
FULL_MODULE_ATTACK = "all"
DEFAULT_SCAN_DEPTH = 4

class WapitiScanner:

    def __init__(self, TMP_DIRECTORY, proxy_IpAddress, proxy_Port):#, apikey, ip_address, port):
        self.TMP_DIRECTORY = TMP_DIRECTORY
        self.crawlers = self.Crawler(self)
        self.attacks = self.Attack(self)
        
        #Due to persistence issuies it is required params to added everytime
        self.wapiti_storage_cmd = "--store-session {}".format(self.TMP_DIRECTORY + STORE_SESSION)
        self.wapiti_included_cmd = ""
        self.wapiti_excluded_cmd = ""

        if (proxy_IpAddress==None):
            logging.warning("Proxy ip address was not provided")
        self.wapiti_proxy_cmd = "-p http://{}:{} ".format(proxy_IpAddress,proxy_Port)

    def createContext(self, target_url, include_urls, exclude_urls):
        targetUrlParsed = urlparse(target_url)

        logging.info("WAPITI: Creating Context")
        self.context_name = targetUrlParsed.hostname

        # include target url
        self.target_url = target_url

        # According to Wapiti url's must be added with: --start <url>
        logging.info('Included %s and its subpaths', self.target_url)
        for url in include_urls:
            self.wapiti_included_cmd += "--start {} ".format(url)
            logging.info('Included %s and its subpaths', target_url)

        if len(exclude_urls) == 0:
            logging.info('Exclude urls not provided for %s using defaults', self.target_url)
            default_excluded_paths=['logout', 'uitloggen', 'afmelden', '.signout']

            # According to Wapiti url's must be excluded with: --exclude <url>
            for path in default_excluded_paths:
                exclude_url = self.target_url+str(path)
                self.wapiti_excluded_cmd += "--exclude {} ".format(exclude_url)
                logging.info('Excluded %s', exclude_url)

        # According to Wapiti url's must be excluded with: --exclude <url>
        for url in exclude_urls:
            self.wapiti_excluded_cmd += "--exclude {} ".format(url)
            logging.info('Excluded %s', url)
      
    class Crawler:
        def __init__(self, wapitiscanner):
            self.wapitiscanner = wapitiscanner
            self.depth = 4

        def scanTradional(self, username=None,depth=DEFAULT_SCAN_DEPTH):
            user_path = ""
            if(username is not None):
                user_path += "_"+username

            logging.info("Setting up the pre-defined constrains")
            wapiti_cmd = "wapiti -u {} ".format(self.wapitiscanner.target_url)
            wapiti_cmd += self.wapitiscanner.wapiti_included_cmd
            wapiti_cmd += self.wapitiscanner.wapiti_excluded_cmd

            logging.info("Setting up the scan custom properties")
            wapiti_cmd += "-d {} ".format(depth)
            wapiti_cmd += "-m {} ".format(INVALID_MODULE)
            wapiti_cmd += self.wapitiscanner.wapiti_proxy_cmd
            wapiti_cmd += self.wapitiscanner.wapiti_storage_cmd + user_path + " "
        
            wapiti_cmd +=  "--format json --output {} ".format(self.wapitiscanner.TMP_DIRECTORY + REPORT_PATH + user_path + ".json")

            logging.info('Spidering target {}'.format(self.wapitiscanner.context_name))
            print(wapiti_cmd)

            with open(self.wapitiscanner.TMP_DIRECTORY + WAPITI_LOG, "a+") as wapiti_log:
                wapiti_log.write("\n\n"+wapiti_cmd)
                subprocess.call(wapiti_cmd, stderr=wapiti_log, shell=True)

        def readUrlEntries(self, username=None):
            user_path = ""
            if(username is not None):
                user_path = "_"+username

            logging.info("Setting up the pre-defined constrains")
            wapiti_cmd = "wapiti -u {} ".format(self.wapitiscanner.target_url)
            wapiti_cmd += self.wapitiscanner.wapiti_excluded_cmd

            #Reading entries from file
            logging.info("Setting up the scan custom properties")
            wapiti_cmd += "--start {} ".format(self.wapitiscanner.TMP_DIRECTORY + URL_ENTRIES)
            wapiti_cmd += "-m {} ".format(INVALID_MODULE)
            wapiti_cmd += self.wapitiscanner.wapiti_proxy_cmd
            wapiti_cmd += self.wapitiscanner.wapiti_storage_cmd + user_path + " "
            wapiti_cmd +=  "--format json --output {} ".format(self.wapitiscanner.TMP_DIRECTORY + REPORT_PATH + user_path + ".json")

            logging.info('Spidering target {}'.format(self.wapitiscanner.context_name))
            print(wapiti_cmd)

            with open(self.wapitiscanner.TMP_DIRECTORY + WAPITI_LOG, "a+") as wapiti_log:
                wapiti_log.write("\n\n"+wapiti_cmd)
                subprocess.call(wapiti_cmd, stderr=wapiti_log, shell=True)

    class Attack:
        def __init__(self, wapitiscanner):
            self.wapitiscanner = wapitiscanner

        def startActiveScan(self, username=None):
            user_path = ""
            if(username is not None):
                user_path = "_"+username

            logging.info("Setting up the pre-defined constrains")
            wapiti_cmd = "wapiti -u {} ".format(self.wapitiscanner.target_url)
            wapiti_cmd += self.wapitiscanner.wapiti_excluded_cmd
            wapiti_cmd += "--skip-crawl "

            logging.info("Setting up the scan custom properties")
            wapiti_cmd += "-m {} ".format(FULL_MODULE_ATTACK)
            wapiti_cmd += self.wapitiscanner.wapiti_proxy_cmd
            wapiti_cmd += self.wapitiscanner.wapiti_storage_cmd + user_path + " "
            wapiti_cmd += "--format json --output {} ".format(self.wapitiscanner.TMP_DIRECTORY + REPORT_PATH + user_path + ".json")

            print(wapiti_cmd)
            with open(self.wapitiscanner.TMP_DIRECTORY + WAPITI_LOG, "a+") as wapiti_log:
                wapiti_log.write("\n\n"+wapiti_cmd)
                subprocess.call(wapiti_cmd, stderr=wapiti_log, shell=True)

            logging.info('Active Scanning target {}'.format(self.wapitiscanner.context_name))


