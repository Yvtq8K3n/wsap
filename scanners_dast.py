from zap import ZapScanner
from wapiti import WapitiScanner
from urllib.parse import urlparse
import subprocess
import time
import sys
import os
import uuid
import logging

#Files
TMP_DIRECTORY =  os.path.dirname(__file__) + "/tmp/"
DAST_LOG = "/dast_analysis.log"
ZAP_PROCESS_LOG =  "/zap.log"
WAPITI_PROCESS_LOG = "/wapiti.log"

class ScannersDast:
    def __init__(self, target_url, proxy_IpAddress, proxy_PortAddress, scan_mode, current_time):#, ip_address, port):
        parsedURL= urlparse(proxy_IpAddress)
        PATH = TMP_DIRECTORY + urlparse(target_url).netloc + "_" + current_time

        os.makedirs(PATH, exist_ok=True)

        #Duplicate stdout/stderr
        tee = subprocess.Popen(["tee", PATH + DAST_LOG], stdin=subprocess.PIPE)
        os.dup2(tee.stdin.fileno(), sys.stdout.fileno())
        os.dup2(tee.stdin.fileno(), sys.stderr.fileno())

        print("Generating random ZAP API key")
        api_key = uuid.uuid4().hex
        print("API_KEY: "+api_key)

        print ('Launching ZAP instance...')
        if (scan_mode == "TRADITIONAL"):
            logging.info("Loading aditional modules")
            subprocess.Popen(["/usr/local/bin/zap.sh","-daemon", "-addoninstall", "domxss", "-addoninstall", "sqliplugin","-config", "api.key="+api_key,
        "-port", proxy_PortAddress],stdout=open(PATH + ZAP_PROCESS_LOG, "w"))
        else:
            subprocess.Popen(["/usr/local/bin/zap.sh","-daemon", "-addonuninstall", "domxss", "-addoninstall", "sqliplugin", "-config", "api.key="+api_key,
            "-port", proxy_PortAddress],stdout=open(PATH + ZAP_PROCESS_LOG, "w"))

        print ('Waiting for ZAP to load, 1 min...')
        sleep(60)
        
        #Parse IpAddress
        parsedIpAddress = parsedURL.netloc
        if ( parsedIpAddress is None or parsedIpAddress == ""):
            parsedIpAddress = parsedURL.path 

        #Initializing Scanners
        self.zap = ZapScanner(PATH, parsedIpAddress, proxy_PortAddress, api_key) #zap
        self.wapiti = WapitiScanner(PATH, parsedIpAddress, proxy_PortAddress) #Wapiti

        #Creating inner classes     
        self.crawlers = self.Crawler(self)
        self.attacks = self.Attack(self)
        self.authentications = self.Authentication(self)
        self.alerts = self.Alert(self)

    def createContext(self, target_url, include_Urls, exclude_Urls, current_time):
        self.zap.createContext(target_url, include_Urls, exclude_Urls, current_time)
        self.wapiti.createContext(target_url, include_Urls, exclude_Urls)

    def shutdown(self):
        self.zap.shutdown()

    class Crawler:
        def __init__(self, scanners):
            self.zap = scanners.zap
            self.wapiti = scanners.wapiti

        def scan(self, scan_type, apiUrl=None, apiDefinitionURI=None):
            print ('Selecting scan method: '+scan_type.name)

            if (scan_type.name=='FULL'):
                self.fullScan(apiUrl, apiDefinitionURI)
            elif(scan_type.name=='APIONLY'):
                self.readOpenApi(apiUrl, apiDefinitionURI)
            elif(scan_type.name=='TRADITIONAL'):
                self.scanTradional()
            elif(scan_type.name=='AJAX'):
                self.scanAjax()

        def scanAsUser(self, scan_type, user_id, username):
            print ('Selecting scan method: '+scan_type.name)

            if (scan_type.name=='FULL') or (scan_type.name=='APIONLY'):
                self.fullScanAsUser(user_id, username)
            elif(scan_type.name=='TRADITIONAL'):
                self.scanTradionalAsUser(user_id, username)
            elif(scan_type.name=='AJAX'):
                self.scanAjaxAsUser(user_id, username)

        def scanTradional(self):
            print("ZAP: Starting traditional scanning")
            self.zap.crawlers.scanTradional()
            self.zap.saveState()

            print("Wapiti: Starting traditional scanning")
            self.wapiti.crawlers.scanTradional()
            self.zap.restoreState()

        def scanTradionalAsUser(self, user_id, username):
            self.zap.authentications.forceUserMode(user_id)

            print("ZAP: Starting traditional scanning with user: "+user_id)
            self.zap.crawlers.scanTradionalAsUser(user_id)
            self.zap.saveState()
            
            print("Wapiti: Starting traditional authenticated via ZAP Proxy")
            self.wapiti.crawlers.scanTradional(username)
            self.zap.restoreState()

            self.zap.authentications.releaseUserMode()
        
        def scanAjax(self):
            print("ZAP: Starting AJAX scanning")
            self.zap.crawlers.scanTradional()
            self.zap.saveState()

            logging.warning("Wapiti: doens't support AJAX scanning")

        def scanAjaxAsUser(self, user_id, username):
            self.zap.authentications.forceUserMode(user_id)

            print("ZAP: Starting AJAX scanning with user: "+user_id)
            self.zap.crawlers.scanTradional()
            self.zap.saveState()
            logging.warning("Wapiti: doens't support AJAX scanning")

            self.zap.authentications.releaseUserMode()

        def readOpenApi(self, apiUrl, apiDefinitionURI):
            if (apiUrl is None or apiUrl == "" or apiDefinitionURI is None or apiDefinitionURI == ""):
                raise Exception('Please provide a valid APIURL and APIDefinition')
            print("ZAP: Starting to read OpenAPI definition entries")
            self.zap.crawlers.readOpenApi(apiUrl, apiDefinitionURI)
            self.zap.saveState()
            
            logging.warning("Wapiti: does not support OpenAPI scheme natively")
            print("Wapiti: Using entries retrieved by Zap instead")

            self.zap.crawlers.exportUrlScanEntries()
            self.wapiti.crawlers.readUrlEntries()
            self.zap.restoreState()

        def fullScan(self, apiUrl, apiDefinitionURI):
            self.scanTradional()
            self.scanAjax()
            self.readOpenApi(apiUrl, apiDefinitionURI)

        def fullScanAsUser(self, user_id, username):
            self.scanTradionalAsUser(user_id, username)
            self.scanAjaxAsUser(user_id, username)
            logging.warning("Wapiti: OpenAPI entries will be loaded from previous scan")
            self.wapiti.crawlers.readUrlEntries(username)

    class Attack:
        def __init__(self, scanners):
            self.zap = scanners.zap
            self.wapiti = scanners.wapiti

        def startPassiveScan(self):
            print("ZAP: Starting passive scanning")
            self.zap.attacks.startPassiveScan()

            logging.warning("Wapiti: does not support passive scanning")

        def startActiveScan(self):
            logging.warning("Active scanning my overload the target machine")

            print("ZAP: Starting active scanning")
            self.zap.attacks.startActiveScan()
            self.zap.saveState()

            print("Wapiti: Start active scanning")
            self.wapiti.attacks.startActiveScan()
            self.zap.restoreState()

        def startActiveScanAsUser(self, user_id, username):
            logging.warning("Active scanning my overload the target machine")
            self.zap.authentications.forceUserMode(user_id)

            print("ZAP: Starting active scanning with user: "+user_id)
            self.zap.attacks.startActiveScanAsUser(user_id)
            self.zap.saveState()

            print("Wapiti: Starting active scanning authenticated via ZAP Proxy")
            self.wapiti.attacks.startActiveScan(username)
            self.zap.restoreState()

            self.zap.authentications.releaseUserMode()
        
    class Authentication:
        def __init__(self, scanners):
            self.zap = scanners.zap
            self.wapiti = scanners.wapiti

        def performJSONLogin(self, login_url, login_dataJSON, field_username, field_password, logged_in_regex=None, logged_out_regex=None):
            print("ZAP: Creating new user")
            print(login_dataJSON)
            user_id = self.zap.authentications.performJSONLogin(login_url, login_dataJSON, field_username=field_username, field_password=field_password, logged_in_regex=None, logged_out_regex=None)

            logging.warning("Wapiti: Authentication of requests is provided by ZAP Proxy")
            return user_id

    class Alert:
        def __init__(self, scanners):
            self.zap = scanners.zap
            self.wapiti = scanners.wapiti

        def report(self):
            print ("Generating report")
            self.zap.alerts.report()

def sleep(seconds):
    timeout = time.time() + seconds
    while (time.time() <= timeout):
        sys.stdout.write('\rloading |')
        time.sleep(0.1)
        sys.stdout.write('\rloading /')
        time.sleep(0.1)
        sys.stdout.write('\rloading -')
        time.sleep(0.1)
        sys.stdout.write('\rloading \\')
        time.sleep(0.1)
    sys.stdout.write('\rDone!      \n')
