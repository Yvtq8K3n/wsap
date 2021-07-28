from zap import ZapScanner
from wapiti import WapitiScanner
from urllib.parse import urlparse
import subprocess
import time
import sys
import os
import logging

#Files
TMP_DIRECTORY =  os.path.dirname(__file__) + "/tmp/"
ZAP_PROCESS_LOG =  "/zap_process.log"
WAPITI_PROCESS_LOG = "/wapiti_process.log"

class ScannersDast:
    def __init__(self, target_url, proxy_IpAddress, proxy_PortAddress, zap_APIkey, current_time):#, apikey, ip_address, port):
        parsedURL= urlparse(proxy_IpAddress)
        PATH = TMP_DIRECTORY + urlparse(target_url).netloc + "_" + current_time

        os.makedirs(PATH, exist_ok=True)

        print ('Launching ZAP instance...')
        subprocess.Popen(["/usr/local/bin/zap.sh","-daemon", "-config", "api.key=vcvicclkl5kegm34aba9dhroem",
        "-port", proxy_PortAddress],stdout=open(PATH + ZAP_PROCESS_LOG, "w"))

        print ('Waiting for ZAP to load, 1 min...')
        sleep(60)
        
        #Parse IpAddress
        parsedIpAddress = parsedURL.netloc
        if ( parsedIpAddress is None or parsedIpAddress == ""):
            parsedIpAddress = parsedURL.path 

        #Initializing Scanners
        self.zap = ZapScanner(PATH, parsedIpAddress, proxy_PortAddress, zap_APIkey) #zap
        self.wapiti = WapitiScanner(PATH, parsedIpAddress, proxy_PortAddress) #Wapiti

        #Creating inner classes     
        self.crawlers = self.Crawler(self)
        self.attacks = self.Attack(self)
        self.authentications = self.Authentication(self)
        self.alerts = self.Alert(self)

    def createContext(self, target_url, include_Urls, exclude_Urls):
        self.zap.createContext(target_url, include_Urls, exclude_Urls)
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

        def scanAsUser(self, scan_type, user_id):
            print ('Selecting scan method: '+scan_type.name)

            if (scan_type.name=='FULL'):
                self.fullScanAsUser(user_id)
            elif(scan_type.name=='APIONLY'):
                raise Exception ("APIONLY: Not support as User")
            elif(scan_type.name=='TRADITIONAL'):
                self.scanTradionalAsUser(user_id)
            elif(scan_type.name=='AJAX'):
                self.scanAjaxAsUser(user_id)

        def scanTradional(self):
            print("ZAP: Starting traditional scanning")
            self.zap.crawlers.scanTradional()

            print("Wapiti: Starting traditional scanning")
            self.wapiti.crawlers.scanTradional()

        def scanTradionalAsUser(self, user_id):
            self.zap.authentications.forceUserMode(user_id)

            print("ZAP: Starting traditional scanning with user: "+user_id)
            self.zap.crawlers.scanTradionalAsUser(user_id)
            
            print("Wapiti: Starting traditional authenticated via ZAP Proxy")
            self.wapiti.crawlers.scanTradional()

            self.zap.authentications.releaseUserMode()
        def scanAjax(self):
            print("ZAP: Starting AJAX scanning")
            self.zap.crawlers.scanTradional()

            logging.warning("Wapiti: doens't support AJAX scanning")

        def scanAjaxAsUser(self, user_id):
            self.zap.authentications.forceUserMode(user_id)

            print("ZAP: Starting AJAX scanning with user: "+user_id)
            self.zap.crawlers.scanTradional()
            logging.warning("Wapiti: doens't support AJAX scanning")

            self.zap.authentications.releaseUserMode()

        def readOpenApi(self, apiUrl, apiDefinitionURI):
            if (apiUrl is None or apiUrl == "" or apiDefinitionURI is None or apiDefinitionURI == ""):
                raise Exception('Please provide a valid APIURL and APIDefinition')
            print("ZAP: Starting to read OpenAPI definition entries")
            self.zap.crawlers.readOpenApi(apiUrl, apiDefinitionURI)
            
            logging.warning("Wapiti: Doesnt support OpenAPI definitions natively")
            print("Wapiti: Using entries retrieved by Zap instead")

            urlEntries = self.zap.crawlers.exportUrlScanEntries()
            self.wapiti.crawlers.readUrlEntries(urlEntries)

        def fullScan(self, apiUrl, apiDefinitionURI):
            self.scanTradional()
            self.scanAjax()
            self.readOpenApi(apiUrl, apiDefinitionURI)

        def fullScanAsUser(self, user_id):
            self.scanTradionalAsUser(user_id)
            self.scanAjaxAsUser(user_id)
            logging.warning("OpenAPI definition will not be loaded when scanning as User")

    class Attack:
        def __init__(self, scanners):
            self.zap = scanners.zap
            self.wapiti = scanners.wapiti

        def startPassiveScan(self):
            print("ZAP: Starting passive scanning")
            self.zap.attacks.startPassiveScan()

            logging.warning("Wapiti: Doesn't support passive scanning")

        def startActiveScan(self):
            logging.warning("Active scanning my overload the target machine")

            print("ZAP: Starting active scanning")
            self.zap.attacks.startActiveScan()

            print("Wapiti: Start active scanning")
            self.wapiti.attacks.startActiveScan()

        def startActiveScanAsUser(self, user_id):
            logging.warning("Active scanning my overload the target machine")
            self.zap.authentications.forceUserMode(user_id)

            print("ZAP: Starting active scanning with user: "+user_id)
            self.zap.attacks.startActiveScanAsUser(user_id)

            print("Wapiti: Starting active scanning authenticated via ZAP Proxy")
            self.wapiti.attacks.startActiveScan()

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
