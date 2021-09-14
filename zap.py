from zapv2 import ZAPv2
import logging
import time
import json
import urllib
import os
import subprocess
from pprint import pprint
from urllib.parse import urlparse

#Files
ZAP_PROCESS_LOG =  "/zap.log"
ZAP_REPORT =  "/zap_report.json"
STORE_URLS =  "/api_endpoints.txt"
ZAP_URLS =  "/zap_endpoints.txt"
AUTH_SCRIPT =  os.path.dirname(__file__) + '/Scripts/jwtScript.js'

class ZapScanner:

    def __init__(self, TMP_DIRECTORY, ip_address, port, apikey):
        self.TMP_DIRECTORY = TMP_DIRECTORY
        self.ip_address = ip_address
        self.port = port
        self.api_key = apikey
        self.zap = ZAPv2(apikey=apikey, proxies={'http': 'http://'+ip_address+':'+port, 'https': 'http://'+ip_address+':'+port})
        self.crawlers = self.Crawler(self)
        self.attacks = self.Attack(self)
        self.alerts = self.Alert(self)
        self.authentications = self.Authentication(self)

    def createContext(self, target_url, include_urls, exclude_urls, current_time):
        targetUrlParsed = urlparse(target_url)
        
        logging.info("ZAP: Creating Context")
        self.context_name = targetUrlParsed.hostname + "_" +current_time
        self.context_id = self.zap.context.new_context(self.context_name)
        print("New context created for "+self.context_name+" with id:"+self.context_id)

        # include target url
        self.target_url = target_url
        self.zap.context.include_in_context(self.context_name, target_url)

        # include additional url's
        for url in include_urls:
            self.zap.context.include_in_context(self.context_name, url)
            logging.info('Included %s and its subpaths', url)

        # exclude all urls that end the authenticated session
        if len(exclude_urls) == 0:
            self.zap.context.exclude_from_context(self.context_name, target_url+'/.*logout.*')
            self.zap.context.exclude_from_context(self.context_name, target_url+'/.*uitloggen.*')
            self.zap.context.exclude_from_context(self.context_name, target_url+'/.*afmelden.*')
            self.zap.context.exclude_from_context(self.context_name, target_url+'/.*signout.*')

        for url in exclude_urls:
            self.zap.context.exclude_from_context(self.context_name, url)
            self.zap.context.exclude_from_context(self.context_name+"/.*", url)
            logging.info('Excluded %s and its subpaths', url)

    def saveState(self):
        logging.info("Saving in memory Zap current state")
        self.urls = self.zap.context.urls(self.context_name)
        print("Urls found: " + str(len(self.urls)))

        print("Writing into file: " + self.TMP_DIRECTORY + ZAP_URLS)
        jsonUrls = json.dumps(self.urls)

        with open(self.TMP_DIRECTORY + ZAP_URLS, "w") as url_entries:
            url_entries.write(json.dumps(self.urls, indent=4))     

    def restoreState(self):
        print("Urls in zap: " + str(len(self.zap.context.urls(self.context_name))))

        print("Restoring Zap to its initial state")
        self.total_urls = self.zap.context.urls(self.context_name)
        self.fuzzer_urls = list(set(self.total_urls) - set(self.urls))

        for url in self.fuzzer_urls:
            logging.info("- Removing invalid url: "+ url)
            self.zap.core.delete_site_node(url)

        print("Urls in zap after: " + str(len(self.zap.context.urls(self.context_name))))

    def shutdown(self):
        self.zap.core.shutdown()

    class Crawler:
        def __init__(self, zapscanner):
            self.zapscanner = zapscanner
            self.zap = zapscanner.zap

        def scanTradional(self):
            logging.info('Spidering target {}'.format(self.zapscanner.context_name))

            print(self.zapscanner.target_url)
            print(self.zapscanner.context_name)
        
            # The scan returns a scan id to support concurrent scanning
            scanID = self.zap.spider.scan(url = self.zapscanner.target_url, contextname = self.zapscanner.context_name)
            
            while int(self.zap.spider.status(scanID)) < 100:
                # Poll the status until it completes
                logging.info('Spider progress %: {}'.format(self.zap.spider.status(scanID)))
                time.sleep(1)
            
            logging.info('Spider has completed!')
          
            # Prints the URLs the spider has crawled
            with open(self.zapscanner.TMP_DIRECTORY+ZAP_PROCESS_LOG, 'a+') as zap_log:
                zap_log.write('Spidering target {}'.format(self.zapscanner.context_name))
                zap_log.write('\r\n'.join(map(str, self.zap.spider.results(scanID))))
            
        def scanTradionalAsUser(self, user_id):
            if not self.zapscanner.authentications.isUseModeSet:
                raise Exception("Can't scan as user because User Mode is not enabled")

            user = self.zap.users.get_user_by_id(self.zapscanner.context_id, user_id)
            json_user = json.loads(user)

            logging.info('Spidering as {0} target: {1}'.format(json_user["username"], self.zapscanner.context_name))
            scanID = self.zap.spider.scan_as_user(contextid = self.zapscanner.context_id, userid=user_id, url=self.zapscanner.target_url)
            
            while int(self.zap.spider.status(scanID)) < 100:
                # Poll the status until it completes
                logging.info('Spider progress %: {}'.format(self.zap.spider.status(scanID)))
                time.sleep(1)
            
            logging.info('Spider has completed!')

            # Prints the URLs the spider has crawled
            with open(self.zapscanner.TMP_DIRECTORY+ZAP_PROCESS_LOG, 'a+') as zap_log:
                zap_log.write('Spidering as {0} target: {1}'.format(json_user["username"], self.zapscanner.context_name))
                zap_log.write('\n'.join(map(str, self.zap.spider.results(scanID))))
            # If required post process the spider results
            
        def scanAjax(self):            
            logging.info('Ajax Spider target {}'.format(self.zapscanner.context_name))
            scanID = self.zap.ajaxSpider.scan(contextname = self.zapscanner.context_name)

            timeout = time.time() + 60*2   # 2 minutes from now

            # Loop until the ajax spider has finished or the timeout has exceeded
            while self.zap.ajaxSpider.status == 'running':
                if time.time() > timeout:
                    break
                logging.info('Ajax Spider status: ' + self.zap.ajaxSpider.status)
                time.sleep(2)

            logging.info('Ajax Spider completed')
            ajaxResults = self.zap.ajaxSpider.results(start=0, count=10)

            with open(self.zapscanner.TMP_DIRECTORY+ZAP_PROCESS_LOG, 'a+') as zap_log:
                zap_log.write('Ajax Spider target {}'.format(self.zapscanner.context_name))
                zap_log.write(json.dumps(ajaxResults, indent=4))

        def scanAjaxAsUser(self, user_id):
            if not self.zapscanner.authentications.isUseModeSet:
                raise Exception("Can't scan as user because User Mode is not enabled")

            user = self.zap.users.get_user_by_id(self.zapscanner.context_id, user_id)
            json_user = json.loads((user))

            logging.info('Ajax Spider as {0} target: {1}'.format(json_user["username"],self.zapscanner.context_name))
            scanID = self.zap.ajaxSpider.scan_as_user(contextname = self.zapscanner.context_name, username=json_user["username"], url=self.zapscanner.target_url)
            timeout = time.time() + 60*2   # 2 minutes from now
            print(scanID)

            # Loop until the ajax spider has finished or the timeout has exceeded
            while self.zap.ajaxSpider.status == 'running':
                if time.time() > timeout:
                    break
                logging.info('Ajax Spider status: ' + self.zap.ajaxSpider.status)
                time.sleep(2)

            logging.info('Ajax Spider completed')
            ajaxResults = self.zap.ajaxSpider.results(start=0, count=3)
            #print(json.dumps(ajaxResults, indent=4))

            with open(self.zapscanner.TMP_DIRECTORY+ZAP_PROCESS_LOG,'a+') as zap_log:
                zap_log.write('Writing a sample of the ajax request performed')
                json.dump(ajaxResults, zap_log, ensure_ascii=False, indent=4)

        def readOpenApi(self, apiUrl, apiDefinitionURI):
            logging.info('Included API %s and its subpaths', apiUrl)
            self.zap.context.include_in_context(self.zapscanner.context_name, apiUrl + '.*')

            logging.info('OpenApi Reading target {}'.format(self.zapscanner.context_name))
            apiDefinitionParsed = urlparse(apiDefinitionURI)
            print (apiDefinitionParsed)

            if (apiDefinitionParsed.scheme=="http" or apiDefinitionParsed.scheme=="https"):
                logging.info("Importing api definition from url")
                self.zap.openapi.import_url(apiDefinitionParsed.path, apiUrl)
            else:
                try:
                    logging.info("Attempting to importing api definition from file")
                    self.zap.openapi.import_file(apiDefinitionParsed.path, apiUrl)
                except:
                   logging.warning("Scheme Format Not Supported")

        def exportUrlScanEntries(self):
            urlEntries = self.zap.context.urls(self.zapscanner.context_name)

            with open(self.zapscanner.TMP_DIRECTORY + STORE_URLS, 'a+') as f:
                for url in urlEntries:
                    f.write("%s\n" % url)
        
    class Attack:
        def __init__(self, zapscanner):
            self.zapscanner = zapscanner
            self.zap = zapscanner.zap

        def startPassiveScan(self):
            # TODO : explore the app (Spider, etc) before using the Passive Scan API, Refer the explore section for details
            logging.info('Active Scanning target {}'.format(self.zapscanner.context_name))

            while int(self.zap.pscan.records_to_scan) > 0:
                # Loop until the passive scan has finished
                logging.info('Records  scan : ' + self.zap.pscan.records_to_scan)
                time.sleep(2)

            print('Passive Scan completed')

            # Print Passive scan results/alerts
            print('Hosts: {}'.format(', '.join(self.zap.core.hosts)))

        def startActiveScan(self):
            print('Active Scanning target {}'.format(self.zapscanner.context_name))
            print(self.zapscanner.target_url)
            print(self.zapscanner.context_id)
            scanID = self.zap.ascan.scan(url=self.zapscanner.target_url, contextid=self.zapscanner.context_id)
            print(scanID)

            while int(self.zap.ascan.status(scanID)) < 100:
                # Loop until the scanner has finished
                print('Scan progress %: {}'.format(self.zap.ascan.status(scanID)))
                time.sleep(5)

            print('Active Scan completed')

        def startActiveScanAsUser(self, user_id):
            if not self.zapscanner.authentications.isUseModeSet:
                raise Exception("Can't scan as user because User Mode is not enabled")

            user = self.zap.users.get_user_by_id(self.zapscanner.context_id, user_id)
            json_user = json.loads((user))

            print('Active as {0} target: {1}'.format(json_user["username"],self.zapscanner.context_name))
            scanID = self.zap.ascan.scan_as_user(contextid=self.zapscanner.context_id, userid=user_id)
            print(scanID)

            while int(self.zap.ascan.status(scanID)) < 100:
                # Loop until the scanner has finished
                print('Scan progress %: {}'.format(self.zap.ascan.status(scanID)))
                time.sleep(5)

            print('Active Scan completed')
            # Print vulnerabilities found by the scanning
            print('Hosts: {}'.format(', '.join(self.zap.core.hosts)))

    class Alert:
        def __init__(self, zapscanner):
            self.zapscanner = zapscanner
            self.zap = zapscanner.zap

        def report(self):
            # Retrieve the alerts using paging in case there are lots of them
            alert_dict = []
            st = 0
            pg = 5000
            alert_count = 0

            alerts = self.zap.alert.alerts(baseurl=self.zapscanner.target_url,start=st, count=pg)
            blacklist = [1,2]

            while len(alerts) > 0:
                print('Reading ' + str(pg) + ' alerts from ' + str(st))
                alert_count += len(alerts)
                for alert in alerts:
                    if alert is not None:
                        plugin_id = alert.get('pluginId')
                        if plugin_id in blacklist:
                            continue
                        # if alert.get('risk') == 'High':
                            # Trigger any relevant postprocessing
                            # continue
                        if alert.get('risk') == 'Informational':
                            # Ignore all info alerts - some of them may have been downgraded by security annotations
                            continue
                    alert_dict.append(alert)
                st += pg
                alerts = self.zap.alert.alerts(baseurl=self.zapscanner.target_url, start=st, count=pg)
            print('Total number of alerts: ' + str(alert_count))

            print('Writing alerts to file')
            with open(self.zapscanner.TMP_DIRECTORY+ZAP_REPORT, 'w') as outfile:
                json.dump(alert_dict, outfile, ensure_ascii=False, indent=4)

    
    class Authentication:
        def __init__(self, zapscanner):
            self.zapscanner = zapscanner
            self.zap = zapscanner.zap

        def performFormBasedLogin(self, login_url, username, password, field_username="username", field_password="password", logged_in_regex=None, logged_out_regex=None):
            #set_logged_in_indicator
            self.zap.authentication.set_logged_in_indicator(self.zapscanner.context_id, logged_in_regex)
            print('Configured logged in indicator regex: ')

            #set_form_based_auth
            login_request_data = 'username={%username%}&password={%password%}'
            form_based_config = 'loginUrl=' + urllib.parse.quote(login_url) + '&loginRequestData=' + urllib.parse.quote(login_request_data)
            self.zap.authentication.set_authentication_method(self.zapscanner.context_id , 'formBasedAuthentication', form_based_config)
            print('Configured form based authentication')

            #set_user_auth_config():'
            user_id = self.zap.users.new_user(self.zapscanner.context_id, username)
            user_auth_config = 'username=' + urllib.parse.quote(username) + '&password=' + urllib.parse.quote(password)
            self.zap.users.set_authentication_credentials(self.zapscanner.context_id , user_id, user_auth_config)
            self.zap.users.set_user_enabled(self.zapscanner.context_id , user_id, 'true')
            self.zap.forcedUser.set_forced_user(self.zapscanner.context_id , user_id)
            self.zap.forcedUser.set_forced_user_mode_enabled('true')
            print('User Auth Configured')
            print('User created with id:'+user_id)
        
        def performJSONLogin(self, login_url, login_headers, login_Request, field_username, field_password, logged_in_regex=None, logged_out_regex=None):
            #upload_script
            script_name = 'jwtScript.js'
            script_type = 'httpsender'
            script_engine = 'Oracle Nashorn'
            file_name = AUTH_SCRIPT
            print("Loading Script: "+self.zap.script.load(script_name, script_type, script_engine, file_name))
            print("Activating Script: "+self.zap.script.enable(script_name))

            login_data = json.dumps(login_Request)
            #set_json_based_auth
            #print(login_Request)
            #login_data = bytes(str(login_Request), "utf-8")#.decode("unicode_escape")
            #print(login_data)
            json_based_config = 'loginUrl=' + urllib.parse.quote(login_url) +'&loginRequestData=' + urllib.parse.quote(login_data)
            print(json_based_config)
            
            self.zap.authentication.set_authentication_method(self.zapscanner.context_id, 'jsonBasedAuthentication', json_based_config)
            print('Configured JSON based authentication')
            
            #set_logged_in_indicator
            #logged_in_regex = '\Q<a href="logout.php">Logout</a>\E'
            #logged_out_regex = '(?:Location: [./]*login\.php)|(?:\Q<form action="login.php" method="post">\E)'
            self.zap.authentication.set_logged_in_indicator(self.zapscanner.context_id, logged_in_regex)
            self.zap.authentication.set_logged_out_indicator(self.zapscanner.context_id, logged_out_regex)
            print('Configured logged in indicator regex: ')
            
            #set_user_auth_config:
            login_dataJSON = login_Request
            username = login_dataJSON[field_username]
            password = login_dataJSON[field_password]
            print (username)
            print (password)
            user_id = self.zap.users.new_user(self.zapscanner.context_id, username)
            user_auth_config = 'username=' + urllib.parse.quote(username) + '&password=' + urllib.parse.quote(password)

            self.zap.users.set_authentication_credentials(self.zapscanner.context_id, user_id, user_auth_config)
            self.zap.users.set_user_enabled(self.zapscanner.context_id , user_id, 'true')

            print("Adding customs headers")
            if (login_headers is not None):
                for (header, value) in login_headers:
                    self.zap.script.set_script_var(scriptname=script_name,varkey=header, 
                        varvalue=value,apikey=self.zapscanner.api_key)

            return user_id

        def isUseModeSet(self):
            self.zap.forcedUser.is_forced_user_mode_enabled()

        def forceUserMode(self, user_id):
            print('Force user mode locked with user: '+user_id)
            self.zap.forcedUser.set_forced_user(self.zapscanner.context_id , user_id)
            self.zap.forcedUser.set_forced_user_mode_enabled('true')

        def releaseUserMode(self):
            print('Force user mode released')
            self.zap.forcedUser.set_forced_user_mode_enabled('false')