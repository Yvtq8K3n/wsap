import argparse
import json
from logging import currentframe
import urllib
from datetime import datetime
from scanners_sast import ScannersSast
from scanners_dast import ScannersDast
from scan_mode import ScanMode
from urllib.parse import urlparse

'''
/usr/bin/python3 main.py --scanner.ip http://127.0.0.1 --scanner.port 8010 --target.url https://test-lm.void.pt --include.url https://test-lm.void.pt/robots.txt --include.url https://test-lm.void.pt/favicon.ico --scan.mode FULL --scan.apiUrl https://test-lm-api.void.pt --scan.apiDefinition /home/marquez/Desktop/wsap/tmp/openapi.json --login.url https://test-lm-api.void.pt/authentication/login --login.request "{\"cartId\":\"3fa85f64-5717-4562-b3fc-2c963f66afa6\",\"email\":\"string\",\"password\":\"string\"}" --login.userField email --login.passField password --login.user admin@leiriamarket.pt "hud6&ç#R[f1"
'''

parser = argparse.ArgumentParser(prog='Web Security Application Project(WSAP)')

parser.add_argument('-dT','--target.url', help='The url base of the target web application')

#Sast
sast_scanner = parser.add_argument_group('⭐SAST Scanner Properties⭐')
sast_scanner.add_argument('-sT','--target', help='The target web application directory path')

#Dast
dast_scanner = parser.add_argument_group('⭐DAST Scanner Properties⭐', 'Scanner Properties:')
dast_scanner.add_argument('-dIp','--scanner.ip', help='The current Scanner IP Address')
dast_scanner.add_argument('-dPort','--scanner.port', help='The current Port the scanner is listening too')

dast_required = parser.add_argument_group('Required arguments')
dast_required.add_argument('-dM','--scan.mode', type=ScanMode.argparse, choices=list(ScanMode), help='The scan mode being used')

dast_optional = parser.add_argument_group('Optional arquments')
dast_optional.add_argument('-dI','--include.url', action='append', help='Additional url to include into context (Can be used multiple times)')
dast_optional.add_argument('-dE','--exclude.url', action='append', help='Excude url from the context (Can be used multiple times)')
dast_optional.add_argument('--scan.apiUrl', help='Activate the attack modules on to the target')
dast_optional.add_argument('--scan.apiDefinition', help='Activate the attack modules on to the target')

login_properties = parser.add_argument_group('Login properties')
login_properties.add_argument('--login.url', help='The login url necessary to successfully log into the application')
login_properties.add_argument('--login.request', help='A skeleton of the JSON Request sent to perform a successfull login')
login_properties.add_argument('--login.userField', help='The Username key used on the JSON Request Login')
login_properties.add_argument('--login.passField', help='The Password key used on the JSON Request Login')
#group2.add_argument('--login.loggedInRegex', help='A Regex indicator used to verify a successfull logged in state')
#group2.add_argument('--login.loggedOutRegex', help='A Regex indicator used to verify a logged out state')
login_properties.add_argument('-u','--login.user',action='append',nargs=2, metavar=('username','password'),help='The username:password of the wanted user (Can be used multiple times)')

args = parser.parse_args()

#Target
target_url = getattr(args, 'target.url') #forçar como obrigatorio
current_time = datetime.now().strftime("%Y_%m_%d_%H:%M:%S")

#SAST SCANNER
scanner_target = getattr(args, 'target')
if (scanner_target is not None):
    print ('Starting SAST scan')
    scanners_sast = ScannersSast(target_url, current_time)
    scanners_sast.scanner.start(scanner_target)

#DAST SCANNER
scanner_ip = getattr(args, 'scanner.ip')
scanner_port = getattr(args, 'scanner.port')

if (scanner_ip is not None) or (scanner_port is not None):

    print ('Starting DAST module:')
    scanners_dast = ScannersDast(target_url, scanner_ip, scanner_port, current_time)

    print ('Creating profile...')
    include_Urls = getattr(args, 'include.url')
    if include_Urls is None: 
        include_Urls = []

    exclude_Urls = getattr(args, 'exclude.url')
    if exclude_Urls is None: 
        exclude_Urls = []

    scanners_dast.createContext(target_url, include_Urls, exclude_Urls, current_time)

    #3) Crawling / Exploring 
    # Full, OpenApi, Normal Crawl, Ajax Crawl, 
    print ('Launching crawler...')
    scan_mode = getattr(args, 'scan.mode')
    scan_apiUrl = getattr(args, 'scan.apiUrl') #"https://test-lm-api.void.pt/"
    scan_apiDefitinion = getattr(args, 'scan.apiDefinition') #"file:///home/marquez/Desktop/openapi.json"
    scanners_dast.crawlers.scan(scan_mode, scan_apiUrl, scan_apiDefitinion)

    #4) Attack
    print ('Launching attack...')
    scanners_dast.attacks.startActiveScan()

    #5) Authenticate
    login_url = getattr(args, 'login.url')
    login_Request = urllib.parse.unquote(getattr(args, 'login.request'))
    login_JSON_Request = json.loads(login_Request)
    login_usernameFieldName = getattr(args, 'login.userField') 
    login_passwordFieldName = getattr(args, 'login.passField')
    Zap_logged_in_regex = ""
    Zap_logged_out_regex = r'\Q<a href="logout.jsp">Logout</a>\E'
    users = getattr(args, 'login.user')

    for (username,password) in users:
        login_JSON_Request[login_usernameFieldName] = username
        login_JSON_Request[login_passwordFieldName] = password

        #1) Create User
        user_id=scanners_dast.authentications.performJSONLogin(login_url, login_JSON_Request, 
            field_username=login_usernameFieldName, field_password=login_passwordFieldName)
        
        #2) Scan
        scanners_dast.crawlers.scanAsUser(scan_mode,user_id, username)
        
        #3) Perform Attack
        print ('Launching attack...')
        scanners_dast.attacks.startActiveScanAsUser(user_id, username)

    #6) Report
    scanners_dast.alerts.report()

    # To close ZAP:
    #scanners_dast.shutdown()
