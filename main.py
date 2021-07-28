import argparse
import json
import urllib
from scanners_sast import ScannersSast
from scanners_dast import ScannersDast
from scan_mode import ScanMode
from urllib.parse import urlparse

'''
/usr/bin/python3 /home/marquez/Desktop/wsap/main.py --scanner.ip http://127.0.0.1 --scanner.port 8010 --scanner.key vcvicclkl5kegm34aba9dhroem --scan.mode FULL --scan.apiUrl https://test-lm-api.void.pt/ --scan.apiDefinition file:///home/marquez/Desktop/openapi.json --performAttack --login.url http://target_url.com/api/authentication/login --login.request "{\"name\":\"name\",\"username\":\"username\",\"password\":\"password\"}" --login.userField username --login.passField password --login.user AltesBesta ItsSecret --login.user excuseme nope --login.user bob thebuilder
'''
parser = argparse.ArgumentParser(prog='Web Security Application Project(WSAP)')

#Sast
sast_scanner = parser.add_argument_group('⭐SAST Scanner Properties⭐')
sast_scanner.add_argument('-sT','--target', help='The target web application directory path')

#Dast
dast_scanner = parser.add_argument_group('⭐DAST Scanner Properties⭐', 'Scanner Properties:')
dast_scanner.add_argument('-dIp','--scanner.ip', help='The current Scanner IP Address')
dast_scanner.add_argument('-dPort','--scanner.port', help='The current Port the scanner is listening too')
dast_scanner.add_argument('-dKey','--scanner.key', help='A Random Key value used by the scanner to authenticate to the API')

dast_required = parser.add_argument_group('Required arguments')
dast_required.add_argument('-dT','--targetUrl', help='The url base of the target web application')
dast_required.add_argument('-dM','--scan.mode', type=ScanMode.argparse, choices=list(ScanMode), help='The scan mode being used')

dast_optional = parser.add_argument_group('Optional arquments')
dast_optional.add_argument('-dI','--includeUrl', action='append', help='Additional url to include into context (Can be used multiple times)')
dast_optional.add_argument('-dE','--excludeUrl', action='append', help='Excude url from the context (Can be used multiple times)')
dast_optional.add_argument('-dA','--performAttack', action='store_true', help='Activate the attack modules on to the target')
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

#SAST SCANNER
scanner_target = getattr(args, 'target')
if (scanner_target is not None):
    print ('Starting SAST scan')
    scanners_sast = ScannersSast()
    scanners_sast.scanner.start(scanner_target)

#DAST SCANNER
scanner_ip = getattr(args, 'scanner.ip')
scanner_port = getattr(args, 'scanner.port')
scanner_key = getattr(args, 'scanner.key')
if (scanner_ip is not None) or (scanner_port is not None) or (scanner_key is not None):
    print ('Starting DAST scan:')
    print ('Creating instance...')
    scanner_ip = getattr(args, 'scanner.ip')
    scanner_port = getattr(args, 'scanner.port')
    scanner_key = getattr(args, 'scanner.key')
    scanners_dast = ScannersDast(scanner_ip, scanner_port, scanner_key) #zap

    print ('Creating profile...')
    target_Url = getattr(args, 'targetUrl') #"https://test-lm.void.pt/" #"http://localhost:8090/bodgeit/"
    include_Urls = getattr(args, 'includeUrl')
    exclude_Urls = getattr(args, 'excludeUrl')
    scanners_dast.createContext(target_Url, include_Urls, exclude_Urls)

    #3) Crawling / Exploring 
    # Full, OpenApi, Normal Crawl, Ajax Crawl, 
    print ('Launching crawler...')
    scan_mode = getattr(args, 'scan.mode')
    scan_apiUrl = getattr(args, 'scan.apiUrl') #"https://test-lm-api.void.pt/"
    scan_apiDefitinion = getattr(args, 'scan.apiDefinition') #"file:///home/marquez/Desktop/openapi.json"
    scanners_dast.crawlers.scan(scan_mode, scan_apiUrl, scan_apiDefitinion)

    #4) Attack
    if args.performAttack is not None:
        print ('Launching attack...')
        scanners_dast.attacks.startActiveScan()

    #5) Display Alertsf
    #zap.alerts.display()S

    #6) Authenticate BY
    login_url = getattr(args, 'login.url')
    login_JSON_Request = json.loads(urllib.parse.unquote(getattr(args, 'login.request')))
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
            login_usernameFieldName, login_passwordFieldName, Zap_logged_in_regex, Zap_logged_out_regex)
        
        #2) Scan
        scanners_dast.crawlers.scanAsUser(scan_mode,user_id)
        
        #3) Perform Attack
        if args.performAttack is not None:
            print ('Launching attack...')
            scanners_dast.attacks.startActiveScanAsUser(user_id)

    #Zap_loginUrl="http://localhost:8090/bodgeit/login.jsp"
    ##Zap_loginUsername = "test1@test.com"
    #Zap_loginPassword = "test123"
    #Zap_UsernameFieldName = "username"
    #Zap_PasswordFieldName = "password"
    #Zap_logged_in_regex = ""
    #Zap_logged_out_regex = r'\Q<a href="logout.jsp">Logout</a>\E'
    #zap.authentications.performFormBasedLogin(Zap_loginUrl, Zap_loginUsername,Zap_loginPassword,logged_out_regex=Zap_logged_out_regex)

    #Client
    '''
    Zap_loginUrl="https://test-lm-api.void.pt/authentication/login"
    Zap_login_dataJSON ='{"cartId": "3fa85f64-5717-4562-b3fc-2c963f66afa6","email": "nb.reis@campus.fct.unl.pt","password": "12345"}'
    Zap_UsernameFieldName = "email"
    Zap_PasswordFieldName = "password"
    Zap_logged_in_regex = ""
    Zap_logged_out_regex = r'\Q<a href="logout.jsp">Logout</a>\E'
    user_id=scanners_dast.authentications.performJSONLogin(Zap_loginUrl, Zap_login_dataJSON, Zap_UsernameFieldName, Zap_PasswordFieldName, logged_out_regex=Zap_logged_out_regex)
    #scanners_dast.crawlers.scanTradionalAsUser(user_id)
    #scanners_dast.crawlers.scanAjaxAsUser(user_id)
    scanners_dast.crawlers.fullScanAsUser(user_id)
    scanners_dast.attacks.startActiveScanAsUser(user_id)

 -
    #Logista(FAIL) - not working
    Zap_loginUrl="https://test-lm-api.void.pt/authentication/login"
    Zap_login_dataJSON ='{"cartId":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"nuno.reis@voidsoftware.com","password":"12345"}'
    Zap_UsernameFieldName = "email"
    Zap_PasswordFieldName = "password"
    Zap_logged_in_regex = ""
    Zap_logged_out_regex = r'\Q<a href="logout.jsp">Logout</a>\E'
    user_id=scanners_dast.authentications.performJSONLogin(Zap_loginUrl, Zap_login_dataJSON, Zap_UsernameFieldName, Zap_PasswordFieldName, logged_out_regex=Zap_logged_out_regex)
    #scanners_dast.crawlers.scanTradionalAsUser(user_id)
    #scanners_dast.crawlers.scanAjaxAsUser(user_id)
    scanners_dast.crawlers.fullScanAsUser(user_id)
    scanners_dast.attacks.startActiveScanAsUser(user_id)

    #Admin
    Zap_loginUrl="https://test-lm-api.void.pt/authentication/login"
    Zap_login_dataJSON ='{"cartId": "3fa85f64-5717-4562-b3fc-2c963f66afa6","email": "admin@leiriamarket.pt","password": "hud6&ç#R[f1"}'
    Zap_UsernameFieldName = "email"
    Zap_PasswordFieldName = "password"
    Zap_logged_in_regex = ""
    Zap_logged_out_regex = r'\Q<a href="logout.jsp">Logout</a>\E'
    user_id=scanners_dast.authentications.performJSONLogin(Zap_loginUrl, Zap_login_dataJSON, Zap_UsernameFieldName, Zap_PasswordFieldName, logged_out_regex=Zap_logged_out_regex)
    #scanners_dast.crawlers.scanTradionalAsUser(user_id)
    #scanners_dast.crawlers.scanAjaxAsUser(user_id)
    scanners_dast.crawlers.fullScanAsUser(user_id)
    scanners_dast.attacks.startActiveScanAsUser(user_id)

    #7) Scan as Userq
    #zap.alerts.display()
    '''

    # To close ZAP:
    #scanners_dast.shutdown(=
