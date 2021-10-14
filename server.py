import argparse
import json
import sys
import socket
from logging import currentframe
import logging
from traceback import format_exc
import pathlib
import urllib
import subprocess, os
from datetime import datetime
from scanners_sast import ScannersSast
from scanners_dast import ScannersDast
from vunerabilty_audit import VulnerabilityAudit
from scan_mode import ScanMode
from urllib.parse import urlparse
import psutil

print("Server starting")

#Create a socket
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

ip = "127.0.0.1"
port = int(sys.argv[1])

# Binding socket to specified ip address and port
socket.bind((ip, port))

# This is max ammount of clients we will accept
socket.listen(1)

# Accepting connection from client
sock, addr = socket.accept()
print("Client connected from", addr)

# Receiving data from client
print("Waiting for data")
data = sock.recv(16384) # Raw data from client
jsonData = json.loads(data.decode('utf-8')) # Decoding it
print("Recieved data")

try:
    #Target
    target_url = jsonData['target.url']
    current_time = datetime.now().strftime("%Y_%m_%d_%H:%M:%S")

    #SAST SCANNER
    scanner_target = jsonData['sastAnalysis']['target']
    if (scanner_target is not None): 
        sendJSON = json.dumps({"info" : str("Starting SAST scan")})
        sock.send(sendJSON.encode())

        scanners_sast = ScannersSast(target_url, current_time)
        scanners_sast.scanner.start(scanner_target)

    #DAST SCANNER
    scanner_ip = jsonData['scanner.ip']
    scanner_port = jsonData['scanner.port']

    if (scanner_ip is not None) or (scanner_port is not None):
        dast_analysis = jsonData['dastAnalysis']

        sendJSON = json.dumps({"info" : str("Starting DAST scan")})
        sock.send(sendJSON.encode())
        scan_properties = dast_analysis['scan.properties']
        scan_mode = ScanMode[scan_properties['scan.mode']]
        scanners_dast = ScannersDast(target_url, scanner_ip, scanner_port, scan_mode, current_time)

        sendJSON = json.dumps({"info" : str("Creating profile...")})
        sock.send(sendJSON.encode())

        include_Urls = []
        if "includes" in dast_analysis:
            for include in dast_analysis['includes']:
                include_Urls.append(include['include.url'])

        exclude_Urls = []
        if "excludes" in dast_analysis:
            for exclude in dast_analysis['excludes']:
                exclude_Urls.append(include['exclude.url'])
        
        scanners_dast.createContext(target_url, include_Urls, exclude_Urls, current_time)

        #3) Crawling / Exploring 
        # Full, OpenApi, Normal Crawl, Ajax Crawl
        sendJSON = json.dumps({"info" : str("Launching crawler...")})
        sock.send(sendJSON.encode())

        scan_apiUrl = scan_properties['scan.apiUrl']
        scan_apiDefitinion = scan_properties['scan.apiDefinition']
        scanners_dast.crawlers.scan(scan_mode, scan_apiUrl, scan_apiDefitinion)

        #4) Attack
        sendJSON = json.dumps({"info" : str("Launching attack...")})
        sock.send(sendJSON.encode())
        scanners_dast.attacks.startActiveScan()

        #5) Authenticate
        login_data = dast_analysis["loginProperties"]
        login_url = login_data['login.url']
        login_request = login_data['login.request']

        if (login_url is not None) and (login_request is not None):
            login_headers = []
            if "login.headers" in login_data:
                for header in login_data['login.headers']:
                    login_headers.append([header["header"],header["value"]])
                            
            login_JSON_Request = json.loads(urllib.parse.unquote(login_request))

            login_usernameFieldName = str(login_data['login.userField'])
            login_passwordFieldName = str(login_data['login.passField'])
            Zap_logged_in_regex = ""
            Zap_logged_out_regex = r'\Q<a href="logout.jsp">Logout</a>\E'

            users = []
            if "users" in login_data:
                for user in login_data['users']:
                    users.append([user["username"],user["password"]])
                    
            for (username,password) in users:
                login_JSON_Request[login_usernameFieldName] = username
                login_JSON_Request[login_passwordFieldName] = password
                
                #1) Create User
                sendJSON = json.dumps({"info" : str("Creating user: "+str(username))})
                sock.send(sendJSON.encode())
                user_id=scanners_dast.authentications.performJSONLogin(login_url, login_headers, login_JSON_Request, 
                    field_username=login_usernameFieldName, field_password=login_passwordFieldName)
                
                #2) Scan
                sendJSON = json.dumps({"info" : "Scanning as user: "+str(username)})
                sock.send(sendJSON.encode())
                scanners_dast.crawlers.scanAsUser(scan_mode,user_id, username)
                
                #3) Perform Attack
                sendJSON = json.dumps({"info" : "Attacking as user: "+str(username)})
                sock.send(sendJSON.encode())
                scanners_dast.attacks.startActiveScanAsUser(user_id, username)

        #6) Report
        sendJSON = json.dumps({"info" : "Generating report"})
        sock.send(sendJSON.encode())

        scanners_dast.alerts.report()

        # To close ZAP:
        scanners_dast.shutdown()

    users = []
    if "users" in login_data:
        for user in login_data['users']:
            login_headers.append({user["username"]:user["password"]})

    vulnerabilty_audit = VulnerabilityAudit(target_url, current_time, users)

    sendJSON = json.dumps({"info" : "\nAnalysis Summary:"})
    sock.send(sendJSON.encode())

    for tool,analysis in vulnerabilty_audit.items():
        for level,results in analysis.items():
            analysis[level]=len(results)

    sendJSON = json.dumps(vulnerabilty_audit)
    sock.send(sendJSON.encode())

except Exception as e:
    error_message = format_exc()
    sendJSON = json.dumps({"error" : str(error_message)})
    sock.send(sendJSON.encode())
    print("Sending exception to client")
finally:
    #Closing all created child processes
    for process in psutil.process_iter():
        _ppid = process.ppid()
        if _ppid == os.getpid():
            _pid = process.pid
            if sys.platform == 'win32':
                process.terminate()
            else:
                os.system('kill -9 {0}'.format(_pid))

    sock.shutdown()
    sock.close()


