from scanners_dast import ScannersDast
from urllib.parse import urlparse
import json
import time
import sys
import os
import logging

TMP_DIRECTORY =  os.path.dirname(__file__) + "/tmp/"
INSIDER_REPORT = "/insider_report.json"
ZAP_REPORT = "/zap_report.json"
WAPITI_REPORT = "/wapiti_report"
AUDIT_REPORT = "/audit_report.json"

LIMIT = 7 #A vulnerabilty will be consider high if it reaches at least 7
HIGH_LEVEL = 3
MEDIUM_LEVEL = 2
LOW_LEVEL = 1
INFO_LEVEL = 0

class VulnerabilityAudit:
    def __init__(self, target_url, current_time, users):
        PATH = TMP_DIRECTORY + urlparse(target_url).netloc + "_" + current_time

        os.makedirs(PATH, exist_ok=True)
        print ('Processing reports...')

        self.insider_vulnerabilities = json.loads('{ "High" : [], "Medium" : [], "Low" : [], "Info" : [] }')
       
        #Initializing Scanners
        insider_path = PATH  + INSIDER_REPORT
        try:
            print("Loading file: "+insider_path)
            with open(insider_path) as json_file:
                insider_report = json.load(json_file)
                for vulnerability in insider_report["vulnerabilities"]:
                    scaled_cvss = int(float(vulnerability["cvss"]) * float(HIGH_LEVEL) / LIMIT)
                    if (scaled_cvss > HIGH_LEVEL):
                        scaled_cvss = scaled_cvss
                    self.append(self.insider_vulnerabilities,scaled_cvss,vulnerability)

            #print(self.insider_vulnerabilities)
        except IOError:
            print("Unable to load file:"+ insider_path)
            self.insider_vulnerabilities = json.loads('{}')

        self.zap_vulnerabilities = json.loads('{ "High" : [], "Medium" : [], "Low" : [], "Info" : [] }')
        zap_path = PATH + ZAP_REPORT
        try:
            print("Loading file: "+ zap_path)
            with open(zap_path) as json_file:
                zap_report = json.load(json_file)
                for vulnerability in zap_report:
                    level = vulnerability["risk"]
                    self.zap_vulnerabilities[level].append(vulnerability)
            
            #print(self.zap_vulnerabilities)
        except IOError:
            print("Unable to load file:"+ zap_path)
            self.zap_vulnerabilities = json.loads('{}')
		
        self.wapiti_vulnerabilities = json.loads('{ "High" : [], "Medium" : [], "Low" : [], "Info" : [] }')
        wapiti_path = PATH + WAPITI_REPORT + ".json"
        try:
            print("Loading file: "+ wapiti_path)
            with open(wapiti_path) as json_file:
                wapiti_report = json.load(json_file)
                vulnerabilities = wapiti_report["vulnerabilities"]
                for vul_category in vulnerabilities:
                    for vulnerability in vulnerabilities[vul_category]:
                        vulnerability["vulnerability_type"] = vul_category
                        cvss = vulnerability["level"]
                        self.append(self.wapiti_vulnerabilities,cvss,vulnerability)

            for (username,password) in users:
                wapiti_path = PATH + WAPITI_REPORT + "_" + username +".json"
                print("Loading file: "+ wapiti_path)
                with open(wapiti_path) as json_file:
                    wapiti_report = json.load(json_file)
                    vulnerabilities = wapiti_report["vulnerabilities"]
                    for vul_category in vulnerabilities:
                        for vulnerability in vulnerabilities[vul_category]:
                            vulnerability["vulnerability_type"] = vul_category
                            vulnerability["asUser"] = username
                            cvss = vulnerability["level"]
                            self.append(self.wapiti_vulnerabilities,cvss,vulnerability)

            #print(self.wapiti_vulnerabilities)
        except IOError:
            print("Unable to load file:"+ wapiti_path)
            self.wapiti_vulnerabilities = json.loads('{}')

        self.vulnerabilty_audit = {
            "SAST_InsiderCLI": self.insider_vulnerabilities,
            "DAST_ZAP": self.zap_vulnerabilities,
            "DAST_WAPITI": self.wapiti_vulnerabilities
        }

        audit_path = PATH + AUDIT_REPORT
        with open(audit_path, 'w') as outfile:
            json.dump(self.vulnerabilty_audit, outfile, ensure_ascii=False, indent=4)

        #self.vulnerabilty_audit = json.load(self.vulnerabilty_audit)

        print("\nAnalysis Summary:")
        for key,value in self.vulnerabilty_audit.items():
            print("\n"+key)
            for key,value in value.items():
                print("- {} [{}]".format(key, len(value)))

        print("\nReport successfully generated in: ")
        print(audit_path)

    def get_report(self):
        return self.vulnerabilty_audit

    def append(self, root, level, vulnerability):
        if (level >= HIGH_LEVEL):
            root["High"].append(vulnerability)
        elif (level == MEDIUM_LEVEL):
            root["Medium"].append(vulnerability)
        elif (level == LOW_LEVEL):
            root["Low"].append(vulnerability)
        else:
            root["Info"].append(vulnerability)