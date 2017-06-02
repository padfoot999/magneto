#!/usr/bin/python -tt
__description__ = 'Configuration file to store all "global" variables and setup logging'
# Usage:
# from config import CONFIG
# list_of_vt_api_keys = CONFIG['VTCHECKER']['VT_API2_KEYS']
# proxies = CONFIG['ONLINE']['PROXIES']
# is_mitm_proxy = CONFIG['ONLINE']['MITMPROXY']


import logging
import os
import OUTPUT_log
OUTPUT_log.setupLogger('root')

# Install tor browser when VT has blocked your IP address. Use socks5 proxy for tor.
# URL: https://www.torproject.org/download/download-easy.html.en
#NAME: isMitmProxy
#OUTPUT: TRUE or FALSE
#DESCRIPTION: To determine if we want to disable SSL cert verification if we are using a proxy (as MITM cert injection is most likely present)
# Usage E.g:
# import requests
# req = requests.get(
#             url, 
#             params={'resource': query, 'apikey': self.vt_api2_key}, 
#             proxies=getProxies(),
#             verify=(not isMitmProxy()))
def isMitmProxy():
    #return PROXIES["http"].count('proxy.proxy.proxy.com:8080/') or PROXIES["https"].count('proxy.proxy.proxy.com:8080/')
    return PROXIES["http"].count('socks5://127.0.0.1:9150') or PROXIES["https"].count('socks5://127.0.0.1:9150')

#NAME: PROXIES
#OUTPUT: N/A
#DESCRIPTION: Proxy config for use in Requests library 
#Refer to http://requests.readthedocs.org/en/master/user/advanced/#proxies
PROXIES = {
    # take from these examples and mod as per necessary
    "http": "",
    #"http": "socks5://127.0.0.1:9150", 
    #"http": "http://proxy.proxy.proxy.com:8080/",
    #"http": "http://10.10.1.10:3128",   
    "https": "", 
    #"https": "socks5://127.0.0.1:9150",
    #"https": "http://proxy.proxy.proxy.com:8080/",
    #"https": "http://10.10.1.10:1080",    
}

#NAME: PROXIES
#OUTPUT: N/A
#DESCRIPTION: Proxy config for use in Requests library 
VT_API2_KEYS = []
try:
    with open('config_vtKeys.txt') as f:
        for line in f:
            #Copy all virustotal API keys to memory... ...
            VT_API2_KEYS.append(line.strip())
except:
    pass
# finally:
#     print "%s keys in VT keypool loaded" % len(VT_API2_KEYS)

#NAME: CONFIG
#OUTPUT: N/A
#DESCRIPTION: Main Configuration parameters
CONFIG = {

    'DATABASE': {
        'DATABASENAME': "'magneto'",
        'HOST': "'127.0.0.1'",
        'USER': "'postgres'",
        'PASSWORD': "'<INSERT PASSWORD TO MAGNETO DATABASE'",
    },

    'ONLINE': {
        'PROXIES': PROXIES,
        'MITMPROXY': isMitmProxy(),
    },

	'VTCHECKER': {
        'DEBUG_FLAG': False,     
        'SHOW_LINE_COUNTER': False,
        'ENABLE_DB_RESULTS_FILTER': False,
        'ENABLE_NSRL_FILTER': False,
        'MAX_VT_DAEMONS': 100,
        'VT_API2_KEYS': VT_API2_KEYS,
        'VT_RESULT': 'results/json/report/',
        'VT_UPLOAD_RESULT': 'results/json/uploadstatus/',
        'VT_UPLOAD_REPORT_RESULT': 'results/json/uploadreport/',
        'MALWR_UPLOAD_RESULT': 'results/malwr/',
        'MALWR_LOGIN_USERNAME': '<INSERT MALWR LOGIN USERNAME>',
        'MALWR_LOGIN_PASSWORD': '<INSERT MALWR PASSWORD',
        'EXIFTOOL_RESULT': 'results/exiftool/',
        'RESULTS_TO_DB': False,
        'RESULTS_TO_EXCEL': True,
        'EXCEL_LINES_MAX': 1000000,
        'MAGIC_FILE': '/usr/share/misc/magic.mgc',
        'CUCKOO_PATH': '/opt/cuckoo',
        'FILE_CLEANUP': False,        
	},
    'CVE': {
        'NVD_CACHE': 'nvd_cache',
    },
}