#!/usr/bin/env python

import re
import csv
from bs4 import BeautifulSoup
import urllib2
import csv
import re
import time
import sys
import argparse
from datetime import datetime
import requests

import logging
logging.basicConfig()
logger = logging.getLogger('root')

timestamp = str(datetime.strftime(datetime.today(),'%Y%m%d%H%M%S'))

#NAME: main
#INPUT: csv containing IP Addresses to query in first column
#OUTPUT: Text file containing blacklist information of IP Address
#DESCRIPTION: Compare a list of IP address against ipvoid.com for blacklisted IP addresses
# Usage Example : python ipv4BlacklistChecker-v3.py
# Sample of Input File :
#115.78.230.120
#117.3.101.181
#117.6.130.188
#118.69.204.200
def main(input_ipaddresslist):
	count=0 #Count number of ips finished
	private_ip_address = ('10.', '172.16.', '172.31.', '192.168')
	output_resultfile = '.\Results\\' + timestamp + "_IPv4BlacklistResult.txt"
	url = "http://www.ipvoid.com/ip-blacklist-check/"

	#Getting user input for ip address list
	try:
		with open ('%s' %input_ipaddresslist,'rb') as inputlist, open (output_resultfile,'wb') as outputlist:
			reader = csv.reader(inputlist)
			writer = csv.writer(outputlist)
			for row in reader:
				ip = row[0]
				if not ip.startswith(private_ip_address):
					logger.info("Checking %s for blacklist" % (ip)) 		
					req = requests.post(url, data={'ip':ip})
					if req.status_code == 200:
						logger.info("Parsing result for %s" % (ip))				
						soup = BeautifulSoup(req.text,"html.parser")
						try:					
							b = soup.find("table")
							str1 = b.find('td')
							str2 = str1.find_next('td').find_next('td').find_next('td')
							str3 = str(str2.find("span").contents)[3:-2]
							ips = {"Name":ip,"Status":str3}
							writer.writerow([ips['Name'],ips['Status']])
							logger.debug("Saving result for " + row[0])
						except:
							try:
								c = soup.find('h1').contents
								logger.debug(str(c)[3:-2])
							except:
								with open('%s.html' %count, "wb") as code:
									code.write(str(soup))
								continue
							continue
					else:
						logger.error("Request to ipvoid failed!")					
				else:
					logger.error("%s is a private IP address and will not be checked." % (ip))
	except Exception as e:
		logger.error("Failed to query ipvoid due to %s" % e.message)
		
if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Checks if IP is blacklisted")
	parser.add_argument('-f', dest='filename', required=True, help="Filename containing the list of IP address to be checked") 
	args = parser.parse_args()
	main(args.filename)
