#!/usr/bin/python -tt
__description__ = 'Check reputation of IP Addresses'

import collections
import IO_databaseOperations as db
import json
import datetime
import psycopg2
from netaddr import * 
import re
from bs4 import BeautifulSoup
from config import CONFIG
import requests
import sys
import argparse
import os

import logging
logger = logging.getLogger('root')

#NAME: checkIpReputation
#INPUT: string ip_addr
#OUTPUT: dictionary obj (everything is a string)
'''
{
    'Blacklist Status': '0/40' (string containing a fraction of positive blacklist results out of the total number of sources checked),
    'IP Address': '8.8.8.8',
    'Reverse DNS': 'google-public-dns-a.google.com',
    'ASN': 'AS15169',
    'ASN Owner': 'Google Inc.',
    'ISP': 'Level 3 Communications',
    'Continent': 'North America',
    'Country Code': 'Flag (US) United States',
    'Latitude / Longitude': '37.386 / -122.084',
    'City': 'Mountain View',
    'Region': 'California'
}
'''
#DESCRIPTION: To check for ip address details from ipvoid.com.  Call this SPARINGLY as this function hits a website to get the data.  We don't want our IP to get blocked.
# Internal workings: if there is at least one "hit" under the blacklist status, positive MYWOT results are subtracted from the blacklist status score.
def checkIpReputation(ip_addr = ''):
    logging.info('checkIpReputation called on "%s"' % ip_addr)

    EMPTY_REPORT = {
        'Blacklist Status': '',
        'IP Address': ip_addr,
        'Reverse DNS': '',
        'ASN': '',
        'ASN Owner': '',
        'ISP': '',
        'Continent': '',
        'Country Code': '',
        'Latitude / Longitude': '',
        'City': '',
        'Region': '',
    }

    try:


        data = {}
        soup = BeautifulSoup(
			requests.get(
				"http://www.ipvoid.com/scan/%s" % ip_addr, 
				proxies=CONFIG['ONLINE']['PROXIES'],
				verify=(not CONFIG['ONLINE']['MITMPROXY'])
			).text, 
			"html.parser")

        if soup.find(string="Report not found"):
            return EMPTY_REPORT
        
        ipinfotable = soup.find(string="Analysis Date").parent.parent.parent.parent
        logger.info("ipinfotable is " + str(ipinfotable))

        ipblreporttable = soup.find(string="IP Blacklist Report").parent.findNext("table")
        # logger.info("ipblreporttable is " + str(ipblreporttable))

        blstatus = ipinfotable.find('span', {"class" : "label"}).string.encode()
        logger.info("blstatus is " + str(blstatus))

        blhits = int(re.findall(r'(\d+)/', blstatus)[0])
        logger.info("blhits is " + str(blhits))
        
        bltotal = int(re.findall(r'/(\d+)', blstatus)[0])        
        logger.info("bltotal is " + str(bltotal))

        #Remove false positive from MyWOT        
        # if blhits > 0:
        #     if ipblreporttable.find(string="  MyWOT").findNext("img").attrs['title'] != 'Clean':
        #         blhits -= 1

        logger.info("Parsing BeautifulSoup...")
        data['Blacklist Status'] = '%s/%s' % (blhits, bltotal)
        data['IP Address'] = ip_addr
        data['Reverse DNS'] = ipinfotable.find(string="Reverse DNS").parent.nextSibling.string.encode()
        data['ASN'] = ipinfotable.find(string="ASN").parent.nextSibling.string.encode()
        data['ASN Owner'] = ipinfotable.find(string="ASN Owner").parent.nextSibling.string.encode()
        data['ISP'] = ipinfotable.find(string="ISP").parent.nextSibling.string.encode()
        data['Continent'] = ipinfotable.find(string="Continent").parent.nextSibling.string.encode()
        data['Country Code'] = ipinfotable.find(string="Country Code").parent.nextSibling.text.encode().strip()
        data['Latitude / Longitude'] = ipinfotable.find(string="Latitude / Longitude").parent.nextSibling.text.encode()
        data['City'] = ipinfotable.find(string="City").parent.nextSibling.text.encode()
        data['Region'] = ipinfotable.find(string="Region").parent.nextSibling.text.encode()
        logging.info('checkIpReputation returning ip reputation report on "%s" in data structure.' % ip_addr)

        return data

    except Exception as excptn:
        logger.error("ERROR: in checkIpReputation.  Returning empty report data structure.\n%s\n%s" % (type(excptn), excptn.args))
        # print "ERROR: in checkIpReputation.  soup structure is %s" % soup
        return EMPTY_REPORT
    else:
        pass
    finally:
        pass



#NAME: jdefault
#INPUT: object obj
#OUTPUT: return object
#DESCRIPTION: To allow json support for the object types that have been specified
def jdefault(obj):
    if isinstance(obj, (list, dict, str, unicode, int, float, bool, type(None))):
        return list(obj)
    return obj.__dict__


#NAME: ipChecker
#INPUT: psycopg2-db-handle databaseConnectionHandle, string userInput
#OUTPUT: NONE
#DESCRIPTION: based on the type of input given, the ip address will be checked for its blacklisted status
#DESCRIPTION: if no input is given, all information of the ip addresses in the database will be given
def ipChecker(databaseConnectionHandle, userInput):
    logging.info("INFO: databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")

    #to enable all queries returned in a string format
    #delete any typecasters of psycopg2 
    psycopg2.extensions.string_types.clear()
    
    allBlacklisted = collections.OrderedDict()
    counter = 0

    if userInput:
        #check if userInput is an ip address

        if len(userInput.split(".")) == 4 and re.search(r'\d', userInput):
            #check if ip address given is valid, and is not a private address
            if IPAddress(userInput).is_unicast() and not IPAddress(userInput).is_private():
                ipCheck = checkIpReputation(userInput)
                logging.info("INFO: ipCheck is " + str(ipCheck) + "\n")
                
                #check if ip address was checked against ipvoid
                if ipCheck:
                    #check if the results retrieved is in form of a dictionary
                    if isinstance(ipCheck, dict):
                        #check if dict.key is empty
                        if ipCheck['Blacklist Status']:
                            try:
                                #if blacklisted, insert into database
                                if int(ipCheck['Blacklist Status'][0]) != 0:
                                    Schema = "ip_blacklist"
                                    Table = "blacklistedip"

                                    #check if ip address has already been added into database
                                    selectValue = collections.OrderedDict.fromkeys(['ipaddress'])
                                    whereValue = collections.OrderedDict.fromkeys(['ipaddress'])
                                    whereValue['ipaddress'] = ipCheck['IP Address']
                                    blacklistSelect = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)

                                    if not blacklistSelect:

                                        insertBlacklistValue = collections.OrderedDict.fromkeys(['ipaddress', 'blackliststatus', 'reversedns', 'asn', 'asnowner', 'isp', 'continent', 'countrycode', 'latitude_longitude', 'city', 'region'])

                                        insertBlacklistValue['ipaddress'] = ipCheck['IP Address']
                                        insertBlacklistValue['blackliststatus'] = ipCheck['Blacklist Status']
                                        insertBlacklistValue['reversedns'] = ipCheck['Reverse DNS']
                                        insertBlacklistValue['asn'] = ipCheck['ASN']
                                        insertBlacklistValue['asnowner'] = ipCheck['ASN Owner']
                                        insertBlacklistValue['isp'] = ipCheck['ISP']
                                        insertBlacklistValue['continent'] = ipCheck['Continent']
                                        insertBlacklistValue['countrycode'] = ipCheck['Country Code']
                                        insertBlacklistValue['latitude_longitude'] = ipCheck['Latitude / Longitude']
                                        insertBlacklistValue['city'] = ipCheck['City']
                                        insertBlacklistValue['region'] = ipCheck['Region']

                                        logging.info("INFO: insertBlacklistValue is " + str(insertBlacklistValue) + "\n")
                                        db.databaseInsert(databaseConnectionHandle, Schema, Table, insertBlacklistValue)
                                    else:
                                        logger.debug("IP Address already blacklisted.")

                                    selectValue = {}
                                    getBlacklistData = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)
                                    logging.info(str(getBlacklistData))
                                    
                                    allBlacklisted[(counter+1)] = getBlacklistData
                                    logging.info("INFO: allBlacklisted is " + str(allBlacklisted) + "\n")

                                else:
                                    logger.debug("IP Address is not blacklisted.")
                            except (ValueError, TypeError):
                                logger.error("ERROR: Unable to check if blacklisted.")
                        else:
                            logger.debug("Blacklist Report not found.")
                    else:
                        logger.error("ERROR: Failed to retrieve blacklist results.")

        elif re.search('[a-zA-Z]', userInput):
            #if input is a hostname
            #use hostname to query from database
            Schema = "network"
            Table = "network_ipaddr_domain_only"

            selectValue = collections.OrderedDict.fromkeys(['ipaddr'])
            whereValue = collections.OrderedDict.fromkeys(['domain'])
            whereValue['domain'] = userInput

            ipaddr = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)
            logging.info("INFO: ipaddr is " + str(ipaddr) + "\n")

            #if ip address is in database
            if ipaddr:
                #check if it is blacklisted
                Schema = "network"
                Table = "network_netflow_basic"

                #in the event there are many ip addresses returned for one hostname
                #rows are returned in a list of tuples eg [('ipaddress',),('ipaddress2',),...]
                #hence a loop is needed to specify the position of each result in the list (each row returned)
                #there is only one column returned, so the position of the result per tuple is fixed at 0
                for a in xrange(len(ipaddr)):
                    selectValue = collections.OrderedDict.fromkeys(['srcip','destip'])
                    whereValue = collections.OrderedDict.fromkeys(['srcip','destip'])

                    whereValue['srcip'] = ipaddr[a][0]
                    whereValue['destip'] = ipaddr[a][0]

                    #select statement has to specify that the two WHERE conditions are optional (as long as one condition is met)
                    #this function can be used if the number '1' is specified
                    ipAddList = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue, 1)
                    logging.info("INFO: ipAddList is " + str(ipAddList) + "\n")

                    #check if there are results
                    if ipAddList:
                        #check if ip address is public or private. ignore it if private.
                        for x in xrange(len(ipAddList)):
                            temp = list(ipAddList[x])
                            logging.info("INFO: temp is " + str(temp) + "\n")

                            if IPAddress(temp[0]).is_private() and IPAddress(temp[1]).is_private():
                                #remove both elements in list
                                del temp[:]
                                logging.info("INFO: temp is " + str(temp) + "\n")

                            elif IPAddress(temp[0]).is_private():
                                #remove source ip address in list
                                temp.remove(temp[0])
                                logging.info("INFO: temp is " + str(temp) + "\n")

                            elif IPAddress(temp[1]).is_private():
                                #remove destination ip address in list
                                temp.remove(temp[1])
                                logging.info("INFO: temp is " + str(temp) + "\n")

                            else:
                                #both source and dest ip addresses are not private addresses
                                pass

                            #check reputation of each ip
                            for i in xrange(len(temp)):
                                ipCheck = checkIpReputation(temp[i])
                                logging.info("INFO: ipCheck is " + str(ipCheck) + "\n")
                            
                                #check if ip address was checked against ipvoid
                                if ipCheck:
                                    #check if the results retrieved is in form of a dictionary
                                    if isinstance(ipCheck, dict):
                                        #check if dict.key is empty
                                        if ipCheck['Blacklist Status']:
                                            try:
                                                #if blacklisted, insert into database
                                                if int(ipCheck['Blacklist Status'][0]) != 0:
                                                    Schema = "ip_blacklist"
                                                    Table = "blacklistedip"

                                                    #check if ip address has already been added into database
                                                    selectValue = collections.OrderedDict.fromkeys(['ipaddress'])
                                                    whereValue = collections.OrderedDict.fromkeys(['ipaddress'])
                                                    whereValue['ipaddress'] = ipCheck['IP Address']
                                                    blacklistSelect = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)

                                                    if not blacklistSelect:

                                                        insertBlacklistValue = collections.OrderedDict.fromkeys(['ipaddress', 'blackliststatus', 'reversedns', 'asn', 'asnowner', 'isp', 'continent', 'countrycode', 'latitude_longitude', 'city', 'region'])

                                                        insertBlacklistValue['ipaddress'] = ipCheck['IP Address']
                                                        insertBlacklistValue['blackliststatus'] = ipCheck['Blacklist Status']
                                                        insertBlacklistValue['reversedns'] = ipCheck['Reverse DNS']
                                                        insertBlacklistValue['asn'] = ipCheck['ASN']
                                                        insertBlacklistValue['asnowner'] = ipCheck['ASN Owner']
                                                        insertBlacklistValue['isp'] = ipCheck['ISP']
                                                        insertBlacklistValue['continent'] = ipCheck['Continent']
                                                        insertBlacklistValue['countrycode'] = ipCheck['Country Code']
                                                        insertBlacklistValue['latitude_longitude'] = ipCheck['Latitude / Longitude']
                                                        insertBlacklistValue['city'] = ipCheck['City']
                                                        insertBlacklistValue['region'] = ipCheck['Region']

                                                        logging.info("INFO: insertBlacklistValue is " + str(insertBlacklistValue) + "\n")
                                                        db.databaseInsert(databaseConnectionHandle, Schema, Table, insertBlacklistValue)
                                                    else:
                                                        logger.debug("IP Address already blacklisted.")

                                                    selectValue = {}
                                                    getBlacklistData = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)
                                                    logging.info(str(getBlacklistData))
                                                    
                                                    allBlacklisted[(counter+1)] = getBlacklistData
                                                    logging.info("INFO: allBlacklisted is " + str(allBlacklisted) + "\n")

                                                else:
                                                    logger.debug("IP Address is not blacklisted.")
                                            except (ValueError, TypeError):
                                                logger.error("ERROR: Unable to check if blacklisted.")
                                        else:
                                            logger.debug("Blacklist Report not found.")
                                    else:
                                        logger.error("ERROR: Failed to retrieve blacklist results.")
                    else:
                        "No IP addresses related to Hostname applicable for blacklist check."

            else:
                #if hostname is not in database
                logger.error("ERROR: Hostname not in database.")

        else:
            #if userInput is not an ip address or hostname
            logger.error("Please enter a valid input.")

    else:
        #if no input is given

        #select all source and destination ip addresses from database

        Schema = "network"
        Table = "network_netflow_basic"

        selectValue = collections.OrderedDict.fromkeys(['srcip','destip'])
        whereValue = {}

        ipAddList = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)
        logging.info("INFO: ipAddList is " + str(ipAddList) + "\n")

        #remove internally routed ip addresses
        for x in xrange(len(ipAddList)):
            temp = list(ipAddList[x])
            logging.info("INFO: temp is " + str(temp) + "\n")

            if IPAddress(temp[0]).is_private() and IPAddress(temp[1]).is_private():
                #remove both elements in list
                del temp[:]
                logging.info("INFO: temp is " + str(temp) + "\n")

            elif IPAddress(temp[0]).is_private():
                #remove source ip address in list
                temp.remove(temp[0])
                logging.info("INFO: temp is " + str(temp) + "\n")

            elif IPAddress(temp[1]).is_private():
                #remove source ip address in list
                temp.remove(temp[1])
                logging.info("INFO: temp is " + str(temp) + "\n")

            else:
                #both source and dest ip addresses are not private addresses
                pass

            #check reputation of each ip
            for i in xrange(len(temp)):
                ipCheck = checkIpReputation(temp[i])
                # logging.info("INFO: ipCheck is " + str(ipCheck) + "\n")
            
                #check if ip address was checked against ipvoid
                if ipCheck:
                    #check if the results retrieved is in form of a dictionary
                    if isinstance(ipCheck, dict):
                        #check if dict.key is empty
                        if ipCheck['Blacklist Status']:
                            try:
                                #if blacklisted, insert into database
                                if int(ipCheck['Blacklist Status'][0]) != 0:
                                    Schema = "ip_blacklist"
                                    Table = "blacklistedip"

                                    #check if ip address has already been added into database
                                    selectValue = collections.OrderedDict.fromkeys(['ipaddress'])
                                    whereValue = collections.OrderedDict.fromkeys(['ipaddress'])
                                    whereValue['ipaddress'] = ipCheck['IP Address']
                                    blacklistSelect = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)

                                    if not blacklistSelect:

                                        insertBlacklistValue = collections.OrderedDict.fromkeys(['ipaddress', 'blackliststatus', 'reversedns', 'asn', 'asnowner', 'isp', 'continent', 'countrycode', 'latitude_longitude', 'city', 'region'])

                                        insertBlacklistValue['ipaddress'] = ipCheck['IP Address']
                                        insertBlacklistValue['blackliststatus'] = ipCheck['Blacklist Status']
                                        insertBlacklistValue['reversedns'] = ipCheck['Reverse DNS']
                                        insertBlacklistValue['asn'] = ipCheck['ASN']
                                        insertBlacklistValue['asnowner'] = ipCheck['ASN Owner']
                                        insertBlacklistValue['isp'] = ipCheck['ISP']
                                        insertBlacklistValue['continent'] = ipCheck['Continent']
                                        insertBlacklistValue['countrycode'] = ipCheck['Country Code']
                                        insertBlacklistValue['latitude_longitude'] = ipCheck['Latitude / Longitude']
                                        insertBlacklistValue['city'] = ipCheck['City']
                                        insertBlacklistValue['region'] = ipCheck['Region']

                                        logging.info("INFO: insertBlacklistValue is " + str(insertBlacklistValue) + "\n")
                                        db.databaseInsert(databaseConnectionHandle, Schema, Table, insertBlacklistValue)
                                    else:
                                        logger.debug("IP Address already blacklisted.")

                                    selectValue = {}
                                    getBlacklistData = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)
                                    logging.info(str(getBlacklistData))
                                    
                                    allBlacklisted[counter+1] = getBlacklistData
                                    logging.info("INFO: allBlacklisted is " + str(allBlacklisted) + "\n")
                                    counter += 1

                                else:
                                    logger.debug("IP Address is not blacklisted.")
                            except (ValueError, TypeError):
                                logger.error("ERROR: Unable to check if blacklisted.")
                        else:
                            logger.debug("Blacklist Report not found.")
                    else:
                        logger.error("ERROR: Failed to retrieve blacklist results.")

            # if x==20:
                #for testing purposes
                #to break out of loop in order to review json file output
                # break

    if allBlacklisted:
        date = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))
        with open('./json/' + date + '-ipblacklist.json', 'w') as file:
                file.write(json.dumps(allBlacklisted, default=jdefault, indent=4))


#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    logging.info("INFO: dbhandle is " + str(dbhandle) + "\n")

    parser = argparse.ArgumentParser(description="Check IP address or hostname if it is blacklisted (against ipvoid.com)")
    parser.add_argument('-t', dest='ipOrHostname', type=str, required=True, help="IPv4 address or Hostname")        
    args = parser.parse_args()  
    userInput = args.ipOrHostname
  
    ipChecker(dbhandle, userInput)

if __name__ == '__main__':
    main()
