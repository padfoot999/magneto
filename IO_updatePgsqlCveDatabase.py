#!/usr/bin/python -tt
__description__ = 'Insert and update CVE database'

#ZF: BROKEN. TO FIX

import collections
import IO_databaseOperations as db
import psycopg2
from config import CONFIG
import tempfile
import os
import requests
from contextlib import closing
import csv
from bs4 import BeautifulSoup
from pprint import pformat as pf
from collections import deque
import xlrd
from datetime import datetime
import re
import sys
import win_inet_pton
from config import CONFIG
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import logging
logger = logging.getLogger('root')

# NVD_CACHE = 'nvd_cache'
# NVD cache is not checked into GIT due to its size, copy it in, 
# or download from https://nvd.nist.gov/download.cfm
# and point to NVD cache folder (containing XML files extracted from the downloaded ZIP files)
# filenames have the following structure e.g. nvdcve-2.0-2008.xml
NVD_CACHE = CONFIG['CVE']['NVD_CACHE']

#NAME: getMitreCveListings
#INPUT: optional filepath of local allitems.csv as string
#OUTPUT: data structure 
'''
{
    'reliable_cveid_set': set(['CVE-1234-1111', 'CVE-1234-2222', 'CVE-1234-3333', ...]),

    'mitre_cve_data': {
        'CVE-1234-1111': {
            'Name': 'CVE-1234-1111',
            'Status': string,
            'Description': string,
            'References': string,
            'Phase': string,
            'Votes': string,
            'Comments': string
        },
        'CVE-1234-2222': {
            'Name': 'CVE-1234-2222',
            'Status': string,
            'Description': string,
            'References': string,
            'Phase': string,
            'Votes': string,
            'Comments': string
        },
        'CVE-1234-3333': {
            'Name': 'CVE-1234-3333',
            'Status': string,
            'Description': string,
            'References': string,
            'Phase': string,
            'Votes': string,
            'Comments': string
        },
        ...,
        ...,
        ...
    }
}
'''
#DESCRIPTION: Pull full dump of CVE listings from MITRE site, and parse into data structure.
'''
Only CVEs where the description does not start with a ** tag will be used.  MITRE has various ** tags in the descriptions including TYPOs, so we will just ignore any that has the ** tag altogether.

reliable_cveid_set will contain the set of CVE IDs which are to be populated into the database if they aren't already in.

Example ** tags found in the description
 ** REJECT **
 ** RUESERVED **
 ** DISPUTED **
 ** DISPUTED *
 ** UNVERIFIABLE **
 ** DISPUTED **
 ** SPLIT **
 ** UNVERIFIABLE, PRERELEASE **
 ** DISPUTED **
 ** DISPTED **
 ** DISPUTED **
'''
def getMitreCveListings(filepath):

    if filepath == '':
        # gimme tmp file
        tmpfd, tmpfpath = tempfile.mkstemp()

        # download MITRE CVE dump
        # http://cve.mitre.org/data/downloads/allitems.csv.gz
        # requests library does auto ungzipping, WOOT
        success = False
        while not success:
            try:
                logger.info('Requesting for MITRE CVE dump')
                with closing(
                    requests.get(
                        'http://cve.mitre.org/data/downloads/allitems.csv.gz', 
                        stream=True, 
                        proxies=CONFIG['ONLINE']['PROXIES'],
                        verify=(not CONFIG['ONLINE']['MITMPROXY'])
                    )) as r:
                    if r.status_code == 200:
                        success = True
                        logger.info('writing to temp file %s' % tmpfpath)
                        with os.fdopen(tmpfd, 'wb+') as tmp:
                            for chunk in r:
                                tmp.write(chunk)
            except ConnectionError:
                logger.error('Unable to request for MITRE CVE dump - network connection error')
        #debug(DEBUG_FLAG, 'MITRE CVE download code section done')
        fileloc = tmpfpath
    else:
        #debug(DEBUG_FLAG, 'reading MITRE CVE dump allitems.csv from %s' % filepath)
        fileloc = filepath

    # open the file, seek out header line, pass into CSV DictReader to read the rest of the file
    # check for valid conditions, process into data struct
    data = {
        'reliable_cveid_set': set(),
        'mitre_cve_data': {}
    }
    with open(fileloc, 'rb') as f:
        # header is at third line
            # CVE Version 20061101                        
            # Date: 20160208                      
            # Name    Status  Description References  Phase   Votes   Comments
        f.readline()
        f.readline()
        reader = csv.DictReader(f)
        for row in reader:
            if row['Name'].startswith('CVE-'):
                if not row['Description'].startswith('**'):
                    data['reliable_cveid_set'].add(row['Name'])
                    data['mitre_cve_data'][row['Name']] = row

    if 'tmpfpath' in locals():
        os.remove(tmpfpath)

    return data

#NAME: parseCpe
#INPUT: commondata dictionary {keys: CVEid, CVSS Score, Publish Date}; cpe string
#OUTPUT: dictionary {keys: CVEid, CVSS Score, Publish Date, Manufacturer, Product, Version}
#DESCRIPTION: parses CPE string into dictionary
def parseCpe(commondata, cpe):
    dataitem = {}
    cpe = cpe.split(':')
    dataitem['CVEid'] = commondata['CVEid']
    dataitem['CVSS Score'] = commondata['CVSS Score']
    dataitem['Publish Date'] = commondata['Publish Date']
    dataitem['Manufacturer'] = cpe[2]

    try:
        dataitem['Product'] = cpe[3]
    except:
        dataitem['Product'] = ''

    try:
        dataitem['Version'] = cpe[4]
    except:
        dataitem['Version'] = ''

    return dataitem



#NAME: dontReturnEmptyCve
#INPUT: data dictionary as per getCveDetails OUTPUT
#OUTPUT: data structure as per getCveDetails OUTPUT
#DESCRIPTION: add in the "empty" entry if no vulnerable products were extracted for a CVE (e.g. CVE-1999-0200)
def dontReturnEmptyCve(data, commondata):
    if len(data) == 0:
        data.append({
            'CVEid': commondata['CVEid'],
            'CVSS Score': commondata['CVSS Score'],
            'Publish Date': commondata['Publish Date'],
            'Manufacturer': '',
            'Product': '',
            'Version': '',
            })
    return data

#NAME: getCveDetails
#INPUT: string CVE ID to scrape (cve_id = "CVE-1234-1234")
#OUTPUT: data structure, list of dicts, one dict per affected product by this CVE
'''
[
    {
        'CVEid: 'CVE-1234-1234',
        'Manufacturer: string,
        'Product: string,
        'Version: string,
        'Publish Date: date as string in yyyy-mm-dd format,
        'CVSS Score: float up to one decimal place (can be # or ## or #.# or ##)
    },
    ...,
    ...,
    ...
]
'''
#DESCRIPTION: Scrape for CVE details.  Grabs from a relevant xml file in a subdirectory in NVD_CACHE first if possible.  If not, then will scrape the NVD website to get the data.
# https://nvd.nist.gov/download.cfm
#CHANGELOG 20160221: cvedetails site scrapes info from NIST's National Vulnerability Database (NVD) anyway, and doesn't appear to be entirely up to date.  Changed getCveDetails to scrape from NVD instead.
#TODO look into the NVD's Common Platform Enumeration (CPE) Dictionary, may be better to sync up our data implementation with the CPE for better CVE integration. https://nvd.nist.gov/cpe.cfm and https://cpe.mitre.org/ and https://cpe.mitre.org/specification/
#TODO look into Security Content Automation Protocol (SCAP), which sounds like what we're trying to do here... http://scap.nist.gov/
def getCveDetails(cve_id = ''):
    #debug(DEBUG_FLAG, 'getCveDetails called with "%s"' % cve_id)
    data = []

    commondata = {}
    commondata['CVEid'] = cve_id

    # check NVD cache first
    year = cve_id.split('-')[1]
    linebuffer = ''
    for filename in os.listdir(NVD_CACHE):
        if filename.endswith(".xml"):
            if year in filename:
                #debug(DEBUG_FLAG, 'checking NVD dump file %s first' % filename)
                with open("%s/%s" % (NVD_CACHE, filename), 'rb') as f:
                    # reading in the entire file into BS4 takes too long
                    # skip to start of the entry tag for the cve we want
                    start_tag = '<entry id="%s">' % cve_id.upper() 
                    found_start = False
                    linebuffer = ""
                    for line in f:
                        if not found_start:
                            if start_tag in line:
                                found_start = True
                                linebuffer += line
                            else:
                                # haven't found start of entry yet
                                pass
                        else:
                            # found start of entry, capturing everything till we hit end of entry tag group
                            linebuffer += line
                            if '</entry>' in line:
                                break
    # cannot assume that we find the NVD XML file and that it has what we want
    if linebuffer != '':
        #debug(DEBUG_FLAG, linebuffer)
        # extract (using regex for now, maybe port to XML manipulation library if got time)
        try:
            commondata['CVSS Score'] = str(float(re.search('<cvss:score>(.+?)</cvss:score>', linebuffer).group(1)))
        except:
            # CVSS score not found, tag to a NULL value
            commondata['CVSS Score'] = ''
            logger.error("Unable to find string - CVSS Score")
            pass
        try: 
            commondata['Publish Date'] = re.search(r'<vuln:published-datetime>(\d{4}-\d{2}-\d{2}).+?</vuln:published-datetime>', linebuffer).group(1)
        except:
            commondata['Publish Date'] = ''
            logger.error("Unable to find string - Publish Date")
            pass
        try:    
            for cpe in re.findall('<vuln:product>(.+?)</vuln:product>', linebuffer):
                #debug(DEBUG_FLAG, cpe)
                data.append(parseCpe(commondata, cpe))
        except:
            logger.error("Unable to find string - Product")
            pass
        data = dontReturnEmptyCve(data, commondata)
        #debug(DEBUG_FLAG, 'getCveDetails for "%s":\n%s' % (cve_id, data))
        return data

    # then go online to grab
    success = False
    while not success:
        try:
            logger.info('Requesting for vulnerability details')
            soup = BeautifulSoup(
                requests.get(
                    "https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s" % cve_id, 
                    proxies=CONFIG['ONLINE']['PROXIES'],
                    verify=(not CONFIG['ONLINE']['MITMPROXY'])
                ).text, 
                "html.parser")
            success = True
        except ConnectionError:
            logger.error('Unable to request for vulnerability details - network connection error')
    
    try:
        commondata['CVSS Score'] = str(float(soup.find(string="CVSS v2 Base Score:").parent.parent.find("a").contents[0].encode()))
    except:
        # CVSS score not found, tag to a NULL value
        commondata['CVSS Score'] = ''
        logger.error("Unable to find string - CVSS Score")
        pass

    try:
        commondata['Publish Date'] = datetime.strptime(soup.find(string="Original release date:").next_element.strip(), "%m/%d/%Y").strftime("%Y-%m-%d")
    except:
        commondata['Publish Date'] = ''
        logger.error("Unable to find string - Publish Date")
        pass
    # grab 'Manufacturer', 'Product', and 'Version' info from the "Vulnerable software and versions" section
    # create new dataitem to add to output data list for each CPE row containing 'Manufacturer', 'Product', and 'Version' info
    # cpe:part:vendor:product:version:update:and many more fields...
    # current mapping will be cpe:ignore:Manufacturer:Product:Version
    try:
        vulnswandversions = soup.find(string="Vulnerable software and versions").parent.parent
        for link in vulnswandversions.find_all("a"):
            cpe = link.contents[0].encode()
            # process only if we're dealing with a CPE link
            if not cpe.startswith('cpe:'):
                continue
            data.append(parseCpe(commondata, cpe))
    except:
        logger.error("Unable to find string - Vulnerable software and versions")
        pass

    data = dontReturnEmptyCve(data, commondata)
    #debug(DEBUG_FLAG, 'getCveDetails for "%s":\n%s' % (cve_id, data))
    return data

#NAME: checkNewCVEs
#INPUT: psycopg2-db-handle databaseConnectionHandle
#OUTPUT: NONE
#DESCRIPTION: Acquire a set of CVE IDs for insertion into the database
def checkNewCVEs(databaseConnectionHandle):

    Schema = "vulnerability"
    Table = "cve_details"

    cur = databaseConnectionHandle.cursor()
    query = "SELECT cveID FROM vulnerability.cve_details"
    cur.execute(query)
    existingCveId = cur.fetchall()
    logger.info("existingCveId is " + str(existingCveId) + "\n")
    #results retrieved from the database is a tuple in a list
    #it cannot be converted directly into a set
    #hence it is changed to a list first, then a set
    existingCveIdList = []
    for x in xrange(len(existingCveId)):
        existingCveIdList += list(existingCveId[x])
    existingCveIdList = set(existingCveIdList)
    #debug(DEBUG_FLAG, "INFO: existingCveIdList is " + str(existingCveIdList) + "\n")

    #store the set values of the cveIDs that is to be inserted
    setOfId = getMitreCveListings('')['reliable_cveid_set']
    #debug(DEBUG_FLAG, "INFO: setOfId is " + str(setOfId) + "\n")

    #remove cveIDs that are already stored in the database
    newCveId = setOfId - existingCveIdList
    #debug(DEBUG_FLAG, "INFO: newCveId is " + str(newCveId) + "\n")
    return newCveId


#NAME: insertCveDetails
#INPUT: psycopg2-db-handle databaseConnectionHandle
#OUTPUT: NONE
#DESCRIPTION: To insert CVE information into database
def insertCveDetails(databaseConnectionHandle):
    #debug(DEBUG_FLAG, "INFO: databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")

    #convert set into list for indexing
    insertCveIds = list(checkNewCVEs(databaseConnectionHandle))
    logger.info("INFO: insertCveIds is " + str(insertCveIds) + "\n")
    
    if insertCveIds:
        cveList = getMitreCveListings('')['mitre_cve_data']
        logger.info("INFO: cveList is " + str(cveList) + "\n")

    #=========================================================================================#
    #Populating Table cve_details

    Schema = "vulnerability"

    for x in xrange(len(insertCveIds)):
        Table = "cve_details"

        #Take in each set of dictionary from the list by cveID name
        cveData = cveList[insertCveIds[x]]
        #debug(DEBUG_FLAG, "INFO: cveData is " + str(cveData) + "\n")

        insertCveValue = collections.OrderedDict.fromkeys(['cveID', 'status','description','references_','phase','votes','comments', 'publishedDate', 'cvssScore'])
        insertCveValue['cveID'] = cveData['Name'].encode('string-escape')
        insertCveValue['status'] = cveData['Status'].encode('string-escape')
        insertCveValue['description'] = cveData['Description'].encode('string-escape')
        insertCveValue['references_'] = cveData['References'].encode('string-escape')
        insertCveValue['phase'] = cveData['Phase'].encode('string-escape')
        insertCveValue['votes'] = cveData['Votes'].encode('string-escape')
        insertCveValue['comments'] = cveData['Comments'].encode('string-escape')

        #get additional CVE details by using the cveID
        cveDetails = getCveDetails(insertCveValue['cveID'])
        #debug(DEBUG_FLAG, "INFO: cveDetails is " + str(cveDetails) + "\n")

        #check if there are data retrieved
        if cveDetails:
            #create temp variable to store first result of CVE details in the list
            temp = cveDetails[0]

            #publishDate and CVSS score are the same for all products affected by the specific CVE
            #so it is only necessary to take in both fields once
            insertCveValue['publishedDate'] = temp['Publish Date'].encode('string-escape')
            insertCveValue['cvssScore'] = temp['CVSS Score'].encode('string-escape')

            #debug(DEBUG_FLAG, "INFO: insertCveValue is " + str(insertCveValue) + "\n")
            db.databaseExistInsert(databaseConnectionHandle, Schema, Table, insertCveValue)

            #=========================================================================================#
            #Populating Table product

            for temp in cveDetails:
                Table = "product"
                
                insertProductValue = collections.OrderedDict.fromkeys(['product', 'version', 'cveID'])
                insertProductValue['product'] = temp['Product'].encode('string-escape')
                insertProductValue['version'] = temp['Version'].encode('string-escape')
                insertProductValue['cveID'] = temp['CVEid'].encode('string-escape')

                #debug(DEBUG_FLAG, "INFO: insertProductValue is " + str(insertProductValue) + "\n")
                rowsInserted = db.databaseExistInsert(databaseConnectionHandle, Schema, Table, insertProductValue)

                #=========================================================================================#
                #Populating Table manufacturer
                #When there are no product related to cveid
                if temp['Manufacturer'] or temp['Product'] is not None and '':
                    Table = "manufacturer"

                    insertManufacturerValue = collections.OrderedDict.fromkeys(['manufacturer', 'product'])
                    insertManufacturerValue['manufacturer'] = temp['Manufacturer']
                    insertManufacturerValue['product'] = temp['Product']
                    db.databaseExistInsert(databaseConnectionHandle, Schema, Table, insertManufacturerValue)

        else:
            Table = "cve_details"
            #debug(DEBUG_FLAG, "INFO: insertCveValue is " + str(insertCveValue) + "\n")
            db.databaseExistInsert(databaseConnectionHandle, Schema, Table, insertCveValue)

#NAME: convertMsKb
#INPUT: string
#OUTPUT: string
#DESCRIPTION: Converts MS KB number between numerical-only and "KB#######" formats, since Windows Update dump and triage scripts represent them differently.
def convertMsKb(data=''):
    # if input starts with "KB", strip it and return
    # else add "KB" in front and return
    if data.startswith('KB'):
        return data[2:]
    else:
        return 'KB%s' % data

#NAME: getWindowsUpdateListings
#INPUT: NONE
#OUTPUT: data structure
# bulletin_kb_set will contain the set of bulletin KB numbers (numerical only but represented as strings) which are to be populated into the database if they don't exist.
'''
{
    'bulletin_kb_set': set(['3089657', ...]),
    'windows_update_data': deque([
        {
            'Date Posted': date as string in yyyy-mm-dd format,
            'Bulletin ID': string,
            'Bulletin KB': string (numbers only, no "KB" in front, can be None),
            'Bulletin KB Severity': string,
            'Bulletin KB Impact': string,
            'Title': unicode string,
            'Affected Product': string,
            'Component KB': string (numbers only, no "KB" in front, can be None),
            'Affected Component': string,
            'Component KB Impact': string,
            'Component KB Severity': string,
            'Supersedes': string,
            'Reboot': string,
            'CVEs': (if no CVE will be an empty list)
            [
                'CVE-2016-0029',
                'CVE-2016-0030',
                'CVE-2016-0031',
                'CVE-2016-0032'
            ]
        },
        ...,
        ...,
        ...
    ])
}
'''
#DESCRIPTION: Pull full dump of Windows Update listings from windows update site, and parse into data structure.
def getWindowsUpdateListings():

    # gimme tmp file
    tmpfd, tmpfpath = tempfile.mkstemp()

    # download windows bulletins dump
    # http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx
    #debug(DEBUG_FLAG, 'requesting for Windows patching dump')
    success = False
    while not success:
        try:
            success = True
            logger.info('Requesting for Microsoft Bulletin dump')
            with closing(
                requests.get(
                    'http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx', 
                    stream=True, 
                    proxies=CONFIG['ONLINE']['PROXIES'],
                    verify=(not CONFIG['ONLINE']['MITMPROXY'])
                )) as r:
                if r.status_code == 200:
                    #debug(DEBUG_FLAG, 'writing to temp file %s' % tmpfpath)
                    with os.fdopen(tmpfd, 'wb+') as tmp:
                        for chunk in r:
                            tmp.write(chunk)
        except ConnectionError:
            logger.error('Unable to request for Microsoft Bulletin Dump - network connection error')

   # debug(DEBUG_FLAG, 'Windows patching dump download done')

    # open the file, process into data struct
    data = {
        'bulletin_kb_set': set(),
        'windows_update_data': deque()
    }

    wb = xlrd.open_workbook(tmpfpath)
    sh = wb.sheet_by_index(0)

    for row in xrange(sh.nrows):

        # skip header row
        if row == 0:
            continue

        rowValues = sh.row_values(row)
        #if DEBUG_FLAG:
        print row

        newValues = {}

        datetuple = xlrd.xldate_as_tuple(rowValues[0], 0)
        newValues['Date Posted'] = "%s-%02d-%02d" % (datetuple[0], datetuple[1], datetuple[2])

        newValues['Bulletin ID'] = rowValues[1].encode()

        if rowValues[2] != '':
            newValues['Bulletin KB'] = str(int(rowValues[2]))
        else:
            newValues['Bulletin KB'] = None
        data['bulletin_kb_set'].add(newValues['Bulletin KB'])

        newValues['Bulletin KB Severity'] = rowValues[3].encode()

        newValues['Bulletin KB Impact'] = rowValues[4].encode()

        newValues['Title'] = rowValues[5]

        newValues['Affected Product'] = rowValues[6].encode()

        if rowValues[7] != '':
            newValues['Component KB'] = str(int(rowValues[7]))
        else:
            newValues['Component KB'] = None

        newValues['Affected Component'] = rowValues[8].encode()

        newValues['Component KB Impact'] = rowValues[9].encode()

        newValues['Component KB Severity'] = rowValues[10].encode()

        newValues['Supersedes'] = rowValues[11].encode()

        newValues['Reboot'] = rowValues[12].encode()

        newValues['CVEs'] = rowValues[13].encode().strip().split(',')
        if newValues['CVEs'][0] == '':
            newValues['CVEs'] = []

        data['windows_update_data'].append(newValues)

    os.remove(tmpfpath)
    return data

#NAME: insertWindowsPatchDetails
#INPUT: psycopg2-db-handle databaseConnectionHandle
#OUTPUT: NONE
#DESCRIPTION: To insert Windows Patch Level information into database
def insertWindowsPatchDetails(databaseConnectionHandle):

    windowsUpdateData = getWindowsUpdateListings()['windows_update_data']
    #debug(DEBUG_FLAG, "INFO: windowsUpdateData is " + str(windowsUpdateData) + "\n")

    #=========================================================================================#
    #Populating Table windows_patch_level

    Schema = "vulnerability"
    Table = "windows_patch_level"

    for x in xrange(len(windowsUpdateData)):
        temp = windowsUpdateData[x]
        #debug(DEBUG_FLAG, "INFO: temp is " + str(temp) + "\n")

        insertwindowsUpdateValue = collections.OrderedDict.fromkeys(['cveid','dateposted','bulletinid','bulletinkb','bulletinkbseverity','bulletinkbimpact','title','affectedproduct','componentkb','affectedcomponent','componentkbimpact','componentkbseverity','supersedes','reboot'])
        insertwindowsUpdateValue['dateposted'] = temp['Date Posted']
        insertwindowsUpdateValue['bulletinid'] = temp['Bulletin ID']
        insertwindowsUpdateValue['bulletinkb'] = temp['Bulletin KB']
        insertwindowsUpdateValue['bulletinkbseverity'] = temp['Bulletin KB Severity']
        insertwindowsUpdateValue['bulletinkbimpact'] = temp['Bulletin KB Impact']
        insertwindowsUpdateValue['title'] = temp['Title']
        insertwindowsUpdateValue['affectedproduct'] = temp['Affected Product']
        insertwindowsUpdateValue['componentkb'] = temp['Component KB']
        insertwindowsUpdateValue['affectedcomponent'] = temp['Affected Component']
        insertwindowsUpdateValue['componentkbimpact'] = temp['Component KB Impact']
        insertwindowsUpdateValue['componentkbseverity'] = temp['Component KB Severity']
        insertwindowsUpdateValue['supersedes'] = temp['Supersedes']
        insertwindowsUpdateValue['reboot'] = temp['Reboot']

        #number of CVE ID for each windows patch level differs; some may not exist
        totalCve = temp['CVEs']

        #if CVE ID does not exist
        if not totalCve:
            #remove 'cveid' key from all dictionaries (existing entry in database will not be checked if the key is not removed)
            insertwindowsUpdateValue.pop("cveid", None)
            #debug(DEBUG_FLAG, "INFO: insertwindowsUpdateValue is " + str(insertwindowsUpdateValue) + "\n")
            try:
                db.databaseExistInsert(databaseConnectionHandle, Schema, Table, insertwindowsUpdateValue)
            except psycopg2.Error as e:
                    print "ERROR: Problem inserting into table due to " + str(e)
        else:
            #for each different CVE ID, insert entire set of information into database 
            for i in xrange(len(totalCve)):
                insertwindowsUpdateValue['cveid'] = totalCve[i]
                #debug(DEBUG_FLAG, "INFO: insertwindowsUpdateValue is " + str(insertwindowsUpdateValue) + "\n")
                try:
                    db.databaseExistInsert(databaseConnectionHandle, Schema, Table, insertwindowsUpdateValue)
                except psycopg2.Error as e:
                    print "ERROR: Problem inserting into table due to " + str(e)

#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    #debug(DEBUG_FLAG, "INFO: dbhandle is " + str(dbhandle) + "\n")

    insertCveDetails(dbhandle)
    insertWindowsPatchDetails(dbhandle)

if __name__ == '__main__':
    main()
