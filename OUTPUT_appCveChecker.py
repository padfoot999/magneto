#NAME: checkHotfixCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability of specific application
#!/usr/bin/python -tt
__description__ = 'Generate CVE report'

import collections
import json
import datetime
import sys
import psycopg2
import argparse
import os
import re

import logging
logger = logging.getLogger('root')

import IO_databaseOperations as db
from config import CONFIG

import csv
import codecs

import pandas as pd
import openpyxl
from sqlalchemy import create_engine

#NAME: checkApplicationCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and os version
def checkApplicationCVE(dbEngine, appname):
    #to enable all queries returned in a string format
    #delete any typecasters of psycopg2 
    psycopg2.extensions.string_types.clear()
    appname = appname.lower()
    destFilename = './results/' + str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S')) + "-Application Vulnerability Checker-" + appname + ".xlsx"
    writer = pd.ExcelWriter(destFilename, engine='openpyxl')

    cveVulnerabilities = pd.DataFrame()
    query2 = "SELECT cve.*, product.fullproductname FROM sourcefiles.cve_details cve INNER JOIN (SELECT cveID, manufacturer || ' ' || replace(p.product, '_', ' ') || ' ' || version AS fullProductName FROM sourcefiles.manufacturer m INNER JOIN sourcefiles.product p ON m.product = p.product) product ON product.cveID = cve.cveID"
    logger.info("query is "+query2+"\n")
    
    applist = []
    appname = re.escape(appname)
    applist.append(appname)
    pattern = '|'.join(applist)

    for chunk in pd.read_sql(query2, dbEngine, chunksize=1000):
        chunk = chunk.loc[chunk['fullproductname'].notnull()]
        appvuln = chunk.loc[chunk['fullproductname'].str.contains(pattern)]
        cveVulnerabilities = cveVulnerabilities.append(appvuln, ignore_index=True)
    cveVulnerabilities.to_excel(writer, sheet_name="CVE Vulnerabilities", index=False)
    writer.save()

#NAME: checkHotfixCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and Windows patch level 
def checkHotfixCVE(dbEngine, appname):
    #to enable all queries returned in a string format
    #delete any typecasters of psycopg2
    psycopg2.extensions.string_types.clear()
    appname = appname.lower()
    destFilename = './results/' + str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S')) + "-Hotfix Vulnerability Checker-" + appname + ".xlsx"
    writer = pd.ExcelWriter(destFilename, engine='openpyxl')

    query2 = "SELECT * FROM sourcefiles.windows_patch_level"
    logger.info("query is "+query2+"\n")
    df2 = pd.read_sql(query2, dbEngine)
    print df2
    #Filters for application vulnerabilities
    appVulnerabilities = pd.DataFrame()
    applist = []
    #query2 += " WHERE p.affectedproduct LIKE %(app)s"
    #app = '%' + app + '%'
    appname = re.escape(appname)
    applist.append(appname)
    pattern = '|'.join(applist)
    df2['affectedproduct'] = df2['affectedproduct'].str.lower()
    df2['affectedcomponent'] = df2['affectedcomponent'].str.lower()
    appProductVulnerabilities = df2.loc[df2['affectedproduct'].str.contains(pattern)]
    df2 = df2.loc[df2['affectedcomponent'].notnull()]
    appComponentVulnerabilities = df2.loc[df2['affectedcomponent'].str.contains(pattern)]
    appVulnerabilities = appProductVulnerabilities.append(appComponentVulnerabilities, ignore_index=True)
    appComponentVulnerabilities.to_excel(writer, sheet_name="Microsoft App Vulnerabilities", index=False)
    writer.save()

#NAME: main
#INPUT: NONE 
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():
    DATABASE = CONFIG['DATABASE']
    url = 'postgresql://{}:{}@{}:{}/{}'
    user = DATABASE['USER'].replace("'", "")
    password=DATABASE['PASSWORD'].replace("'", "")
    host=DATABASE['HOST'].replace("'", "")
    port=5432
    db=DATABASE['DATABASENAME'].replace("'", "")
    url = url.format(user, password, host, port, db)
    engine = create_engine(url, client_encoding='utf8')

    parser = argparse.ArgumentParser(description="Check Application installed for known CVE")
    parser.add_argument('-a', dest='appname', type=str, required=True, help="Name of app to be analyzed for known applications CVE")
    args = parser.parse_args()

    appname = args.appname

    #Check if results folder exist, if not, create it.
    dir = os.getcwd()
    resultsDir = dir + "/results"
    if not os.path.exists(resultsDir):
        try:
            os.makedirs(resultsDir)
        except:
            logging.error("Unable to create results folder")
            sys.exit()

    checkApplicationCVE(engine, appname)
    checkHotfixCVE(engine, appname)

if __name__ == '__main__':
    main()