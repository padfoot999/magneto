#NAME: checkHotfixCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and Windows patch level
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

import numpy as num
import pandas as pd
import openpyxl
from openpyxl.utils.dataframe import dataframe_to_rows
from sqlalchemy import create_engine

from fuzzywuzzy import fuzz
from fuzzywuzzy import process

#NAME: checkApplicationCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and os version
def checkApplicationCVE(dbEngine, projectname, imagename):
    
    #to enable all queries returned in a string format
    #delete any typecasters of psycopg2 
    psycopg2.extensions.string_types.clear()

    #=========================================================================================#
    #logger.info("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    #Go through all images from specific project
    if imagename:
        applicationQueryDatabase(dbEngine, projectname, imagename)  

    else:
        query = "SELECT DISTINCT imagename from project.project_image_mapping WHERE projectname=%(projectname)s"
        df = pd.read_sql(query, dbEngine, params={"projectname":projectname})
        imagenames = df["imagename"].values
        for imagename in imagenames:
            applicationQueryDatabase(dbEngine, projectname, imagename)

#NAME: checkApplicationQueryDatabase
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and Windows patch level
def applicationQueryDatabase(dbEngine, projectname, imagename):
    logger.info("Imagename is "+imagename+"\n")
    
    destFilename = './Results/' + projectname + '/' + imagename + "-Application Vulnerability Checker-" + str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S')) + ".xlsx"
    query = 'SELECT DISTINCT appname FROM system.triage_sysinfo_applications WHERE system.triage_sysinfo_applications.imagename=%(imagename)s'
    logger.info("query is "+query+"\n")
    df = pd.read_sql(query, dbEngine, params={"imagename":imagename})
    writer = pd.ExcelWriter(destFilename, engine='openpyxl')

    cveVulnerabilities = pd.DataFrame()
    query2 = "SELECT * FROM vulnerability.cve_details"
    query4 = "SELECT cveID as cveid, manufacturer || ' ' || replace(p.product, '_', ' ') || ' ' || version AS fullProductName FROM vulnerability.manufacturer m INNER JOIN vulnerability.product p ON m.product = p.product"
    logger.info("query is "+query2+"\n")
    
    applist = []
    applicationName = ''
    for app in df['appname'].values:
        #Searches for last decimal and replaces it with nothing
        #pattern = re.compile('\d( +\S*$)')
        if app is not None:
            if re.search(r'([0-9\.]+$)', app) is not None:
                version = re.search(r'([0-9\.]+$)', app).group(1).strip()
                applicationName = re.search(r'(^\D*)\d', app).group(1).strip().lower()
                app = applicationName + ' ' + version
            app = re.escape(app)
            applist.append(app)

    query3 = "SELECT kernelversion FROM system.triage_sysinfo WHERE imagename=%(imagename)s"
    df3 = pd.read_sql(query3, dbEngine, params={"imagename":imagename})
    logger.info("query is "+query3+"\n")
    productName = df3['kernelversion'].iloc[0]
    #Searches for OS Version until digit or decimal 
    pattern = re.compile('\w.+ \d+.?\d*')
    productName = pattern.search(productName).group(0).strip()
    productName = re.escape(productName)
    applist.append(productName)
    pattern = '|'.join(applist)
    
    for chunk in pd.read_sql(query2, dbEngine, chunksize=1000):
        for chunk2 in pd.read_sql(query4, dbEngine, chunksize=1000):
            merged = chunk.merge(chunk2, on='cveid', how='inner')
            merged = merged.loc[merged['fullproductname'].notnull()]
            appvuln = merged.loc[merged['fullproductname'].str.contains(pattern)]
            cveVulnerabilities = cveVulnerabilities.append(appvuln, ignore_index=True)
    cveVulnerabilities.to_excel(writer, sheet_name="CVE Vulnerabilities", index=False)
    writer.save()

#NAME: checkHotfixCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and Windows patch level
def checkHotfixCVE(dbEngine, projectname, imagename):
    
    #to enable all queries returned in a string format
    #delete any typecasters of psycopg2 
    psycopg2.extensions.string_types.clear()

    #=========================================================================================#
    #logger.info("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    #Go through all images from specific project
    if imagename:
        hotfixQueryDatabase(dbEngine, projectname, imagename)  

    else:
        query = "SELECT DISTINCT imagename from project.project_image_mapping WHERE projectname=%(projectname)s"
        df = pd.read_sql(query, dbEngine, params={"projectname":projectname})
        imagenames = df['imagename'].values
        for imagename in imagenames:
            hotfixQueryDatabase(dbEngine, projectname, imagename)

def hotfixQueryDatabase(dbEngine, projectname, imagename):
    destFilename = './Results/' + projectname + '/' + imagename + "-Hotfix Vulnerability Checker-" + str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S')) + ".xlsx"
    query = 'SELECT DISTINCT description FROM system.triage_sysinfo_hotfix WHERE system.triage_sysinfo_hotfix.imagename=%(imagename)s'
    logger.info("query is "+query+"\n")
    df = pd.read_sql(query, dbEngine, params={"imagename":imagename})
    writer = pd.ExcelWriter(destFilename, engine='openpyxl')
    df.to_excel(writer, sheet_name="Installed Patches", index=False)

    query2 = "SELECT * FROM vulnerability.windows_patch_level p LEFT JOIN (SELECT DISTINCT description, imagename FROM system.triage_sysinfo_hotfix WHERE system.triage_sysinfo_hotfix.imagename=%(imagename)s) h ON 'KB' || p.bulletinkb = h.description"
    logger.info("query is "+query2+"\n")
    df2 = pd.read_sql(query2, dbEngine, params={"imagename":imagename})
    choices = df2.affectedproduct
    
    #Filter for OS vulnerabilities
    #Reconstructs windows version to match MSBulletin format
    query3 = "SELECT kernelversion, servicepack, systemtype FROM system.triage_sysinfo WHERE imagename=%(imagename)s"
    logger.info("query is "+query3+"\n")
    df3 = pd.read_sql(query3, dbEngine, params={"imagename":imagename})
    productName = df3['kernelversion'].iloc[0]
    
    #Assuming that kernel version contains a comma (i.e. Windows 7, multiprocessor)
    #pattern = re.compile('[\w\s]*\d+')
    #productName = pattern.search(productName).group(0).strip()
    productName = productName.split(',', 1)[0]
    if(df3['systemtype'].iloc[0]=='x86-based pc'):
        productName += " 32-bit systems "
    else:
        if(df3['systemtype'].iloc[0]=='x64-based pc'):
            productName += " x64-based systems "
    if (df3['servicepack'].iloc[0] is not '') and (df3['servicepack'].iloc[0] is not '0'):
        productName += " service pack " + str(df3['servicepack'].iloc[0])

    match = process.extractOne(productName, choices)
    logger.info("Closest match found is: " + match[0])

    osvulnerabilities = df2.loc[df2['affectedproduct']==match[0]]
    applicationVulnerabilities = osvulnerabilities.loc[osvulnerabilities['affectedcomponent'].notnull()]
    #OS vulnerabilities are only those with no affected component, those with affected component are furthered filter using application list
    osvulnerabilities = osvulnerabilities.loc[osvulnerabilities['affectedcomponent'].isnull()]
    osvulnerabilities = osvulnerabilities.drop(['imagename', 'description'],1)
    osvulnerabilities.to_excel(writer, sheet_name="OS Vulnerabilities", index=False)

    #Filters for application vulnerabilities
    applist = []
    query4 = "SELECT DISTINCT appname FROM system.triage_sysinfo_applications WHERE imagename=%(imagename)s"
    logger.info("query is "+query4+"\n")
    df4 = pd.read_sql(query4, dbEngine, params={"imagename":imagename})
    #query2 += " WHERE p.affectedproduct LIKE %(app)s"
    #app = '%' + app + '%'
    for app in df4['appname'].values:
        #Searches for last decimal and replaces it with nothing
        #pattern = re.compile('\d( +\S*$)')
        if app is not None:
            if re.search(r'\d( +\S*$)', app) is not None:
                stringToReplace = re.search(r'\d( +\S*$)', app).group(1)
                app = app.replace(stringToReplace, "")
            app = re.escape(app)
            applist.append(app)
    pattern = '|'.join(applist)
    appProductVulnerabilities = df2.loc[df2['affectedproduct'].str.contains(pattern)]
    appComponentVulnerabilities = applicationVulnerabilities.loc[applicationVulnerabilities['affectedcomponent'].str.contains(pattern)]
    appVulnerabilities = appProductVulnerabilities.append(appComponentVulnerabilities, ignore_index=True)
    appVulnerabilities.to_excel(writer, sheet_name="Microsoft App Vulnerabilities", index=False)
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
    parser.add_argument('-p', dest='projectname', type=str, required=True, help="Codename of the project that the evidence is part of")
    parser.add_argument('-t', dest='imagename', type=str, help="Name of image to be analyzed for known applications CVE")
    args = parser.parse_args()

    projectname = args.projectname
    imagename = args.imagename

    dir = os.getcwd()
    resultsDir = dir + "/Results"
    if not os.path.exists(resultsDir):
        try:
            os.makedirs(resultsDir)
        except:
            logging.error("Unable to create results folder")
            sys.exit()

    projResultsDir = dir + "/Results/" + projectname 
    if not os.path.exists(projResultsDir):
        try:
            os.makedirs(projResultsDir)
        except:
            logging.error("Unable to create Project results folder")
            sys.exit()

    checkApplicationCVE(engine, projectname, imagename)
    checkHotfixCVE(engine, projectname, imagename)

if __name__ == '__main__':
    main()
