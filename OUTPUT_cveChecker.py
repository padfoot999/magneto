#!/usr/bin/python -tt
__description__ = 'Generate CVE report'

import collections
import json
import datetime
import sys
import psycopg2
import argparse
import os

import logging
logger = logging.getLogger('root')

import IO_databaseOperations as db
from config import CONFIG


#NAME: checkApplicationCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and Windows patch level
def onlineQuery(queryKeyword):
    print "Querying"

#NAME: checkApplicationCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and Windows patch level
def checkApplicationCVE(databaseConnectionHandle, projectname, imagename):
    
    #to enable all queries returned in a string format
    #delete any typecasters of psycopg2 
    psycopg2.extensions.string_types.clear()

    #=========================================================================================#
    logger.info("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")

    #Go through all images from specific project
    if imagename:
        Schema = "system"
        Table = "triage_sysinfo_applications"

        #specify what needs to be selected and if there is a 'where' condition for query (SELECT statement)
        #create dictionary variables for 'SELECT' and 'WHERE' conditions; create an empty dictionary if there are no conditions
        whereValue = collections.OrderedDict.fromkeys(['imagename'])
        selectValue = {}

        #Need to process directory and get directory name as the imagename
        whereValue['imagename'] = imagename
        
        applicationsList = db.databaseSelect(databaseConnectionHandle, Schema, Table, selectValue, whereValue)
        for item in applicationsList:
            logger.info("" + str(item[1]) + "\n") 

        #Setup mongodb and query
        #import into db again and query
        #search online - onlineQuery   
        #We need to parse for vendor, product and version     
        # We need to note the naming nuances of cvedetails... e.g Microsoft .Net is ".net framework"
        # https://www.cvedetails.com/version-search.php?vendor=Adobe&product=Flash+Player&version=11.0.1.152
        # NOTE Version is always the last delimited element in Triage!
        # Naive approach would be 

    else:
        sys.exit()
        #Iterate through all imagename in project
            #List application
                #onlineQuery


#NAME: checkHotfixCVE
#INPUT: psycopg2-db-handle databaseConnectionHandle, string projectname, string imagename
#OUTPUT:
#DESCRIPTION: Identify vulnerability based on application installed and Windows patch level
def checkHotfixCVE(databaseConnectionHandle, projectname, imagename):
    
    #to enable all queries returned in a string format
    #delete any typecasters of psycopg2 
    psycopg2.extensions.string_types.clear()

    #=========================================================================================#
    logger.info("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")

    #Go through all images from specific project
    if imagename:  

        Schema = "system"
        Table = "triage_sysinfo_hotfix"

        #specify what needs to be selected and if there is a 'where' condition for query (SELECT statement)
        #create dictionary variables for 'SELECT' and 'WHERE' conditions; create an empty dictionary if there are no conditions
        #retrieve the last hotfix ID belonging to the specific imagename in the database
        selectValue = collections.OrderedDict.fromkeys(['totalnum'])
        whereValue = collections.OrderedDict.fromkeys(['imagename'])

        #point to the imagename
        whereValue['imagename'] = imagename

        #databaseSelectDistinct has deprecated.
        hotfixID = db.databaseSelectDistinct(databaseConnectionHandle, Schema, Table, selectValue, whereValue)
        logger.info("hotfixID is " + str(hotfixID) + "\n")

        #if results are returned
        if hotfixID:
            #retrieve information of the last hotfix ID belonging to the specific imagename
            selectValue = collections.OrderedDict.fromkeys(['imagename', 'hotfixid', 'description'])
            whereValue = collections.OrderedDict.fromkeys(['imagename', 'hotfixid'])
            whereValue['imagename'] = imagename

            #result returned is in a tuple in a list, hence specify the positions
            hotfixID = '%02d' % int(hotfixID[0][0])
            whereValue['hotfixid'] = hotfixID

            #databaseSelectDistinct has deprecated.
            hotfix = db.databaseSelectDistinct(databaseConnectionHandle, Schema, Table, selectValue, whereValue)
            logger.info("hotfix is " + str(hotfix) + "\n")    

            #=========================================================================================#
            #   ------Querying for Windows Patch Level Details------ #

            if hotfix:
                # Search https://technet.microsoft.com/en-us/security/bulletins
                #This might not be applicable as KB to MS patches depend on the MSFT product installed. Some KB/MS may not apply
                sys.exit()

#NAME: main
#INPUT: NONE 
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():
    
    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    logger.info("dbhandle is " + str(dbhandle) + "\n")

    parser = argparse.ArgumentParser(description="Check Application installed for known CVE")
    parser.add_argument('-p', dest='projectname', type=str, required=True, help="Codename of the project that the evidence is part of")
    parser.add_argument('-t', dest='imagename', type=str, help="Name of image to be analyzed for known applications CVE")
    args = parser.parse_args()

    projectname = args.projectname
    imagename = args.imagename

    checkApplicationCVE(dbhandle, projectname, imagename)
    checkHotfixCVE(dbhandle, projectname, imagename)

if __name__ == '__main__':
    main()
