#!/usr/bin/python -tt
__description__ = 'Parse saved text result from Volatility plugin envars'

import collections
import IO_databaseOperations as db
import IO_fileProcessor as fp
from config import CONFIG

import logging
logger = logging.getLogger('root')

import argparse

#NAME:parseAndPopulate
#INPUT:psycopg2-db-handle databaseConnectionHandle, string filename
#OUTPUT: NONE
#DESCRIPTION: Parse and insert values into database path.mem_envars
def parseAndPopulate(databaseConnectionHandle, filename):

    logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    logger.debug("filename is " + filename + "\n")

    fileBuffer = fp.dequeFile(filename)

    path = filename.split('/')
    
    #To prevent duplicate entries
    tempPathList = []

    #Skip thru the buffer until the title line
    while fileBuffer[0] != ['Pid', 'Process', 'Block', 'Variable', 'Value']:
        fileBuffer.popleft()

    #Remove the title
    fileBuffer.popleft()

    #Remove the ---- line
    fileBuffer.popleft()

    while fileBuffer:
        temp = fileBuffer.popleft()

        skip = False
        #for line with more than five elements
        if len(temp) > 5:
            logger.debug("temp is " + str(temp) + "\n")

            try:
                pid = temp[0]
            except (ValueError,IndexError) as e:
                    pid = ""
                    logger.error("Envars: Problem assigning pid due to " + str(e))
                    pass

            try:
                procname = temp[1]
            except (ValueError,IndexError) as e:
                    procname = ""
                    logger.error("Envars: Problem assigning procname due to " + str(e))
                    pass

            try:
                block = temp[2]
            except (ValueError,IndexError) as e:
                    block = ""
                    logger.error("Envars: Problem assigning block due to " + str(e))
                    pass

            try:
                variable = temp[3]
            except (ValueError,IndexError) as e:
                    variable = ""
                    logger.error("Envars: Problem assigning variable due to " + str(e))
                    pass

            #combine subsequent elements as they belong to the same field
            try:
                pathvalue = " ".join(temp[4:])
            except (ValueError,IndexError) as e:
                    pathvalue = ""
                    logger.error("Envars: Problem assigning pathvalue due to " + str(e))
                    pass

            logger.debug("pid is " + pid + "\n")
            logger.debug("procname is " + procname + "\n")
            logger.debug("block is " + block + "\n")
            logger.debug("variable is " + variable + "\n")
            logger.debug("combined pathvalue is " + pathvalue + "\n")

        #for lines with standard number of elements
        else:
            try:
                pid = temp[0]
            except (ValueError,IndexError) as e:
                    pid = ""
                    logger.error("Envars: Problem assigning pid due to " + str(e))
                    pass

            try:
                procname = temp[1]
            except (ValueError,IndexError) as e:
                    procname = ""
                    logger.error("Envars: Problem assigning procname due to " + str(e))
                    pass

            try:
                block = temp[2]
            except (ValueError,IndexError) as e:
                    block = ""
                    logger.error("Envars: Problem assigning block due to " + str(e))
                    pass

            try:
                variable = temp[3]
            except (ValueError,IndexError) as e:
                    variable = ""
                    logger.error("Envars: Problem assigning variable due to " + str(e))
                    pass

            try:
                pathvalue = temp[4]
            except (ValueError,IndexError) as e:
                    pathvalue = ""
                    logger.error("Envars: Problem assigning pathvalue due to " + str(e))
                    pass

            logger.debug("pid is " + pid + "\n")
            logger.debug("procname is " + procname + "\n")
            logger.debug("block is " + block + "\n")
            logger.debug("variable is " + variable + "\n")
            logger.debug("pathvalue is " + pathvalue + "\n")

        insertValue = collections.OrderedDict.fromkeys(['imagename','pid','procname','block','variable','pathvalue'])

        #Searching for triage naming convention for evidence whereby "Incident_" is always in the name. This is the imagename.
        for tempImageName in path:
            if "Incident_" in tempImageName:
                break
        insertValue['imagename'] = tempImageName

        #Initializing variables for table mem_envars_path
        insertPathValue = collections.OrderedDict.fromkeys(['imagename', 'path'])
        insertPathValue['imagename'] = tempImageName

        if pid.isdigit():
            insertValue['pid'] = pid
        else:
            skip = True
            print "ERROR: Problem processing the following line as pid field is NOT numeric :"
            print str(temp)

        if skip == False:
            Schema = "environment_variables"
            Table = "mem_envars"

            insertValue['procname'] = procname
            insertValue['block'] = block
            insertValue['variable'] = variable
            
            if procname == "csrss.exe" and variable == "Path":                
                Table = "mem_envars_path"
                #List used to separate line delimited by ";"
                tempValue = pathvalue.split(';')                

                #Iterate through all path value
                for pathItem in tempValue:
                    #Check for duplicates
                    if pathItem not in tempPathList:
                        tempPathList.append(pathItem)                        
                        insertPathValue['path'] = pathItem                    
                        logger.debug("insertPathValue is " + str(insertPathValue) + "\n")
                        db.databaseInsert(databaseConnectionHandle,Schema,Table,insertPathValue)
                
                #Revert table to mem_envars
                Table = "mem_envars"
            else:
                insertValue['pathvalue'] = pathvalue

            logger.debug("insertValue is " + str(insertValue) + "\n")
            db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)


#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    logger.debug("dbhandle is " + str(dbhandle) + "\n")

    parser = argparse.ArgumentParser(description="Process volatility envar output files")    
    parser.add_argument('-d', dest='filename', type=str, required=True, help="envar plugin text output")  
    args = parser.parse_args()

    parseAndPopulate(dbhandle,args.filename)

if __name__ == '__main__':
    main()
