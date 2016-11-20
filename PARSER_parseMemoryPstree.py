#!/usr/bin/python -tt
__description__ = 'Parse saved text result from Memory PSList'

import collections
import IO_databaseOperations as db
import IO_fileProcessor as fp
import re
from config import CONFIG

import logging
logger = logging.getLogger('root')

import argparse

#NAME: emptyField
#INPUT: string change
#OUTPUT: empty string
#DESCRIPTION: To change lines consisting of '------' into null
def emptyField(change):
    if re.match("^-+$", change):
        change = ""
    return change

#NAME:parseAndPopulate
#INPUT:psycopg2-db-handle databaseConnectionHandle, string filename
#OUTPUT: NONE
#DESCRIPTION: Parse and insert values into database process_list.mem_pstree
def parseAndPopulate(databaseConnectionHandle, filename):

    logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    logger.debug("filename is " + filename + "\n")

    fileBuffer = fp.dequeFile(filename)

    path = filename.split('\\')
    
    #Skip thru the buffer until the title line
    while fileBuffer[0] != ['Name', 'Pid', 'PPid', 'Thds', 'Hnds', 'Time']:
        fileBuffer.popleft()

    #Remove the title
    fileBuffer.popleft()

    #Remove the ---- line
    fileBuffer.popleft()

    while fileBuffer:

        temp = fileBuffer.popleft()

        logger.debug("temp is " + str(temp) + "\n")

        #for lines that contains '.' at the start
        if re.match("^[.]+$", temp[0]):
            logger.debug("contain dot at start temp is " + str(temp) + "\n")

            #join and split element according to delimiter
            temp1 = "".join(temp[1]).split(":", 1)
            offsetv = temp1[0]

            #To handle process name with spaces
            procname = ""
            totalNameItems = 0
            for index, value in enumerate(temp):
                #To skip the param which is dot/s
                if not index == 0:
                    totalNameItems += 1
                    if not value.isdigit():
                        if procname:
                            procname += " "
                        procname += str(value)
                        logger.debug("procname is " + str(procname))
                        logger.debug("Number of items to form a name : " + str(totalNameItems))
                    else:
                        totalNameItems-=1
                        break

        else:
            #join and split element according to delimiter
            temp1 = "".join(temp[0]).split(":", 1)
            offsetv = temp1[0]

            #To handle process name with spaces
            procname = ""
            totalNameItems = 0
            for index, value in enumerate(temp):
                totalNameItems += 1
                if not value.isdigit():
                    if procname:
                        procname += " "
                    procname += str(value)
                    logger.debug("procname is " + str(procname))
                    logger.debug("Number of items to form a name : " + str(totalNameItems))
                else:
                    totalNameItems-=1
                    break

        temp1 = procname.split(":", 2)
        procname = temp1[1]

        #We need to work backwards due to the possibility of procname with spaces
        try:
            pid = temp[-7]
        except (ValueError,IndexError) as e:
            pid = ""
            logger.error("Pstree: Problem assigning pid due to " + str(e))
            pass
        try:
            ppid = temp[-6]
        except (ValueError,IndexError) as e:
            ppid = ""
            logger.error("Pstree: Problem assigning ppid due to " + str(e))
            pass

        try:
            thds = temp[-5]
        except (ValueError,IndexError) as e:
            thds = ""
            logger.error("Pstree: Problem assigning thds due to " + str(e))
            pass

        if '--' in temp[-4]:
            hnds = "0"
        else:
            try:
                hnds = temp[-4]
            except (ValueError,IndexError) as e:
                hnds = ""
                logger.error("Pstree: Problem assigning hnds due to " + str(e))
                pass


        #combine subsequent elements as they belong to the same field
        try:
            time = " ".join(temp[-3:])
        except (ValueError,IndexError) as e:
                time = ""
                logger.error("Pstree: Problem assigning time due to " + str(e))
                pass

        logger.debug("offsetv is " + offsetv + "\n")
        logger.debug("procname is " + procname + "\n")
        logger.debug("pid is " + pid + "\n")
        logger.debug("ppid is " + ppid + "\n")
        logger.debug("thds is " + thds + "\n")
        logger.debug("hnds is " + hnds + "\n")
        logger.debug("combined time is " + time + "\n")

        insertValue = collections.OrderedDict.fromkeys(['imagename', 'offsetv', 'procname', 'pid','ppid','thds','hnds', 'ttime'])

        #Searching for triage naming convention for evidence whereby "Incident_" is always in the name. This is the imagename.
        for tempImageName in path:
            if "Incident_" in tempImageName:
                break
        insertValue['imagename'] = tempImageName       

        insertValue['offsetv'] = offsetv
        insertValue['procname'] = procname

        skip = False

        if pid.isdigit():
            insertValue['pid'] = pid
        else:
            skip = True
            logger.error("Pstree: Problem processing the following line as pid field is NOT numeric : " + str(temp))
            
        if ppid.isdigit():
            insertValue['ppid'] = ppid
        else:
            skip = True
            logger.error("Pstree: Problem processing the following line as ppid field is NOT numeric : " + str(temp))

        if thds.isdigit():
            insertValue['thds'] = thds
        else:
            skip = True
            logger.error("Pstree: Problem processing the following line as thds field is NOT numeric : " + str(temp))

        if hnds.isdigit():
            insertValue['hnds'] = hnds
        else:
            skip = True
            logger.error("Pstree: Problem processing the following line as hnds field is NOT numeric : " + str(temp))            

        insertValue['ttime'] = time

        if skip == False:
            Schema = "process_list"
            Table = "mem_pstree"

            logger.debug("insertValue is " + str(insertValue) + "\n")
            db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)

        #Reset values to be inserted
        insertValue = collections.OrderedDict.fromkeys(['imagename', 'offsetv', 'procname', 'pid','ppid','thds','hnds', 'ttime'])


#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    logger.debug("dbhandle is " + str(dbhandle) + "\n")

    parser = argparse.ArgumentParser(description="Process volatility pslist output files")    
    parser.add_argument('-d', dest='filename', type=str, required=True, help="pslist plugin text output")  
    args = parser.parse_args()

    parseAndPopulate(dbhandle,args.filename)

if __name__ == '__main__':
    main()
