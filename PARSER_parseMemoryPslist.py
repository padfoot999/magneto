#!/usr/bin/python -tt
__description__ = 'Parse saved text result from Memory PSList'

import collections
import IO_databaseOperations as db
import IO_fileProcessor as fp
import re
from config import CONFIG
import os

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
#DESCRIPTION: Parse and insert values into database process_list.mem_pslist
def parseAndPopulate(databaseConnectionHandle, filename):

    logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    logger.debug("filename is " + filename + "\n")

    fileBuffer = fp.dequeFile(filename)

    path = filename.split('\\')

    #Skip thru the buffer until the title line
    while fileBuffer[0] != ['Offset(V)', 'Name', 'PID', 'PPID', 'Thds', 'Hnds', 'Sess', 'Wow64', 'Start', 'Exit']:
        fileBuffer.popleft()

    #Remove the title
    fileBuffer.popleft()

    #Remove the ---- line
    fileBuffer.popleft()

    while fileBuffer:

        temp = fileBuffer.popleft()
        logger.debug("temp is " + str(temp) + "\n")

        if len(temp) < 11:
            logger.error("ERROR Pslist: Problem processing the following line as some fields are missing :")
            logger.error(str(temp))
        else:
            #To handle process name with spaces
            procname = ""
            totalNameItems = 0
            for index, value in enumerate(temp):
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

            #for lines with more than 12 elements
            if len(temp)-totalNameItems+1 > 12:
                offsetv = temp[0]

                #We need to work backwards due to the possibility of procname with spaces
                try:
                    pid = temp[-12]
                except (ValueError,IndexError) as e:
                    pid = ""
                    logger.error("ERROR Pslist: Problem assigning pid due to " + str(e))
                    pass

                try:
                    ppid = temp[-11]
                except (ValueError,IndexError) as e:
                    ppid = ""
                    logger.error("ERROR Pslist: Problem assigning ppid due to " + str(e))
                    pass

                try:
                    thds = temp[-10]
                except (ValueError,IndexError) as e:
                    thds = ""
                    logger.error("ERROR Pslist: Problem assigning thds due to " + str(e))
                    pass

                if '.' or '--' in temp[-9]:
                    hnds = "0"
                else:
                    try:
                        hnds = temp[-9]
                    except (ValueError,IndexError) as e:
                        hnds = ""
                        logger.error("ERROR Pslist: Problem assigning hnds due to " + str(e))
                        pass

                if '--' in temp[-8]:
                    sess = "0"
                else:
                    try:
                        sess = temp[-8]
                    except (ValueError,IndexError) as e:
                        sess = ""
                        logger.error("ERROR Pslist: Problem assigning sess due to " + str(e))
                        pass

                try:
                    wow64 = temp[-7]
                except (ValueError,IndexError) as e:
                    wow64 = ""
                    logger.error("ERROR Pslist: Problem assigning wow64 due to " + str(e))
                    pass

                #combine subsequent elements as they belong to the same field
                try:
                    start = " ".join(temp[-6:-3])
                except (ValueError,IndexError) as e:
                    start = ""
                    logger.error("ERROR Pslist: Problem assigning start due to " + str(e))
                    pass

                #combine subsequent elements as they belong to the same field
                try:
                    exit = " ".join(temp[-3:])
                except (ValueError,IndexError) as e:
                    exit = ""
                    logger.error("ERROR Pslist: Problem assigning exit due to " + str(e))
                    pass

                logger.debug("offsetv is " + offsetv + "\n")
                logger.debug("procname is " + procname + "\n")
                logger.debug("pid is " + pid + "\n")
                logger.debug("ppid is " + ppid + "\n")
                logger.debug("thds is " + thds + "\n")
                logger.debug("hnds is " + hnds + "\n")
                logger.debug("sess is " + sess + "\n")
                logger.debug("wow64 is " + wow64 + "\n")
                logger.debug("combined start is " + start + "\n")
                logger.debug("combined exit is " + exit + "\n")

            #for lines with 11 elements (minimal)
            else:
                offsetv = temp[0]

                #We need to work backwards due to the possibility of procname with spaces
                try:
                    pid = temp[-9]
                except (ValueError,IndexError) as e:
                    pid = ""
                    logger.error("ERROR Pslist: Problem assigning pid due to " + str(e))
                    pass

                try:
                    ppid = temp[-8]
                except (ValueError,IndexError) as e:
                    ppid = ""
                    logger.error("ERROR Pslist: Problem assigning ppid due to " + str(e))
                    pass

                try:
                    thds = temp[-7]
                except (ValueError,IndexError) as e:
                    thds = ""
                    logger.error("ERROR Pslist: Problem assigning thds due to " + str(e))
                    pass

                if '--' in temp[-6] or '.' in temp[-6]:
                    hnds = "0"
                else:
                    try:
                        hnds = temp[-6]
                    except (ValueError,IndexError) as e:
                        hnds = ""
                        logger.error("ERROR Pslist: Problem assigning hnds due to " + str(e))
                        pass


                if '--' in temp[-5]:
                    sess = "0"
                else:
                    try:
                        sess = temp[-5]
                    except (ValueError,IndexError) as e:
                        sess = ""
                        logger.error("ERROR Pslist: Problem assigning sess due to " + str(e))
                        pass
                try:
                    wow64 = temp[-4]
                except (ValueError,IndexError) as e:
                        sess = ""
                        logger.error("ERROR Pslist: Problem assigning wow64 due to " + str(e))
                        pass

                #combine subsequent elements as they belong to the same field
                try:
                    start = " ".join(temp[-3:])
                except (ValueError,IndexError) as e:
                    start = ""
                    logger.error("ERROR Pslist: Problem assigning start due to " + str(e))
                    pass

                exit = None

                logger.debug("offsetv is " + offsetv + "\n")
                logger.debug("procname is " + procname + "\n")
                logger.debug("pid is " + pid + "\n")
                logger.debug("ppid is " + ppid + "\n")
                logger.debug("thds is " + thds + "\n")
                logger.debug("hnds is " + hnds + "\n")
                logger.debug("sess is " + sess + "\n")
                logger.debug("wow64 is " + wow64 + "\n")
                logger.debug("combined start is " + start + "\n")
                logger.debug("exit is " + str(exit) + "\n")


            insertValue = collections.OrderedDict.fromkeys(['imagename', 'offsetv', 'procname', 'pid','ppid','thds','hnds','sess', 'wow64', 'start', 'exit'])

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
                logger.error("ERROR Pslist: Problem processing the following line as pid field is NOT numeric :")
                logger.error("pid is " + pid)
                logger.error(str(temp))


            if ppid.isdigit():
                insertValue['ppid'] = ppid
            else:
                skip = True
                logger.error("ERROR Pslist: Problem processing the following line as ppid field is NOT numeric :")
                logger.error("ppid is " + ppid)
                logger.error(str(temp))

            if thds.isdigit():
                insertValue['thds'] = thds
            else:
                skip = True
                logger.error("ERROR Pslist: Problem processing the following line as thds field is NOT numeric :")
                logger.error("thds is " + thds)
                logger.error(str(temp))

            if hnds.isdigit():
                insertValue['hnds'] = hnds
            else:
                skip = True
                logger.error("ERROR Pslist: Problem processing the following line as hnds field is NOT numeric :")
                logger.error("hnds is " + hnds)
                logger.error(str(temp))

            if sess.isdigit():
                insertValue['sess'] = sess
            else:
                skip = True
                logger.error("ERROR Pslist: Problem processing the following line as sess field is NOT numeric :")
                logger.error("sess is " + sess)
                logger.error(str(temp))

            if wow64.isdigit():
                insertValue['wow64'] = wow64
            else:
                skip = True
                logger.error("ERROR Pslist: Problem processing the following line as wow64 field is NOT numeric :")
                logger.error("wow64 is " + wow64)
                logger.error(str(temp))

            insertValue['start'] = start
            insertValue['exit'] = exit

            if skip == False:
                Schema = "process_list"
                Table = "mem_pslist"

                logger.debug("insertValue is " + str(insertValue) + "\n")
                db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)

            #Reset
            insertValue = collections.OrderedDict.fromkeys(['imagename', 'offsetv', 'procname', 'pid','ppid','thds','hnds','sess', 'wow64', 'start', 'exit'])




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
