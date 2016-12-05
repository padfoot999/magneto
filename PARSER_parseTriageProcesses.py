#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
__description__ = 'Parse saved text result from Triage Processes.txt'

import collections
import IO_databaseOperations as db
import IO_fileProcessor as fp
from config import CONFIG
import os
import logging
logger = logging.getLogger('root')

import argparse

#NAME:parseAndPopulate
#INPUT:psycopg2-db-handle databaseConnectionHandle, string filename
#OUTPUT: NONE
#DESCRIPTION: Parse and insert values into database process_list.triage_processes_*
def parseAndPopulate(databaseConnectionHandle, filename):

    logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    logger.debug("filename is " + filename + "\n")

    fileBuffer = fp.dequeFile(filename)
    #directory, imagename
    path = os.path.split(os.path.split(filename)[0])

    try:
        #Skip thru the buffer until the title line
        while fileBuffer[0] != ['Image', 'Name', 'PID', 'Services']:
            fileBuffer.popleft()

    except (ValueError,IndexError) as e:
        logger.error("Processes: Problem finding 'Image', 'Name', 'PID', 'Services' headers due to " + str(e))
        pass

    try:
        #Remove the title
        fileBuffer.popleft()
    except (ValueError,IndexError) as e:
        logger.error("Processes: Problem popping due to " + str(e))
        pass

    try:
        #Remove the ====== line
        fileBuffer.popleft()
    except (ValueError,IndexError) as e:
        logger.error("Processes: Problem popping due to " + str(e))
        pass

    try:
        #For lines before the first "Process information for <HOSTNAME>:"
        while fileBuffer[0][0:3] != ['Process', 'information', 'for']:
            temp = fileBuffer.popleft()
            logger.debug("temp is " + str(temp))

            #Assuming that "Image Name" and "Services" does NOT contain number! This is a BAD BAD assumption
            if any(char.isdigit() for char in temp):
                for index, item in enumerate(temp):
                    if item.isdigit():
                        pid = item
                        logger.debug("pid " + str(pid))
                        procname =  " ".join(temp[0:index])
                        logger.debug("procname " + str(procname))
                        services = " ".join(temp[index+1:])
                        logger.debug("services " + str(services))
                        break
            else:
                logger.debug("Line DOES NOT have a number")
                #Concatenate with services [] initiated previously
                services += " "
                services += " ".join(temp)
                logger.debug("services " + str(services))

            insertValue = collections.OrderedDict.fromkeys(['imagename', 'procname', 'pid', 'services'])

            insertValue['imagename'] = path[1]

            if pid.isdigit():
                    insertValue['pid'] = pid
            else:
                logger.error("Processes: Problem processing the following line as pid field is NOT numeric :")
                print str(temp)

            insertValue['procname'] = procname
            insertValue['services'] = services

            Schema = "process_list"
            Table = "triage_processes"

            logger.debug("insertValue is " + str(insertValue) + "\n")
            db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)

            #reset
            insertValue = collections.OrderedDict.fromkeys(['imagename', 'procname', 'pid', 'services'])

    except (ValueError,IndexError) as e:
        logger.error("Processes: Problem finding first 'Process', 'information' headers due to " + str(e))
        pass
    #=========================================================================================#
    #For lines between the 1st and 2nd "Process information for <HOSTNAME>:"
    Schema = "process_list"
    Table = "triage_processes_tree"

    try:
        #Remove the title
        fileBuffer.popleft()
    except (ValueError,IndexError) as e:
        logger.error("Processes: Problem popping due to " + str(e))
        pass

    try:
        while fileBuffer[0][0:3] != ['Process', 'information', 'for']:
            if fileBuffer[0] == ['Name', 'Pid', 'Pri', 'Thd', 'Hnd', 'Priv', 'CPU', 'Time', 'Elapsed', 'Time']:
                #remove title
                fileBuffer.popleft()
            else:
                temp = fileBuffer.popleft()
                logger.debug("temp is " + str(temp) + "\n")

                #Join all item until the first number, which is likely the pid
                for index, item in enumerate(temp):
                    if item.isdigit():
                        logger.debug("index is " + str(index))
                        pid = item
                        logger.debug("pid " + str(pid))
                        procname =  " ".join(temp[0:index])
                        logger.debug("procname " + str(procname))

                        pid = temp[index]
                        pri = temp[index + 1]
                        thd = temp[index + 2]
                        hnd = temp[index + 3]
                        priv = temp[index + 4]

                        #Convert to milisecond
                        cpuTimeString = temp[index + 5]
                        cpuTimeList = cpuTimeString.split(':')
                        cpuTimeSeconds = cpuTimeList[2].split('.')
                        cputime = int(cpuTimeList[0])*60*60*1000 + int(cpuTimeList[1])*60*1000 + int(cpuTimeSeconds[0])*1000 + int(cpuTimeSeconds[1])
                        logger.debug("cputime is " + str(cputime) + "\n")

                        elapsedtime = temp[index + 6]
                        elapsedTimeString = temp[index + 5]
                        elapsedTimeList = elapsedTimeString.split(':')
                        elapsedTimeSeconds = elapsedTimeList[2].split('.')
                        elapsedtime = int(elapsedTimeList[0])*60*60*1000 + int(elapsedTimeList[1])*60*1000 + int(elapsedTimeSeconds[0])*1000 + int(elapsedTimeSeconds[1])
                        logger.debug("elapsedTimeInt is " + str(elapsedtime) + "\n")

                        break


                logger.debug("procname is " + procname + "\n")
                logger.debug("pid is " + pid + "\n")
                logger.debug("pri is " + pri + "\n")
                logger.debug("thd is " + thd + "\n")
                logger.debug("hnd is " + hnd + "\n")
                logger.debug("priv is " + priv + "\n")
                logger.debug("cputime is " + str(cputime) + "\n")
                logger.debug("elapsedtime is " + str(elapsedtime) + "\n")

                insertValue = collections.OrderedDict.fromkeys(['imagename', 'procname', 'pid','pri','thd','hnd','priv', 'cputime', 'elapsedtime'])

                #Need to process directory and get directory name as the imagename
                insertValue['imagename'] = path[1]
                insertValue['procname'] = procname
                insertValue['pid'] = pid

                if pid.isdigit():
                    insertValue['pid'] = pid
                else:
                    logger.error("Processes: Problem processing the following line as pid field is NOT numeric :")
                    print str(temp)

                if pri.isdigit():
                    insertValue['pri'] = pri
                else:
                    logger.error("Processes: Problem processing the following line as pri field is NOT numeric :")
                    print str(temp)

                if thd.isdigit():
                    insertValue['thd'] = thd
                else:
                    logger.error("Processes: Problem processing the following line as thd field is NOT numeric :")
                    print str(temp)

                if hnd.isdigit():
                    insertValue['hnd'] = hnd
                else:
                    logger.error("Processes: Problem processing the following line as hnd field is NOT numeric :")
                    print str(temp)

                if priv.isdigit():
                    insertValue['priv'] = priv
                else:
                    logger.error("Processes: Problem processing the following line as priv field is NOT numeric :")
                    print str(temp)

                insertValue['cputime'] = str(cputime)
                insertValue['elapsedtime'] = str(elapsedtime)

                #reset
                logger.debug("insertValue is " + str(insertValue) + "\n")
                db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)
    except (ValueError,IndexError) as e:
        logger.error("Processes: Problem finding 2nd 'Process', 'information', 'for' headers due to " + str(e))
        pass

    try:
        #Remove line 'Process', 'information', 'for'
        fileBuffer.popleft()
    except (ValueError,IndexError) as e:
        logger.error("Processes: Problem popping due to " + str(e))
        pass

    try:
        temp = fileBuffer.popleft()
    except (ValueError,IndexError) as e:
            logger.error("Processes: Problem popping due to " + str(e))
            pass

    while fileBuffer:

        try:
            if temp == ['Name', 'Pid', 'Pri', 'Thd', 'Hnd', 'VM', 'WS', 'Priv']:
                #remove title
                fileBuffer.popleft()
            else:
                logger.debug("temp2 is " + str(temp) + "\n")
                #procname, pid, pri,thd,hnd and priv are already populated previously
                pid = temp[-7]
                vm = temp[-3]
                ws = temp[-2]
                priv = temp[-1]

                logger.debug("pid is " + pid + "\n")
                logger.debug("vm is " + vm + "\n")
                logger.debug("ws " + ws + "\n")
                logger.debug("priv " + priv + "\n")

                setValue = collections.OrderedDict.fromkeys(['vm','ws'])
                whereValue = collections.OrderedDict.fromkeys(['imagename','pid','priv'])

                #Need to process directory and get directory name as the imagename
                whereValue['imagename'] = path[1]

                if pid.isdigit():
                    whereValue['pid'] = pid
                else:
                    logger.error("Processes: Problem processing line as pid field is NOT numeric")

                if priv.isdigit():
                    whereValue['priv'] = priv
                else:
                    logger.error("Processes: Problem processing line as priv field is NOT numeric")

                setValue['vm'] = vm
                setValue['ws'] = ws

                #Note that this is updating values!
                #Note: If there are non-unique entries, they WILL NOT be updated. Need to fix the Primary Key issue.
                logger.debug("setValue is " + str(setValue) + "\n")
                db.databaseUpdate(databaseConnectionHandle,Schema,Table,setValue,whereValue)

            temp = fileBuffer.popleft()

        except (ValueError,IndexError) as e:
            logger.error("Processes: Problem finding 'Name', 'Pid', 'Pri', 'Thd', 'Hnd', 'VM', 'WS', 'Priv' headers due to " + str(e))
            pass

#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    logger.debug("dbhandle is " + str(dbhandle) + "\n")

    parseAndPopulate(dbhandle,filename)

if __name__ == '__main__':
    main()
