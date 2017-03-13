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
    
    insertValue = collections.OrderedDict.fromkeys(['imagename', 'interface', 'ipaddress', 'macaddress', 'type'])
    insertValue['imagename'] = path[1]
    
    try:
        #For lines before the first "Process information for <HOSTNAME>:"
        while fileBuffer.count != 0:
            interfaceheader = fileBuffer.popleft()
            if interfaceheader[0] == 'Interface:':
                insertValue['interface'] = interfaceheader[1]
                fileBuffer.popleft()
                while fileBuffer[0][0] != 'Interface:':
                    arpdata = fileBuffer.popleft()
                    insertValue['ipaddress'] = arpdata[0]
                    insertValue['macaddress'] = arpdata[1]
                    insertValue['type'] = arpdata[2]

                    Schema = "system"
                    Table = "triage_sysinfo_arp"
                    db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)

    except (ValueError,IndexError) as e:
        logger.error("Processes: Problem inserting into database due to " + str(e))
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
