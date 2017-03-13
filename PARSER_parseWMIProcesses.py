#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
__description__ = 'Parse saved text result from wmi-ProcessStatus.csv'

import collections
import IO_databaseOperations as db
import IO_fileProcessor as fp
from config import CONFIG
import os
import csv
import codecs
import chardet
import logging
logger = logging.getLogger('root')

import sys  
reload(sys)  
sys.setdefaultencoding('utf8')

import argparse

#NAME:parseAndPopulate
#INPUT:psycopg2-db-handle databaseConnectionHandle, string filename
#OUTPUT: NONE
#DESCRIPTION: Parse and insert values into database process_list.triage_processes_*
def parseAndPopulate(databaseConnectionHandle, filename):

    logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    logger.debug("filename is " + filename + "\n")
    #directory, imagename
    path = os.path.split(os.path.split(filename)[0])
    Schema = "process_list"
    Table = "wmi_processes"

    insertValue = collections.OrderedDict.fromkeys(['imagename', 'procname', 'pid'])
    insertValue['imagename'] = path[1]

    reader = csv.reader(codecs.open(filename, 'rU', "UTF-16"))
    for row in reader:
        try:
            insertValue['procname'] = row[1]
            insertValue['pid'] = int(row[2])
            db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)
        except:
            logger.info("Unable to insert %s", row)

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
