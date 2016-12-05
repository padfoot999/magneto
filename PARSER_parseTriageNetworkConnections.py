#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
__description__ = 'Parse saved text result from Triage Network Connections.txt'

import collections
import os
import sys
import IO_databaseOperations as db
import IO_fileProcessor as fp
from config import CONFIG
import os

import logging
logger = logging.getLogger('root')



# Flag all ESTABLISHED IPv6 connection as suspicious! 
# Proto  Local Address          Foreign Address        State           PID
#   TCP    127.0.0.1:1026         127.0.0.1:50414        TIME_WAIT       0      //#These TCP connections have closed and is being queued by the system for remaining TCP packets.
#   TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       396    // 0.0.0.0 means that host is listening on all interfaces at port 135.
#   TCP    10.156.99.73:139       0.0.0.0:0              LISTENING       4      //Host is listening to the Internet!
#   TCP    10.156.99.73:49263     10.156.67.152:5061     ESTABLISHED     3360   //Host is connected to Internet!
#   TCP    127.0.0.1:49306        0.0.0.0:0              LISTENING       4480   //Host is listening on port 49306 for loopback connections
#   TCP    [::]:135               [::]:0                 LISTENING       396    //IPv6 equivalent of "TCP 0.0.0.0:135  0.0.0.0:0"
#   UDP    0.0.0.0:123            *:*                                    868    // Host is listening on all interfaces at port 123. Note the different annotation for foreign address
#   UDP    10.156.99.73:137       *:*                                    4      //Host is listening on port 137 for Internet traffic!
#   UDP    127.0.0.1:1900         *:*                                    4180   //Listening on port 1900 for loopback connections
#   UDP    [::]:123               *:*                                    868    //IPv6 equivalent of "UDP 0.0.0.0:123  *:*"
#   UDP    [::1]:1900             *:*                                    4180   //IPv6 equivalent of "UDP 127.0.0.1:1900   *:* "


import argparse

#NAME:parseAndPopulate
#INPUT:psycopg2-db-handle databaseConnectionHandle, string filename
#OUTPUT: NONE
#DESCRIPTION: Parse and insert values into database process_list.triage_processes_*
def parseAndPopulate(databaseConnectionHandle, filename):

    logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    logger.debug("filename is " + filename + "\n")

    fileBuffer = fp.dequeFile(filename)

    path = os.path.split(os.path.split(filename)[0])
    logger.debug("PATH is " + str(path))
    logger.debug("imagename is " + str(path[-2]))

    try:
        #Skip thru the buffer until the title line
        while fileBuffer[0] != ['Proto', 'Local', 'Address', 'Foreign', 'Address', 'State', 'PID']:            
            fileBuffer.popleft()

    except (ValueError,IndexError) as e:
        logger.error("Problem finding 'Proto', 'Local Address','Foreign Address','State','PID' headers due to " + str(e))
        pass

    try:
        #Remove the line containing "Proto  LocalAddress ForeignAddress State PID"
        fileBuffer.popleft()
    except (ValueError,IndexError) as e:
        logger.error("Problem popping 'Proto', 'Local Address','Foreign Address','State','PID' headers due to " + str(e))
        pass

    try:
        
        logger.debug("fileBuffer[0] is " + str(fileBuffer[0]))
        while fileBuffer[0] != ['Active', 'Connections']:

            #used to hold the line for processing later
            temp = fileBuffer.popleft()
            logger.debug(str(temp))

            #iniatlizing dictionary to store data for inserting into database
            insertValue = collections.OrderedDict.fromkeys(['imagename', 'protocol','source', 'sourceport', 'destination', 'destinationport', 'state', 'pid'])
            insertValue['imagename'] = path[1]
            insertValue['protocol'] = temp[0]

            try:
                #Check for IPv6, Processing IPv6
                if "[" in temp[1]:
                    temp_list = temp[1].split("]:")
                    logger.debug(str(temp_list))
                    insertValue['source'] = temp_list[0] + "]"
                    insertValue['sourceport'] = int(temp_list[1])
                else:
                    #processing IPv4
                    temp_list = temp[1].split(':')
                    logger.debug(str(temp_list))
                    insertValue['source'] = temp_list[0]
                    insertValue['sourceport'] = int(temp_list[1])
            
            except (ValueError,IndexError) as e:
                logger.error("Problem splitting \"Local Address\" line into IP address and port due to " + str(e))
                #exit first to troubleshoot
                sys.exit()

            try:
                if "[" in temp[1]:
                    temp_list = temp[1].split("]:")
                    logger.debug(str(temp_list))
                    insertValue['destination'] = temp_list[0] + "]"
                    insertValue['destinationport'] = int(temp_list[1])
                else:                
                    temp_list = temp[2].split(':')
                    logger.debug(str(temp_list))
                    insertValue['destination'] = temp_list[0]

                    #If value is *:*, we will assign it 0
                    if temp_list[1] == "*":
                        insertValue['destinationport'] = 0
                    else:
                        insertValue['destinationport'] = int(temp_list[1])
            except (ValueError,IndexError) as e:
                logger.error("Problem splitting \"Foreign Address\" line into IP address and port due to " + str(e))
                #exit first to troubleshoot
                sys.exit()

            try:
                if temp[3] == "ESTABLISHED" or temp[3] == "LISTENING":
                    insertValue['state'] = temp[3]   
                    logger.debug(str(insertValue))
            except (ValueError,IndexError) as e:
                logger.error("Unable to determine STATE of connection due to " + str(e))
                #exit first to troubleshoot
                sys.exit()

            try:  
                #Not temp[4] as some entries does not have STATE value
                insertValue['pid'] = int(temp[-1])
            except (ValueError,IndexError) as e:
                logger.error("Unable to convert pid string into number due to " + str(e))
                #exit first to troubleshoot                
                sys.exit()
                          
            logger.debug("insertValue is " + str(insertValue))
            Schema = "network"
            Table = "triage_network_connections"
            db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)
            

    except (ValueError,IndexError) as e:
        logger.error("Problem finding first 'Active', 'Connections' headers due to " + str(e))
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
