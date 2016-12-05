#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
__description__ = 'Parse saved text result from Memory Volatility netscan plugin output *-memory-netscan.txt'

import collections
import os
import sys
import logging

import IO_databaseOperations as db
import IO_fileProcessor as fp
from config import CONFIG
import os
import logging
logger = logging.getLogger('root')

#NAME:parseAndPopulate
#INPUT:psycopg2-db-handle databaseConnectionHandle, string filename
#OUTPUT: NONE
#DESCRIPTION: Parse and insert values into database process_list.triage_processes_*
def parseAndPopulate(databaseConnectionHandle, filename):

    logger.info("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    logger.info("filename is " + filename + "\n")

    fileBuffer = fp.dequeFile(filename)

    path = os.path.split(os.path.split(os.path.split(filename)[0])[0])
    logger.info("PATH is " + str(path))    

    try:
        #Skip thru the buffer until the title line
        while fileBuffer[0] != ['Offset(P)', 'Proto', 'Local', 'Address', 'Foreign', 'Address', 'State', 'Pid','Owner','Created']:            
            fileBuffer.popleft()        

    except (ValueError,IndexError) as e:
        logger.error("Problem finding 'Offset(P)', 'Proto', 'Local', 'Address', 'Foreign', 'Address', 'State', 'Pid','Owner','Created' headers due to " + str(e))
        pass

    try:
        #Remove the line containing "Proto  LocalAddress ForeignAddress State PID"
        fileBuffer.popleft()
    except (ValueError,IndexError) as e:
        logger.error("Problem popping 'Offset(P)', 'Proto', 'Local', 'Address', 'Foreign', 'Address', 'State', 'Pid','Owner','Created' headers due to " + str(e))
        pass

    try:                
        while fileBuffer:
            #used to hold the line for processing later
            temp = fileBuffer.popleft()
            logger.info(str(temp))
            

            #iniatlizing dictionary to store data for inserting into database
            insertValue = collections.OrderedDict.fromkeys(['imagename', 'protocol','source', 'sourceport', 
                'destination', 'destinationport', 'state', 'pid', 'owner','timecreated','memoryoffset'])
            
            insertValue['imagename'] = path[1]
            
            insertValue['memoryoffset'] = temp[0]
            if temp[1] == "UDPv4" or temp[1] == "UDPv6":
                insertValue['protocol'] = "UDP"
            if temp[1] == "TCPv4" or temp[1] == "TCPv6":
                insertValue['protocol'] = "TCP"

            try:                
                #processing source
                #split by the last delimiter instead of first using rsplit
                temp_list = temp[2].rsplit(':',1)
                logger.info(str(temp_list))

                if temp[1] == "UDPv6" or temp[1] =="TCPv6":
                    #add square bracket around IPv6 to be in line with triage network connection representation
                    insertValue['source'] = "[" + temp_list[0] + "]"
                else:
                    insertValue['source'] = temp_list[0]                    
                                    #If value is *:*, we will assign it 0
                
                if temp_list[1] == "*":
                    insertValue['sourceport'] = 0
                else:
                    insertValue['sourceport'] = int(temp_list[1])
                
            except (ValueError,IndexError) as e:
                logger.error("Problem splitting \"Local Address\" line into IP address and port due to " + str(e))
                sys.exit()

                

            try:                
                #processing destination
                #split by the last delimiter instead of first using rsplit
                temp_list = temp[3].rsplit(':',1)
                logger.info(str(temp_list))

                if temp[1] == "UDPv6" or temp[1] =="TCPv6":
                    #add square bracket around IPv6 to be in line with triage network connection representation
                    insertValue['destination'] = "[" + temp_list[0] + "]"
                else:
                    insertValue['destination'] = temp_list[0]                                       
                
                if temp_list[1] == "*":
                    insertValue['destinationport'] = 0
                else:
                    insertValue['destinationport'] = int(temp_list[1])
                
                
            except (ValueError,IndexError) as e:
                logger.error("Problem splitting \"Foreign Address\" line into IP address and port due to " + str(e))
                sys.exit()

            try:
                if temp[4] == "ESTABLISHED" or temp[4] == "LISTENING" or temp[4] == "CLOSED" or temp[4] == "FIN_WAIT2":
                    insertValue['state'] = temp[4]
                    parsingOffset = 1
                else:
                    #Means temp[4] is a pid. 
                    parsingOffset = 0
            except (ValueError,IndexError) as e:
                logger.error("Unable to determine STATE of connection due to " + str(e))
                #exit first to troubleshoot
                sys.exit()

            if temp[4 + parsingOffset] == "-1":
                #As database is set to numeric, -1 does not fit.
                logger.debug("ZERO")
            else:
                insertValue['pid'] = int(temp[4 + parsingOffset])

            try:    
                insertValue['owner'] = temp[5 + parsingOffset]
            except:
                #in case there is no temp[5], which is ok
                pass

            try:
                insertValue['timecreated'] = temp[6 + parsingOffset:]
            except:
                #in case there is no temp[6], which is ok
                pass

                          
            logger.debug("insertValue is " + str(insertValue) + "\n")
            Schema = "network"
            Table = "mem_netscan"
            db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)
            

    except (ValueError,IndexError) as e:
        logger.error("Error parsing to the end of file due to " + str(e))
        pass
    

#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    logger.info("dbhandle is " + str(dbhandle) + "\n")

    filename = "/home/z/testfiles/20160630172626 - SGC10709 Incident_DesmondHo/Evidence/20160906_062043--memory-netscan.txt"
    parseAndPopulate(dbhandle,filename)
    
if __name__ == '__main__':
    main()
