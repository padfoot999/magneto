#!/usr/bin/python -tt
__author__ = "ZF"
__description__ = 'To import and launch individual parsers to insert into database for Triage and Memory files'

import os
import sys
import getopt
import collections
import argparse
import pickle

#Customized python modules
import IO_databaseOperations as db
import IO_fileProcessor

import PARSER_parseTriageSystemInfo
import PARSER_parseTriageSystemVariables
import PARSER_parseTriageProcesses
import PARSER_parseTriageNetworkConnections

import PARSER_parseMemoryPslist
import PARSER_parseMemoryPstree
import PARSER_parseMemoryPsxview
import PARSER_parseMemoryEnvars
import PARSER_parseMemoryNetscan

from config import CONFIG


#For log file
import logging
logger = logging.getLogger('root')


#NAME:process
#INPUT: database connection handle, directory to evidence files
#OUTPUT: NONE
#DESCRIPTION:   
def process(databaseConnectionHandle, directory):
    unprocessedlist=[]    
    cur = databaseConnectionHandle.cursor()

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(directory):
        path = root.split('/')
        # logger.info("root is " + root)
        # logger.info("dirs is " + str(dirs))
        # logger.info("files is " + str(files))
        for filename in files:
            #Queueing all triage output files for processing. Once processed, they are removed
            if filename.endswith(('.txt','.csv','.raw')):                
                unprocessedlist.append(os.path.join(root,filename))

        for rawFile in unprocessedlist:

            if "/System Info.txt" in rawFile:
                logger.info("System Info file is " + rawFile)
                try:
                    logger.info("Processing System Info...")                    
                    PARSER_parseTriageSystemInfo.parseAndPopulate(databaseConnectionHandle, rawFile)
                    logger.info("Processing System Info Completed.")
                except:
                    logger.error("Error encountered at PARSER_parseTriageSystemInfo.")                    
                    sys.exit()
                    pass

            if "/System Variables.txt" in rawFile:
                logger.info("System Variables file is " + rawFile)
                try:
                    logger.info("Processing System Variables...")
                    PARSER_parseTriageSystemVariables.parseAndPopulate(databaseConnectionHandle, rawFile)
                    logger.info("Processing System Variables Completed.")                    
                except:
                    logger.error("Error encountered at PARSER_parseTriageSystemVariables.")                    
                    sys.exit()
                    pass

            
            if "/Processes.txt" in rawFile:
                logger.info("Processes file is " + rawFile)
                try:
                    logger.info("Processing Processes...")
                    PARSER_parseTriageProcesses.parseAndPopulate(databaseConnectionHandle, rawFile)                    
                    logger.info("Processing Processes Completed.")                    
                except:
                    logger.error("Error encountered at PARSER_parseTriageProcesses.")                    
                    sys.exit()
                    pass

            if "/Network Connections.txt" in rawFile:
                logger.info("Network Connections file is " + rawFile)
                try:
                    logger.info("Processing Network Connections...")                    
                    PARSER_parseTriageNetworkConnections.parseAndPopulate(databaseConnectionHandle, rawFile)                    
                    logger.info("Processing Network Connections Completed.")                    
                except:
                    logger.error("Error encountered at PARSER_parseTriageNetworkConnections.")                    
                    sys.exit()
                    pass


            # if rawFile == root + "/output_pslist.txt":
            if "-memory-pslist.txt" in rawFile:
                logger.info("pslist file is " + rawFile)
                try:
                    logger.info("Processing pslist...")                
                                    
                    PARSER_parseMemoryPslist.parseAndPopulate(databaseConnectionHandle, rawFile)
                    logger.info("Processing pslist Completed.")                    
                except:
                    logger.error("Error encountered at PARSER_parseMemoryPslist.")                    
                    sys.exit()
                    pass
            
            if "-memory-pstree.txt" in rawFile:
                logger.info("pstree file is " + rawFile)
                try:

                    logger.info("Processing pstree...")                                        
                    PARSER_parseMemoryPstree.parseAndPopulate(databaseConnectionHandle, rawFile)
                    logger.info("Processing pstree Completed.")                    
                except:
                    logger.error("Error encountered at PARSER_parseMemoryPstree.")                    
                    sys.exit()
                    pass

            
            if "-memory-psxview.txt" in rawFile:
                logger.info("psxview file is " + rawFile)
                try:
                    logger.info("Processing psxview...")                                        
                    PARSER_parseMemoryPsxview.parseAndPopulate(databaseConnectionHandle, rawFile)
                    logger.info("Processing output_psxview Completed.")                    
                except:
                    logger.error("Error encountered at PARSER_parseMemoryPsxview.")                    
                    sys.exit()
                    pass
            
            if "-memory-envars.txt" in rawFile:
                logger.info("envars file is " + rawFile)
                try:
                    logger.info("Processing envars...")                    
                    PARSER_parseMemoryEnvars.parseAndPopulate(databaseConnectionHandle, rawFile)
                    logger.info("Processsing envars Completed.")                    
                except:
                    logger.error("Error encountered at PARSER_parseMemoryEnvars.")                    
                    sys.exit()
                    pass

            if "-memory-netscan.txt" in rawFile:
                logger.info("netscan file is " + rawFile)
                try:
                    logger.info("Processing netscan...")                    
                    PARSER_parseMemoryNetscan.parseAndPopulate(databaseConnectionHandle, rawFile)
                    logger.info("Processsing netscan Completed.")                    

                except:
                    logger.error("Error encountered at PARSER_parseMemoryNetscan.")                    
                    sys.exit()
                    pass

def main():
    
    db.databaseInitiate()
    
    #Image name is obtained from Incident Log.txt AND/OR *-log.txt from memory
    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    logger.info("dbhandle is " + str(dbhandle))

    searchDirectory = ''

    parser = argparse.ArgumentParser(description="Process triage, network or memory dump evidence file(s), sorted by projects for correlation")
    parser.add_argument('-d', dest='directory', type=str, help="Directory containing evidence files")
    parser.add_argument('-f', dest='file', type=str, help="Path to single evidence file")
    parser.add_argument('-p', dest='projectname', type=str, required=True, help="Codename of the project that the evidence is part of")
    args = parser.parse_args()

    if not args.directory:
        searchDirectory = args.file
    else:
        searchDirectory = args.directory

    name = args.projectname
    imagelist = []

    for root, dirs, files in os.walk(searchDirectory):
        path = root.split('/')
        imgname = path[-3]

        Schema = "project"
        Table = "project_image_mapping"

        
        insertProjectValue = collections.OrderedDict.fromkeys(['projectname','imagename'])
        insertProjectValue['projectname'] = name
        insertProjectValue['imagename'] = imgname

        #Triage folders always have the word incident
        if "Incident" in imgname:
            if imgname not in imagelist:
                imagelist.append(imgname)
                db.databaseInsert(dbhandle,Schema,Table,insertProjectValue)

        #ZFZFTODO: Need to handle memory and tcpdump folders?

    
    process(dbhandle, searchDirectory)

    
    


if __name__ == '__main__':
    main()

