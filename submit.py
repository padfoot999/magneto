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
import PARSER_parseTriageARPInfo
import PARSER_parseTriageSystemVariables
import PARSER_parseTriageProcesses
import PARSER_parseTriageNetworkConnections
import PARSER_parseWMIProcesses

import PARSER_parseMemoryPslist
import PARSER_parseMemoryPstree
import PARSER_parseMemoryPsxview
import PARSER_parseMemoryEnvars
import PARSER_parseMemoryNetscan

from config import CONFIG

#For log file
import logging
logger = logging.getLogger('root')
fileArg = False

#NAME:process
#INPUT: database connection handle, directory to evidence files
#OUTPUT: NONE
#DESCRIPTION:   
def dbprocess(databaseConnectionHandle, directory):
	unprocessedlist=[]    
	cur = databaseConnectionHandle.cursor()
	if not fileArg:
		# traverse root directory, and list directories as dirs and files as files
		for root, dirs, files in os.walk(directory):
			# logger.info("root is " + root)
			# logger.info("dirs is " + str(dirs))
			# logger.info("files is " + str(files))
			for filename in files:
				#Queueing all triage output files for processing. Once processed, they are removed
				if filename.endswith(('.txt','.csv','.raw')):
					if str(os.path.join(root,filename)) not in unprocessedlist:             
						unprocessedlist.append(os.path.join(root,filename))
	else:
		logger.info("Success")
		unprocessedlist.append(directory)

	for rawFile in unprocessedlist:
		if "ARP Info.txt" in rawFile:
			logger.info("System ARP file is " + rawFile)
			try:
				logger.info("Processing ARP Info...")                    
				PARSER_parseTriageARPInfo.parseAndPopulate(databaseConnectionHandle, rawFile)
				logger.info("Processing System Info Completed.")
			except Exception as e:
				logger.error("Error encountered at PARSER_parseTriageARPInfo.")
				logger.error(e.message)                    
				sys.exit()
				pass

		if "System Info.txt" in rawFile:
			logger.info("System Info file is " + rawFile)
			try:
				logger.info("Processing System Info...")                    
				PARSER_parseTriageSystemInfo.parseAndPopulate(databaseConnectionHandle, rawFile)
				logger.info("Processing System Info Completed.")
			except Exception as e:
				logger.error("Error encountered at PARSER_parseTriageSystemInfo.")
				logger.error(e)                    
				sys.exit()
				pass

		if "System Variables.txt" in rawFile:
			logger.info("System Variables file is " + rawFile)
			try:
				logger.info("Processing System Variables...")
				PARSER_parseTriageSystemVariables.parseAndPopulate(databaseConnectionHandle, rawFile)
				logger.info("Processing System Variables Completed.")                    
			except Exception as e:
				logger.error("Error encountered at PARSER_parseTriageSystemVariables.") 
				logger.error(e.message)                    
				sys.exit()
				pass
		
		if "Processes.txt" in rawFile:
			logger.info("Processes file is " + rawFile)
			try:
				logger.info("Processing Processes...")
				PARSER_parseTriageProcesses.parseAndPopulate(databaseConnectionHandle, rawFile)                    
				logger.info("Processing Processes Completed.")                    
			except Exception as e:
				logger.error("Error encountered at PARSER_parseTriageProcesses.") 
				logger.error(e.message, e.args)                   
				sys.exit()
				pass

		if "Network Connections.txt" in rawFile:
			logger.info("Network Connections file is " + rawFile)
			try:
				logger.info("Processing Network Connections...")                    
				PARSER_parseTriageNetworkConnections.parseAndPopulate(databaseConnectionHandle, rawFile)                    
				logger.info("Processing Network Connections Completed.")                    
			except Exception as e:
				logger.error(e.message, e.args) 
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

		if "wmi-ProcessStatus.csv" in rawFile:
			logger.info("WMI Process Status file is " + rawFile)
			try:
				logger.info("Processing wmi process status...")                    
				PARSER_parseWMIProcesses.parseAndPopulate(databaseConnectionHandle, rawFile)
				logger.info("Processsing wmi process status Completed.")                    
			except Exception as e:
				logger.error(e)
				logger.error("Error encountered at PARSER_parseWMIProcesses.")                    
				sys.exit()
				pass

def main():
	
	db.databaseInitiate()
	global fileArg
	
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
		fileArg = True
	else:
		searchDirectory = args.directory

	imagelist = []
	Schema = "project"
	Table = "project_image_mapping"
	insertProjectValue = collections.OrderedDict.fromkeys(['projectname','imagename'])

	#Path that is being passed in is only one Incident Folder / or a single file
	if "Incident" in searchDirectory:
		pathParts = searchDirectory.split('\\')
		for part in pathParts:
			if "Incident" in part:
				imagelist.append(part)
				insertProjectValue['projectname'] = args.projectname
				insertProjectValue['imagename'] = part
				db.databaseExistInsert(dbhandle,Schema,Table,insertProjectValue)
				dbprocess(dbhandle, searchDirectory)
				
	else:
		for root, dirs, files in os.walk(searchDirectory):
		#searchDirectory cannot end with a slash!
			for directory in dirs:
				if "Incident" in directory:
						if directory not in imagelist:
							imagelist.append(directory)
							insertProjectValue['projectname'] = args.projectname
							insertProjectValue['imagename'] = directory
							db.databaseExistInsert(dbhandle,Schema,Table,insertProjectValue)
							dbprocess(dbhandle, str(os.path.join(root,directory)))
	
if __name__ == '__main__':
	main()

