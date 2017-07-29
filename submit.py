#!/usr/bin/python -tt
__author__ = "ZF"
__description__ = 'To import and launch individual parsers to insert into database for Triage and Memory files'

import os
import sys
import getopt
import collections
import argparse
import pickle

import IO_databaseOperations as db
import PROCESS_postTriage as postTriage
import PROCESS_submitDatabase as submitDatabase
import OUTPUT_summary as summary 
import OUTPUT_timeline as timeline 
from config import CONFIG

#For log file
import logging
logger = logging.getLogger('root')
fileArg = False

def main():	
	parser = argparse.ArgumentParser(description="Process triage, network or memory dump evidence file(s), sorted by projects for correlation")
	parser.add_argument('-d', dest='directory', type=str, help="Directory containing evidence files")
	parser.add_argument('-p', dest='projectname', type=str, required=True, help="Codename of the project that the evidence is part of")
	parser.add_argument('-s', dest='split', type=int, required=False, help="Split timeline to number of excel workbooks specified by input")
	args = parser.parse_args()

	if args.split:
		split = args.split
	else:
		split = 0

	#Initialize folders
	projectName = args.projectname
	searchDirectory = args.directory
	magnetodir = os.getcwd()
	resultsDir = magnetodir + "/Results"
	if not os.path.exists(resultsDir):
		try:
			os.makedirs(resultsDir)
		except:
			logging.error("Unable to create results folder")
			sys.exit()

	projResultsDir = magnetodir + "/Results/" + projectName 
	if not os.path.exists(projResultsDir):
		try:
			os.makedirs(projResultsDir)
		except:
			logging.error("Unable to create Project results folder")
			sys.exit()

	#Initialize database
	DATABASE = CONFIG['DATABASE']
	dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
	logger.info("dbhandle is " + str(dbhandle))

	db.databaseInitiate()
	imagelist = []
	Schema = "project"
	Table = "project_image_mapping"
	insertProjectValue = collections.OrderedDict.fromkeys(['projectname','imagename'])

	#Process Incident Folders
	if "Incident" in searchDirectory:
		pathParts = searchDirectory.split('\\')
		for part in pathParts:
			if "Incident" in part:
				insertProjectValue['projectname'] = args.projectname
				insertProjectValue['imagename'] = part
				db.databaseExistInsert(dbhandle,Schema,Table,insertProjectValue)
		postTriage.postTriage(searchDirectory, projectName)
		submitDatabase.dbprocess(dbhandle, searchDirectory)
		summary.outputSummary(searchDirectory, projectName, projResultsDir)
		timeline.outputTimeline(searchDirectory,projectName,projResultsDir,split)
					
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
							postTriage.postTriage(searchDirectory, projectName)
							submitDatabase.dbprocess(dbhandle, searchDirectory)
							summary.outputSummary(searchDirectory, projectName, projResultsDir)
							timeline.outputTimeline(searchDirectory,projectName,projResultsDir,split)

	
if __name__ == '__main__':
	main()

