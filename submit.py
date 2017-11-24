#!/usr/bin/python -tt
__author__ = "ZF"
__description__ = 'To import and launch individual parsers to insert into database for Triage and Memory files'

import os
import sys
import getopt
import collections
import argparse
import pickle
from pprint import pformat as pf

import IO_databaseOperations as db
import PROCESS_postTriage as postTriage
import PROCESS_submitDatabase as submitDatabase
import OUTPUT_summary as summary 
import OUTPUT_timeline as timeline 
from config import CONFIG

#For log file
import logging
logger = logging.getLogger('root')

def main():	
	parser = argparse.ArgumentParser(description="Process triage, network or memory dump evidence file(s), sorted by projects for correlation")
	parser.add_argument('-d', dest='directory', type=str, help="Directory containing evidence files")
	parser.add_argument('-p', dest='projectname', type=str, required=True, help="Codename of the project that the evidence is part of")
	parser.add_argument('-s', dest='split', type=int, required=False, help="Split timeline to a maximum of X rows per file.  Default 100k.")
	args = parser.parse_args()

	if args.split:
		split = args.split
	else:
		split = CONFIG['TIMELINE']['DEFAULT_SPLIT']

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

	logger.info("submit.py STARTED on %s with project %s" % (searchDirectory, args.projectname))
	
	#Initialize database
	DATABASE = CONFIG['DATABASE']
	dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
	logger.debug("dbhandle is " + str(dbhandle))

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
				logger.info("insertProjectValue is %s" % pf(insertProjectValue))
				db.databaseExistInsert(dbhandle,Schema,Table,insertProjectValue)
		logger.info("postTriage.postTriage on %s" % searchDirectory)
		postTriage.postTriage(searchDirectory, projectName)
		logger.info("submitDatabase.dbprocess on %s" % searchDirectory)
		submitDatabase.dbprocess(dbhandle, searchDirectory)
		logger.info("summary.outputSummary on %s" % searchDirectory)
		summary.outputSummary(searchDirectory, projectName, projResultsDir)
		logger.info("timeline.outputTimeline on %s" % searchDirectory)
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
							logger.info("insertProjectValue is %s" % pf(insertProjectValue))
							db.databaseExistInsert(dbhandle,Schema,Table,insertProjectValue)

							fulldirectory = os.path.join(root, directory)

							logger.info("postTriage.postTriage on %s" % fulldirectory)
							postTriage.postTriage(fulldirectory, projectName)
							logger.info("submitDatabase.dbprocess on %s" % fulldirectory)
							submitDatabase.dbprocess(dbhandle, fulldirectory)
							logger.info("summary.outputSummary on %s" % fulldirectory)
							summary.outputSummary(fulldirectory, projectName, projResultsDir)
							logger.info("timeline.outputTimeline on %s" % fulldirectory)
							timeline.outputTimeline(fulldirectory,projectName,projResultsDir,split)

	
if __name__ == '__main__':
	main()

