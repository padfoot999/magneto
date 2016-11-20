#!/usr/bin/python -tt
__description__ = 'Parse saved text result from Triage System Variables.txt'

import collections
import IO_databaseOperations as db
import IO_fileProcessor as fp
from config import CONFIG

import logging
logger = logging.getLogger('root')

import argparse

#NAME:parseAndPopulate
#INPUT:psycopg2-db-handle databaseConnectionHandle, string filename
#OUTPUT: NONE
#DESCRIPTION: Parse and insert values into database path.triage_sysvariables_main
def parseAndPopulate(databaseConnectionHandle, filename):

	logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
	logger.debug("filename is " + filename + "\n")

	fileBuffer = fp.dequeFile(filename)

	path = filename.split('\\')

	#To prevent duplicate entries
	tempPathList = []

	insertValue = collections.OrderedDict.fromkeys(['imagename', 'allusersprofile',
													'appdata','commonprogramfiles','commonprogramfilesx86','commonprogramw6432',
													'computername', 'comspec', 'fp_no_host_check',
													'homedrive','homepath','localappdata','logonserver','number_of_processors',
													'os','pathext','processor_architecture','processor_architew6432',
													'processor_identifier','processor_level','processor_revision','programdata','programfiles',
													'programfilesx86','programw6432','prompt','psmodulepath','public',
													'systemdrive','systemroot','temp','tmp','userdomain',
													'userdomain_roamingprofile','username','userprofile','windir',
													'__compat_layer'])


	insertValue['imagename'] = path[-2]
	#To prevent duplicate entries
	insertPathValueList = []

	while fileBuffer:

		temp = fileBuffer.popleft()

		logger.debug("\ntemp is " + str(temp))

		#List used to separate line delimited by "="
		tempString = " ".join(temp)
		tempValue = tempString.split('=')
		logger.debug("tempValue is " + str(tempValue))
		logger.debug("tempValue[0] is " + str(tempValue[0]))
		logger.debug("tempValue[1] is " + tempValue[1])

		#Inserting into ordered dictionary
		skip = False

		if tempValue[0].lower() == "commonprogramfiles(x86)":
			try:
				insertValue['commonprogramfilesx86'] = tempValue[1]
				logger.debug("insertValue[commonprogramfilesx86] is " + tempValue[1])
			except (ValueError,IndexError) as e:
				logger.error("SystemVariables: Problem inserting " + tempValue[0].lower() + " due to " + str(e))
				pass
		elif tempValue[0].lower() == "programfiles(x86)":
			try:
				insertValue['programfilesx86'] = tempValue[1]
				logger.debug("insertValue[programfilesx86] is " + tempValue[1])
			except (ValueError,IndexError) as e:
				logger.error("SystemVariables: Problem inserting " + tempValue[0].lower() + " due to " + str(e))
				pass
		elif tempValue[0].lower() not in insertValue.keys():
			if tempValue[0].lower() == "path":
				try:

					#used to separate line delimited by ";"
					pathList = tempValue[1].split(';')

					for pathItem in pathList:
						if pathItem not in tempPathList:
							tempPathList.append(pathItem)                        
							insertPathValue = collections.OrderedDict.fromkeys(['imagename', 'path'])
							insertPathValue['imagename'] = insertValue['imagename']
							insertPathValue['path'] = pathItem  
							logger.debug("insertPathValue[path] is " + str(pathItem))
							insertPathValueList.append(insertPathValue)
							logger.debug("insertPathValueList is " + str(insertPathValueList))
				except (ValueError,IndexError) as e:
					logger.error("SystemVariables: Problem inserting " + tempValue[0].lower() + " due to " + str(e))
					pass
			else:
				#ZFZFTODO: amend the code to add these variables on the fly to the database
				logger.info(tempValue[0].lower() + " is not a common system variable and is not saved.")

		elif tempValue[0].lower() == "processor_level":
			if not tempValue[1].isdigit():
				logger.error("System Variables : Problem processing the following line as processor_level field is NOT numeric :")
				skip = True
				print str(temp)	
		else:
			try:
				insertValue[tempValue[0].lower()] = tempValue[1]
				logger.debug("insertValue[tempValue[0].lower()] is " + str(tempValue[1]))
			except (ValueError,IndexError) as e:
				logger.error("SystemVariables: Problem inserting " + tempValue[0].lower() + " due to " + str(e))
				pass

	if skip == False:
		Schema = "environment_variables"
		Table = "triage_sysvariables"

		logger.debug("insertValue is " + str(insertValue) + "\n")
		db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)

		logger.debug("Processing triage_sysvariables_path")
		Table = "triage_sysvariables_path"

		#Q: can't we use this to auto insert for all triage table?
		#A: we can't do auto populate for table with non-string entries
		for x in insertPathValueList:
			db.databaseInsert(databaseConnectionHandle,Schema,Table,x)


#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

	DATABASE = CONFIG['DATABASE']
	dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
	logger.debug("dbhandle is " + str(dbhandle) + "\n")

	#This filename is tied to the script and should change ONLY IF the volatility processing script change.
	filename = "System Variables.txt"

	parseAndPopulate(dbhandle,filename)

if __name__ == '__main__':
	main()
