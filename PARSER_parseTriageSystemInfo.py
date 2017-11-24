#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
__description__ = 'Parse saved text result from Triage System Info.txt'

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
#DESCRIPTION: Parse and insert values into database system.triage_sysinfo_*
def parseAndPopulate(databaseConnectionHandle, filename):
	logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
	logger.debug("filename is " + filename + "\n")
	cur = databaseConnectionHandle.cursor()
	query = "savepoint SP1;"
	cur.execute(query)
	fileBuffer = fp.dequeFile(filename)

	path = os.path.split(os.path.split(filename)[0])

	#=========================================================================================#
	#Populating table triage_sysinfo_product

	#initialize key values according to database column
	#Should pull from database instead of hardcoding...
	insertSystemInfo = collections.OrderedDict.fromkeys(['imagename',
														 'uptime',
														 'kernelversion',
														 'producttype',
														 'productversion',
														 'servicepack',
														 'kernelbuildnumber',
														 'registeredorganization',
														 'registeredowner',
														 'ieversion',
														 'systemroot',
														 'processors',
														 'processorspeed',
														 'processortype',
														 'physicalmemory',
														 'videodriver',
														 'hostname',
														 'osname',
														 'osversion',
														 'osmanufacturer',
														 'osconfiguration',
														 'osbuildtype',
														 'productid',
														 'originalinstalldate',
														 'systemboottime',
														 'systemmanufacturer',
														 'systemmodel',
														 'systemtype',
														 'biosversion',
														 'procinstalled',
														 'windowsdirectory',
														 'systemdirectory',
														 'bootdevice',
														 'systemlocale',
														 'inputlocale',
														 'timezone',
														 'totalphysicalmemory',
														 'availablephysicalmemory',
														 'virtualmemory_maxsize',
														 'virtualmemory_available',
														 'virtualmemory_inuse',
														 'pagefilelocation',
														 'domain',
														 'logonserver',
														 'vmmonitormodeextensions',
														 'virtualizationenabledinfirmware',
														 'secondleveladdresstranslation',
														 'dataexecutionpreventionavailable'])

	insertSystemInfo['imagename'] = path[1]
	try:
		try:
			while fileBuffer[0][0:3] != ['System', 'information', 'for']:
				fileBuffer.popleft()
			fileBuffer.popleft()

		except (ValueError,IndexError) as e:
			logger.error("ERROR SystemProblem finding 'System', 'information', 'for' headers due to " + str(e))
			pass
		try:
			#Process entries between lines containing the string "System information for" and "Volume Type Format  Label Size Free Free"
			while fileBuffer[0] != ['Volume', 'Type', 'Format', 'Label', 'Size', 'Free', 'Free']:
				temp = fileBuffer.popleft()
				columnValuePair = fp.splitDelimitedLine(temp,":")
				logger.debug("columnValuePair is " + str(columnValuePair) + "\n")
				#Combine all column value into 1 database insertion statement and insert.
				for key,value in columnValuePair.iteritems():
					insertSystemInfo[key] = value

		except (ValueError,IndexError) as e:
			logger.error("ERROR SystemProblem finding 'Volume', 'Type', 'Format' headers due to " + str(e))
			pass

		logger.debug("insertSystemInfo is " + str(insertSystemInfo) + "\n")

		#Insertion is delayed until all multi line entries are populated
		#db.databaseInsert(databaseConnectionHandle,Schema,Table,insertSystemInfo)

		#=========================================================================================#
		#Populating table triage_sysinfo_partitions
		#Multiple Entry Item, hence a new table triage_sysinfo_partitions
		Schema = "system"
		Table = "triage_sysinfo_partitions"

		#initialize key values according to database column
		insertPartitionValue = collections.OrderedDict.fromkeys(['imagename','volumetype','format','label','size','free','freepercent'])

		try:
			#remove the title
			fileBuffer.popleft()
		except (ValueError,IndexError) as e:
			logger.error("Processes: Problem popping due to " + str(e))
			pass

		try:
			#Process entries between the lines containing "Volume Type Format  Label Size Free Free" and "Applications:"
			while fileBuffer[0] != ['Applications:']:
				temp = fileBuffer.popleft()

				try:
					volumetype = " ".join(temp[0:2])
				except (ValueError,IndexError) as e:
					volumetype = None
					logger.error("SystemProblem assigning volumetype due to " + str(e))
					pass

				if not "CD-ROM" in volumetype:
					try:
						format = temp[2]
					except (ValueError,IndexError) as e:
						format = None
						logger.error("SystemProblem assigning format due to " + str(e))
						pass
					try:
						label = temp[3]
					except (ValueError,IndexError) as e:
						label = None
						logger.error("SystemProblem assigning label due to " + str(e))
						logger.error("line is " + str(temp))
						pass

					try:
						size = " ".join(temp[4:6])
					except (ValueError,IndexError) as e:
						size = None
						logger.error("SystemProblem assigning size due to " + str(e))
						pass

					try:
						free = " ".join(temp[6:8])
					except (ValueError,IndexError) as e:
						free = None
						logger.error("SystemProblem assigning free due to " + str(e))
						pass

				freepercent = temp[-1]

				insertPartitionValue['imagename'] = path[1]
				insertPartitionValue['volumetype'] = volumetype
				insertPartitionValue['format'] = format
				insertPartitionValue['label'] = label
				insertPartitionValue['size'] = size
				insertPartitionValue['free'] = free
				insertPartitionValue['freepercent'] = freepercent

				logger.debug("insertPartitionValue is " + str(insertPartitionValue) + "\n")
				db.databaseInsert(databaseConnectionHandle,Schema,Table,insertPartitionValue)

				#Reset values to be inserted
				insertPartitionValue = collections.OrderedDict.fromkeys(['imagename','volumetype','format','label','size','free','freepercent'])
				format = None
				label = None
				size = None
				free = None

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem finding Applications header due to " + str(e))
			pass
		#=========================================================================================#
		#Populating table triage_sysinfo_applications
		#Multiple Entry Item, hence a new table triage_sysinfo_applications
		Schema = "system"
		Table = "triage_sysinfo_applications"

		#initialize key values according to database column
		insertApplicationValue = collections.OrderedDict.fromkeys(['imagename','appname'])
		insertApplicationValue['imagename'] = path[1]
		
		try:
			#remove the "Application:" title
			fileBuffer.popleft()
		except (ValueError,IndexError) as e:
			logger.error("Processes: Problem popping due to " + str(e))
			pass

		try:

			#Process entries between the lines "Applications:" and "Host Name: "
			while fileBuffer[0][0:2] != ['Host', 'Name:']:
				temp = fileBuffer.popleft()

				appname = " ".join(temp)
				appname = fp.translateLine(appname)
				
				#There may be repeated entries of application with the same name.
				#Just let it fail elegantly for now
				insertApplicationValue['appname'] = appname
				logger.debug("insertApplicationValue is " + str(insertApplicationValue) + "\n")
				if appname is not None:
					db.databaseInsert(databaseConnectionHandle,Schema,Table,insertApplicationValue)

				#reset values to be inserted
				insertApplicationValue = collections.OrderedDict.fromkeys(['imagename','appname'])
				insertApplicationValue['imagename'] = path[1]

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem finding 'Host', 'Name:' headers due to " + str(e))
			pass

		db.databaseInsert(databaseConnectionHandle,Schema,Table,insertApplicationValue)

		#=========================================================================================#
		#Continue populating table triage_sysinfo from "Host Name: " to "System Type: "

		#Process entries before the line containing 'Processor(s):'
		try:
			while fileBuffer[0][0] != 'Processor(s):':
				temp = fileBuffer.popleft()
				columnValuePair = fp.splitDelimitedLine(temp,":")
				logger.debug("Start columnValuePair is " + str(columnValuePair) + "\n")

				#Combine all column value into 1 database insertion statement and insert.
				for key,value in columnValuePair.iteritems():
					if key == 'registeredorganization' or key == 'registeredowner':
						logger.debug("Skipping insertion for ... " + key)
					else:
						insertSystemInfo[key] = value

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem finding 'Processor(s):' headers due to " + str(e))
			pass

		logger.debug("insertSystemInfo is " + str(insertSystemInfo) + "\n")

		#=========================================================================================#
		#Populating table triage_sysinfo_processors
		#Multiple Entry Item, hence a new table triage_sysinfo_processors
		Schema = "system"
		Table = "triage_sysinfo_processors"

		#initialize key values according to database column
		insertProcdesValue = collections.OrderedDict.fromkeys(['imagename',
															   'procid',
															   'description'])

		insertProcdesValue['imagename'] = path[1]

		#Process entries before the line containing 'BIOS', 'Version:'
		try:
			while fileBuffer[0][0:2] != ['BIOS', 'Version:']:
				if fileBuffer[0][0] == 'Processor(s):':
					#Note that this is updating insertSystemInfo and NOT insertProcdesValue
					insertSystemInfo['procinstalled'] = fileBuffer.popleft()[1]
				else:
					templist = " ".join(fileBuffer.popleft()).split(":", 1)
					procid = templist[0]

					#remove square brackets
					procid = "".join(procid[1:-1])
					description = templist[1]

					insertProcdesValue['procid'] = procid
					insertProcdesValue['description'] = description
					logger.debug("insertProcdesValue is " + str(insertProcdesValue) + "\n")
					db.databaseInsert(databaseConnectionHandle,Schema,Table,insertProcdesValue)

					#Reset values to be inserted
					insertProcdesValue = collections.OrderedDict.fromkeys(['imagename','procid','description'])

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem finding 'BIOS', 'Version:' headers due to " + str(e))
			pass
		#=========================================================================================#
		#Continue populating table triage_sysinfo from "BIOS Version:" to "Time Zone:"

		temp = fileBuffer.popleft()
		columnValuePair = fp.splitDelimitedLine(temp,":")
		logger.debug("columnValuePair is " + str(columnValuePair) + "\n")

		#Combine all column value into 1 database insertion statement and insert.
		for key,value in columnValuePair.iteritems():
			insertSystemInfo[key] = value

		logger.debug("insertSystemInfo is " + str(insertSystemInfo) + "\n")

		try:
			while fileBuffer[0][0:3] != ['Total', 'Physical', 'Memory:']:
				temp = fileBuffer.popleft()
				columnValuePair = fp.splitDelimitedLine(temp,":")
				logger.debug("columnValuePair is " + str(columnValuePair) + "\n")

				#Combine all column value into 1 database insertion statement and insert.
				for key,value in columnValuePair.iteritems():
					insertSystemInfo[key] = value

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem finding 'Total', 'Physical', 'Memory:' headers due to " + str(e))
			pass

		logger.debug("insertSystemInfo is " + str(insertSystemInfo) + "\n")

	#=========================================================================================#

		# Memory part needs additional processing to remove the comma in the MB e.g 2,048MB to 2048MB

		try:
			while fileBuffer[0][0:3] != ['Page', 'File', 'Location(s):']:
				if fileBuffer[0][0:2] == ['Virtual', 'Memory:']:

					#joining every 2 elements in the list with a space
					temp = fileBuffer.popleft()
					temp = " ".join(temp).split(":", 1)

					#joining every 2 element in the list with an underscore, removing spaces between names
					temp = "".join(("_".join(temp[0:2])).split(" "))
					#split the string as delimited by ":"
					temp = temp.split(":")
					temp[0] = temp[0].lower()
					temp[1] = temp[1].lower()

					#Removing comma from memory size. e.g 2,928mb becomes 2928mb
					temp[1] = temp[1].replace(",", "")

					insertSystemInfo[temp[0]] = temp[1]

				else:
					temp = fileBuffer.popleft()
					columnValuePair = fp.splitDelimitedLine(temp,":")
					logger.debug("columnValuePair is " + str(columnValuePair) + "\n")

					#Combine all column value into 1 database insertion statement and insert.
					for key,value in columnValuePair.iteritems():
						#Cleaning up memory size representations
						if key == 'totalphysicalmemory':
							#Removing comma from memory size. e.g 2,928mb becomes 2928mb
							value = value.replace(",","")
							#Removing space from memory size. e.g 2928 mb becomes 2928mb
							value = value.replace(" ","")
						if key == 'availablephysicalmemory':
							#Removing comma from memory size. e.g 2,928mb becomes 2928mb
							value = value.replace(",","")
							#Removing space from memory size. e.g 2928 mb becomes 2928mb
							value = value.replace(" ","")
						# insertSystemInfo[key] = value #20171020 commented out catch-all

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem finding 'Page', 'File', 'Location(s):' headers due to " + str(e))
			pass

		try:
			# current code assumes there is only 1 page file per system...
			while fileBuffer[0][0] != 'Domain:': #in the event there are more than one page file locations
				if fileBuffer[0][0:3] == ['Page', 'File', 'Location(s):']:
					insertSystemInfo['pagefilelocation'] = " ".join(fileBuffer.popleft()).split(":", 1)[-1]
				else:
					# TODO: rayfoo 20171102 need to do proper revamp of database structure for multiple pagefile scenarios
					insertSystemInfo['pagefilelocation'] = "%s; %s" % (
						insertSystemInfo['pagefilelocation'],
						" ".join(fileBuffer.popleft()).strip())
		except (ValueError,IndexError) as e:
			logger.error("SystemProblem finding 'Domain:' headers due to " + str(e))
			pass

			logger.debug("insertSystemInfo is " + str(insertSystemInfo) + "\n")

		try:
			while fileBuffer[0][0] != 'Hotfix(s):':
				temp = fileBuffer.popleft()
				columnValuePair = fp.splitDelimitedLine(temp,":")
				logger.debug("columnValuePair is " + str(columnValuePair) + "\n")

				#Combine all column value into 1 database insertion statement and insert.
				for key,value in columnValuePair.iteritems():
					insertSystemInfo[key] = value

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem finding 'Hotfix(s)' headers due to " + str(e))
			pass

		logger.debug("insertSystemInfo is " + str(insertSystemInfo) + "\n")


		#=========================================================================================#
		#Populating table triage_sysinfo_hotfix

		Schema = "system"
		Table = "triage_sysinfo_hotfix"

		#initialize key values according to database column
		insertHotfixValue = collections.OrderedDict.fromkeys(['imagename','totalnum','hotfixid','description'])
		insertHotfixValue['imagename'] = path[1]

		try:
			while fileBuffer[0][0:2] != ['Network', 'Card(s):']:
				if fileBuffer[0][0] == 'Hotfix(s):':
					temp = fileBuffer.popleft()

					try:
						hotfixtotalnum = temp[1]
					except (ValueError,IndexError) as e:
						hotfixtotalnum = ""
						logger.error("SystemProblem assigning hotfixtotalnum due to " + str(e))
						pass
					insertHotfixValue['totalnum'] = int(hotfixtotalnum)

				else:
					temp = fileBuffer.popleft()
					temp = "".join(temp).split(":", 1)
					
					try:
						tempstring = temp[0]
						if tempstring == "[246]":
							logger.info("Hotfix exceeds 255 entries! Please take note!")
							hotfixid = ""
							description = ""
						else:
							hotfixid =''.join(tempstring[1:-1])
							description = temp[1]
					except (ValueError,IndexError) as e:
						hotfixid = ""
						description = ""
						logger.error("SystemProblem assigning hotfixid and description due to " + str(e))
						pass

					insertHotfixValue['hotfixid'] = hotfixid
					insertHotfixValue['description'] = description

					logger.debug("insertHotfixValue is " + str(insertHotfixValue) + "\n")
					db.databaseInsert(databaseConnectionHandle,Schema,Table,insertHotfixValue)

					#reset values to be inserted
					insertHotfixValue = collections.OrderedDict.fromkeys(['imagename','totalnum','hotfixid','description'])
					insertHotfixValue['imagename'] = path[1]
					insertHotfixValue['totalnum'] = int(hotfixtotalnum)

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem populating triage_sysinfo_hotfix due to " + str(e))
			pass
		#=========================================================================================#
		#Populating table triage_sysinfo_nic and triage_sysinfo_nicip

		Schema = "system"
		Table = "triage_sysinfo_nic"

		#initialize key values according to database column
		insertNICValue = collections.OrderedDict.fromkeys(['imagename','nicid','nictype','connectionname','dhcpenabled','totalinstalled','status','dhcpserver'])
		insertNICValue['imagename'] = path[1]

		try:
			while fileBuffer[0][0:2] != ['Hyper-V', 'Requirements:']:
				if fileBuffer[0][0:2] == ['Network', 'Card(s):']:
					try:
						nictotalinstalled = fileBuffer.popleft()[2]
					except (ValueError,IndexError) as e:
						nictotalinstalled = ""
						logger.error("SystemProblem assigning nictotalinstalled due to " + str(e))
						pass
					logger.info(nictotalinstalled)
					insertNICValue['totalinstalled'] = int(nictotalinstalled)
					logger.debug("nictotalinstalled is " + str(nictotalinstalled) + "\n")

				else:
					#Line is [nicid]: <nictype> and onwards
					try:
						temp = fileBuffer.popleft()
						temp = "".join(temp).split(":", 1)
						tempstring = temp[0]
						nicid =''.join(tempstring[1:-1])
					except (ValueError,IndexError) as e:
						nicid = ""
						logger.error("SystemProblem assigning nicid due to " + str(e))
						pass

					try:
						nictype = temp[1]
					except (ValueError,IndexError) as e:
						nictype = ""
						logger.error("SystemProblem assigning nictype due to " + str(e))
						pass

					insertNICValue['nicid'] = nicid
					insertNICValue['nictype'] = nictype
					logger.debug("\n\nnicid is " + nicid + "\n")
					logger.debug("nictype is " + nictype + "\n")

					if fileBuffer[0][0:2] == ['Connection', 'Name:']:
						try:
							temp = fileBuffer.popleft()
							temp = "".join(temp).split(":", 1)
							connectionname = temp[1]
						except (ValueError,IndexError) as e:
							connectionname = ""
							logger.error("SystemProblem assigning connectionname due to " + str(e))
							pass

						insertNICValue['connectionname'] = connectionname
						logger.debug("connectionname is " + connectionname + "\n")

					if fileBuffer[0][0:2] == ['DHCP', 'Enabled:']:
						try:
							temp = fileBuffer.popleft()
							dhcpenabled = temp[2]
						except (ValueError,IndexError) as e:
							dhcpenabled = ""
							logger.error("SystemProblem assigning dhcpenabled due to " + str(e))
							pass

						insertNICValue['dhcpenabled'] = dhcpenabled
						logger.debug("dhcpenabled is " + dhcpenabled + "\n")

					if fileBuffer[0][0:2] == ['DHCP', 'Server:']:
						try:
							temp = fileBuffer.popleft()
							dhcpserver = temp[2]
						except (ValueError,IndexError) as e:
							dhcpserver = ""
							logger.error("SystemProblem assigning dhcpserver due to " + str(e))
							pass

						insertNICValue['dhcpserver'] = dhcpserver
						logger.debug("dhcpserver is " + dhcpserver + "\n")

					if fileBuffer[0][0:2] == ['IP', 'address(es)'] or fileBuffer[0][0:2] == ['IP', 'Address']:
						#Populating table triage_sysinfo_nicip
						try:
							#Remove header line 'IP', 'address(es)'
							fileBuffer.popleft()
						except (ValueError,IndexError) as e:
							logger.error("SystemProblem moving file processing pointer for IP address(es) due to " + str(e))
							logger.error("Note that this may be a false positive due to reaching the EOF")
							pass

						#Assuming ip address can only be specified line by line
						try:
							existIpAddressField = len(fileBuffer[0])
						except (ValueError,IndexError) as e:
							logger.error("SystemError moving file processing pointer for IP address(es) due to " + str(e))
							logger.error("Note that this may be a false positive due to reaching the EOF")
							pass

						try:
							while len(fileBuffer[0]) == 2:
								Schema = "system"
								Table = "triage_sysinfo_nicip"

								insertNICIPValue = collections.OrderedDict.fromkeys(['imagename','ipid','ipadd','nicid'])
								insertNICIPValue['imagename'] = path[1]
								insertNICIPValue['nicid'] = nicid

								try:
									temp = "".join(fileBuffer.popleft()).split(":", 1)
									tempstring = temp[0]
									ipid =''.join(tempstring[1:-1])
								except (ValueError,IndexError) as e:
									ipid = ""
									logger.error("SystemProblem assigning ipid due to " + str(e))
									pass

								insertNICIPValue['ipid'] = int(ipid)
								logger.debug("ipid is " + str(ipid) + "\n")

								try:
									ipadd = temp[1]
								except (ValueError,IndexError) as e:
									ipadd = ""
									logger.error("SystemProblem assigning ipadd due to " + str(e))
									pass

								insertNICIPValue['ipadd'] = ipadd
								logger.debug("ipadd is " + str(ipadd) + "\n")

								logger.debug("insertNICIPValue is " + str(insertNICIPValue) + "\n")
								db.databaseInsert(databaseConnectionHandle,Schema,Table,insertNICIPValue)
						except (ValueError,IndexError) as e:
							logger.error("SystemError moving file processing pointer for ipid and ipadd due to " + str(e))
							logger.error("Note that this may be a false positive due to reaching the EOF")
							pass

					#Resetting the table back to triage_sysinfo_nic
					Schema = "system"
					Table = "triage_sysinfo_nic"
					try:
						if fileBuffer[0][0:1] == ['Status:']:
							try:
								temp = fileBuffer.popleft()
								temp = "".join(temp).split(":", 1)
								status = temp[1]
							except (ValueError,IndexError) as e:
									status = ""
									logger.error("SystemProblem assigning status due to " + str(e))
									pass
							insertNICValue['status'] = status
							logger.debug("status is " + status + "\n")
					except (ValueError,IndexError) as e:
						logger.error("SystemError moving file processing pointer for status due to " + str(e))
						logger.error("Note that this may be a false positive due to reaching the EOF")
						pass

					logger.debug("insertNICValue is " + str(insertNICValue) + "\n")
					db.databaseInsert(databaseConnectionHandle,Schema,Table,insertNICValue)

					#reset values to be inserted
					insertNICValue = collections.OrderedDict.fromkeys(['imagename','nicid','nictype','connectionname','dhcpenabled','totalinstalled','status','dhcpserver'])
					insertNICValue['imagename'] = path[1]
					insertNICValue['totalinstalled'] = int(nictotalinstalled)

		except (ValueError,IndexError) as e:
			logger.error("SystemProblem populating triage_sysinfo_nicip due to " + str(e))
			pass
		#=========================================================================================#
		#Continue populating table triage_sysinfo from "Hyper-V Requirements:" to end of file

		Schema = "system"
		Table = "triage_sysinfo"

		#Since this is the last parameter
		while fileBuffer:
			try:
				#special case of double :
				if fileBuffer[0][0:2] == ['Hyper-V', 'Requirements:']:
					try:
						temp = fileBuffer.popleft()
						temp = " ".join(temp[2:]).split(":", 1)
						vmmonitormodeextensions = temp[1].strip()
					except (ValueError,IndexError) as e:
								vmmonitormodeextensions = ""
								logger.error("SystemProblem assigning vmmonitormodeextensions due to " + str(e))
								pass
					insertSystemInfo['vmmonitormodeextensions'] = vmmonitormodeextensions
				else:
					temp = fileBuffer.popleft()
					columnValuePair = fp.splitDelimitedLine(temp,":")
					logger.debug("columnValuePair is " + str(columnValuePair) + "\n")

						#Combine all column value into 1 database insertion statement and insert.
					for key,value in columnValuePair.iteritems():
						insertSystemInfo[key] = value
			except (ValueError,IndexError) as e:
				logger.error("SystemProblem populating triage_sysinfo due to " + str(e))
				pass

		#This variable is a composition of values from alot of segments!!!
		logger.debug("insertSystemInfo is " + str(insertSystemInfo) + "\n")
		db.databaseInsert(databaseConnectionHandle,Schema,Table,insertSystemInfo)
	except (ValueError,IndexError) as e:
		Schema = "system"
		Table = "triage_sysinfo"
		logger.debug("insertSystemInfo is " + str(insertSystemInfo) + "\n")
		db.databaseInsert(databaseConnectionHandle,Schema,Table,insertSystemInfo)

#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():
	DATABASE = CONFIG['DATABASE']
	dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
	logger.debug("dbhandle is " + str(dbhandle) + "\n")

	#This filename is tied to the script and should change ONLY IF the volatility processing script change.
	filename = "System Info.txt"



	parseAndPopulate(dbhandle,filename)




if __name__ == '__main__':
    main()
