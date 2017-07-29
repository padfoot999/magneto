#copy and paste file to results folder
#Go to second tab (i.e. USB)
#Find for specific csv and paste into excel spreadsheet (i.e. same as PARSER or submit)

#rename to Incidents folder

#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
__author__ = "ZF"
__description__ = 'To import and launch individual parsers to insert into database for Triage and Memory files'

import os
import sys
import getopt
import collections
import argparse
import pickle
import re

import pandas as pd
from openpyxl import Workbook, load_workbook
import csv
import datetime
import chardet
import subprocess
import numpy as np

import sys
reload(sys)
sys.setdefaultencoding('utf8')

from config import CONFIG
import IO_databaseOperations as db

#For log file
import logging
logger = logging.getLogger('root')


#NAME:process
#INPUT: database connection handle, directory to evidence files
#OUTPUT: NONE
#DESCRIPTION:
def outputSummary(directory, projectname, results):
	imgname = os.path.split(directory)[1]
	timestamp = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))
	workbook = load_workbook(filename= 'MAGNETO_Host_Analysis_Checklist_Results_template2.xlsx')
	writer = pd.ExcelWriter('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', engine='openpyxl')
	writer.book = workbook
	writer.sheets = dict((ws.title,ws) for ws in workbook.worksheets)
	writer.save()

	#For aggregating destination ip addresses within netstat file
	ipaddress_list = {}
	DATABASE = CONFIG['DATABASE']
	dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
	logger.info("dbhandle is " + str(dbhandle))
	cur = dbhandle.cursor()
	query = "SELECT DISTINCT imagename FROM project.project_image_mapping WHERE projectname = %s"
	logger.info("query is : " + str(query))
	cur.execute(query,(str(projectname),))
	resultImageTuples = cur.fetchall()

	headers = ['IP Address', 'Count']
	query = "SELECT DISTINCT part_conn.destination, full_conn.ipcount FROM network.triage_network_connections part_conn INNER JOIN ("
	query += "SELECT destination, COUNT(DISTINCT n.imagename) as ipcount FROM network.triage_network_connections n INNER JOIN project.project_image_mapping p ON n.imagename=p.imagename WHERE p.projectname = %s AND n.state='ESTABLISHED' GROUP BY n.destination) full_conn ON part_conn.destination=full_conn.destination WHERE imagename = %s"
	cur.execute(query,(str(projectname),str(imgname),))
	resultDestinationIP = cur.fetchall()
	imagenamelist = {'Image with IP': []}
	for i in resultDestinationIP:
		destinationIP = i[0]
		query = "SELECT DISTINCT n.imagename FROM network.triage_network_connections n INNER JOIN project.project_image_mapping p ON n.imagename = p.imagename WHERE p.projectname = %s AND n.destination = %s"
		cur.execute(query,(str(projectname),str(destinationIP),))
		ipImageName = cur.fetchall()
		imagenames = ""
		for i in ipImageName:
			imagenames += i[0] + ", "
		imagenamelist['Image with IP'].append(imagenames)
	logger.info(imagenamelist)
	ipCountTable = pd.DataFrame(resultDestinationIP, columns=headers)
	imagenamelist = pd.DataFrame(imagenamelist)
	ipCountTable = pd.concat([ipCountTable, imagenamelist], axis=1)
	ipCountTable.to_excel(writer, sheet_name="Network Connections", index=False)

	unprocessedlist = []
	jmpRowCount = 2
	recentRowCount = 2

	# traverse root directory, and list directories as dirs and files as files
	for root, dirs, files in os.walk(directory):
		# logger.info("root is " + root)
		# logger.info("dirs is " + str(dirs))
		# logger.info("files is " + str(files))
		for filename in files:
			#Queueing all triage output files for processing. Once processed, they are removed
			if str(os.path.join(root,filename)) not in unprocessedlist:
				unprocessedlist.append(os.path.join(root,filename))

	#For logon accounts that is output in results folder - specific to each custodian
	for root, dirs, files in os.walk(results):
		for filename in files:
			pathFile = str(os.path.join(root,filename))
			if "-Logon Accounts.csv" in pathFile and imgname in pathFile:
				unprocessedlist.append(os.path.join(root,filename))


	fileExecution = pd.DataFrame()
	fileOpening = pd.DataFrame()
	for rawFile in unprocessedlist:
		try: 
			if "USBParser.xlsx" in rawFile:
				usbResults = pd.read_excel(rawFile, sheetname=0)
				usbResults = clean(usbResults, list(usbResults))
				usbResults.to_excel(writer, sheet_name="USB", index=False)

			if "FileExecutionParser.xlsx" in rawFile:
				#fileExecutionResults = pd.read_excel(rawFile, header=None, parse_cols=15,sheetname=0, names=['Path','Last Modified','Last Update','Size','Exec Flag','Path_1','Launch Location_1','Last Execution_1','User_1','File Name_2','File Path_2','MRU List EX Order_2','User_2','Program Name_3','User_3'])
				fileExecutionResults = pd.read_excel(rawFile, header=0, sheetname=0)
				fileExecutionResults = clean(fileExecutionResults, list(fileExecutionResults))
				fileExecutionResults.to_excel(writer,sheet_name="File Execution",startcol=10,index=False,header=False,startrow=2,encoding='utf-8')

			if "RecentFileCache-Output.csv" in rawFile:
				recentFileCache = pd.DataFrame()
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				rawrecentfile = pd.read_csv(rawFile, encoding=charenc)
				rawrecentfile.to_excel(writer,sheet_name="File Execution",startcol=29,index=False,header=False,startrow=2)

			if "FileOpeningParser.xlsx" in rawFile:
				#fileOpeningResults = pd.read_excel(rawFile, header=None, sheetname=0, names=['File Name','MRU List EX Order','Extension','User','File Path_1','MRU List EX Order_1','Extension_1','Last Execution_1','User_1','File Name_2','File Path_2','MRU List EX Order_2','User_2','File Path_3','MRU List EX Order_3','Extension_3','User_3'])
				fileOpeningResults = pd.read_excel(rawFile, header=0, sheetname=0)
				#fileOpeningResults = fileOpeningResults.replace(r'\s+', np.nan, regex=True)
				fileOpeningResults = clean(fileOpeningResults, list(fileOpeningResults))
				fileOpeningResults.to_excel(writer,sheet_name="File or Folder Opening",startcol=15,index=False,header=False,startrow=2)

			if "Prefetch Info.csv" in rawFile:
				prefetch = pd.DataFrame()
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				rawprefetch = pd.read_csv(rawFile, encoding=charenc, skiprows=1,names=['Filename','Created Time','Modified Time','File Size','Process EXE','Process Path','Run Counter','Last Run Time','Missing Process'])

				rawprefetch['Last Run Time'] = pd.to_datetime(rawprefetch['Last Run Time'], dayfirst=True)
				prefetch['Source File'] = rawprefetch['Filename']
				prefetch['File Path'] = rawprefetch['Process Path']
				prefetch['File Name'] = rawprefetch['Process EXE']
				prefetch['Last Execution'] = rawprefetch['Last Run Time']

				prefetch = clean(prefetch, list(prefetch))
				prefetch = prefetch.drop_duplicates(subset="File Path")
				prefetch.to_excel(writer,sheet_name="File or Folder Opening",startcol=0,index=False,header=False,startrow=2)
				prefetch.to_excel(writer,sheet_name="File Execution",startcol=0,index=False,header=False,startrow=2)

			if "_AutomaticDestinations.tsv" in rawFile:
				currentautolist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="E:J",header=1)
				openLastRow = jmpRowCount
				
				jmplist = pd.DataFrame()
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				rawjmplist = pd.read_csv(rawFile, sep='\t', encoding=charenc, skiprows=1,names=['SourceFile','SourceCreated','SourceModified','SourceAccessed','AppId','AppIdDescription','DestListVersion','LastUsedEntryNumber','EntryNumber','CreationTime','LastModified','Hostname','MacAddress','Path','PinStatus','FileBirthDroid','FileDroid','VolumeBirthDroid','VolumeDroid','TargetCreated','TargetModified','TargetAccessed','FileSize','RelativePath','WorkingDirectory','FileAttributes','HeaderFlags','DriveType','DriveSerialNumber','DriveLabel','LocalPath','CommonPath','TargetIDAbsolutePath','TargetMFTEntryNumber','TargetMFTSequenceNumber','MachineID','MachineMACAddress','TrackerCreatedOn','ExtraBlocksPresent','Arguments','Notes','Robocopy File Name'])
				
				if not rawjmplist.empty:
					jmpRowCount += len(rawjmplist.index)
					jmplist['Source File'] = rawjmplist['SourceFile']
					jmplist['File Path'] = rawjmplist['Path']
					jmplist['File Name'] = rawjmplist['AppIdDescription']
					jmplist['User'] = os.path.split(os.path.dirname(rawFile))[1]
					jmplist['Last Execution'] = rawjmplist['LastModified']
					jmplist['Source'] = "Automatic"

					jmplist = clean(jmplist, list(jmplist))
					jmplist.to_excel(writer,sheet_name="File or Folder Opening",startcol=4,index=False,header=False,startrow=openLastRow)
					jmplist.to_excel(writer,sheet_name="File Execution",startcol=4,index=False,header=False,startrow=openLastRow)

			if "_CustomDestinations.tsv" in rawFile:
				currentcustomlist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="E:J",header=1)
				openLastRow = jmpRowCount

				jmplist = pd.DataFrame()
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				rawjmplist = pd.read_csv(rawFile, sep='\t', encoding=charenc, skiprows=1,names=['SourceFile','SourceCreated','SourceModified','SourceAccessed','AppId','AppIdDescription','EntryName','TargetCreated','TargetModified','TargetAccessed','FileSize','RelativePath','WorkingDirectory','FileAttributes','HeaderFlags','DriveType','DriveSerialNumber','DriveLabel','LocalPath','CommonPath','TargetIDAbsolutePath','TargetMFTEntryNumber','TargetMFTSequenceNumber','MachineID','MachineMACAddress','TrackerCreatedOn','ExtraBlocksPresent','Arguments','Robocopy File Name'])

				if not rawjmplist.empty:
					jmpRowCount += len(rawjmplist.index)
					jmplist['Source File'] = rawjmplist['SourceFile']
					jmplist['File Path'] = rawjmplist['LocalPath']
					jmplist['File Name'] = rawjmplist['AppIdDescription']
					jmplist['User'] = os.path.split(os.path.dirname(rawFile))[1]
					jmplist['Last Execution'] = rawjmplist['SourceModified']
					jmplist['Source'] = "Custom"

					jmplist = clean(jmplist, list(jmplist))
					jmplist.to_excel(writer,sheet_name="File or Folder Opening",startcol=4,index=False,header=False,startrow=openLastRow)
					jmplist.to_excel(writer,sheet_name="File Execution",startcol=4,index=False,header=False,startrow=openLastRow)

			pattern = re.compile(r'Recent LNKs\\[^\\]*\\[^\\]*\.csv$')
			if pattern.search(rawFile):
				currentrecent = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="K:O",header=1)
				openLastRow = recentRowCount

				logger.info(rawFile)
				recentlnk = pd.DataFrame()
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				try:
					rawrecentlnk = pd.read_csv(rawFile, encoding=charenc, header=0)
					recentRowCount += len(rawrecentlnk.index)
					recentlnk['File Path'] = rawrecentlnk['Local Path']
					recentlnk['File Path'].fillna(rawrecentlnk['Common Path'], inplace=True)
					usersearch = re.search(r'Recent LNKs\\(.*)\\.*\.csv', rawFile, re.IGNORECASE)
					if usersearch:
						recentlnk['User'] = usersearch.group(1)
					recentlnk['Last Accessed (UTC)'] = rawrecentlnk['Last Accessed (UTC)']
					recentlnk['Date Created (UTC)'] = rawrecentlnk['Date Created (UTC)']
					recentlnk['Last Modified (UTC)'] = rawrecentlnk['Last Modified (UTC)']
					recentlnk = clean(recentlnk, list(recentlnk))
					recentlnk.to_excel(writer,sheet_name="File or Folder Opening",startcol=10,index=False,header=False,startrow=openLastRow)
				except:
					logger.info(rawFile + " is empty")

			if rawFile.endswith("AutoRun Info.csv"):
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				autorun = pd.read_csv(rawFile, encoding=charenc, header=0, index_col=False)
				autorun.to_excel(writer,sheet_name="Autoruns_locations",index=False)

			if "wmi-Software.csv" in rawFile:
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				software = pd.read_csv(rawFile, encoding=charenc, skiprows=2,names=['Node','Description','IdentifyingNumber','InstallDate','InstallLocation','InstallState','Name','PackageCache','SKUNumber','Vendor','Version'])
				software.to_excel(writer, sheet_name="Installed_software", index=False)

			if "wmi-Service.csv" in rawFile:
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				service = pd.read_csv(rawFile, encoding=charenc, skiprows=2,names=['Node','DesktopInteract','ErrorControl','Name','PathName','ServiceType','StartMode'])
				service.to_excel(writer, sheet_name="New_services_installed", index=False)

			if "-Logon Accounts.csv" in rawFile:
				rawdata = open(rawFile, "r").read()
				result = chardet.detect(rawdata)
				charenc = result['encoding']
				logs = pd.read_csv(rawFile, encoding=charenc, header=0)
				logs.to_excel(writer, sheet_name="Logged_on_accounts", index=False)

			# if "Browser History.csv" in rawFile:
			# 	rawdata = open(rawFile, "r").read()
			# 	result = chardet.detect(rawdata)
			# 	charenc = result['encoding']
			# 	browserHistory = pd.read_csv(rawFile, encoding=charenc, header=0)
			# 	browserHistory.to_excel(writer, sheet_name="Browser", index=False)
		except Exception as e:
			logger.error("[+] Failed to proccess: " + rawFile)
	writer.save()

def clean(df, columns):
	for col in df.select_dtypes([np.object]).columns[1:]:
		df[col] = df[col].str.replace('[\000-\010]|[\013-\014]|[\016-\037]', '')
	return df

def replace_first_null(df, col_name):
	"""
	Replace the first null value in DataFrame df.`col_name`
	with `value`.
	"""
	idx = list(df.index)
	last_valid = df[col_name].last_valid_index()
	last_valid_row_number = idx.index(last_valid)
	return last_valid_row_number + 1

def main():
	parser = argparse.ArgumentParser(description="Process triage, network or memory dump evidence file(s), sorted by projects for correlation")
	parser.add_argument('-d', dest='directory', required=True, type=str, help="Directory containing evidence files")
	parser.add_argument('-r', dest='results', required=True, type=str, help="Directory containing results that was output by Post Triage Python Script")
	parser.add_argument('-p', dest='projectname', type=str, required=True, help="Codename of the project that the evidence is part of")
	args = parser.parse_args()

	searchDirectory = args.directory
	projectname = args.projectname
	imagelist=[]

	if "Incident" in searchDirectory:
		pathParts = searchDirectory.split('\\')
		for part in pathParts:
			if "Incident" in part:
				imagelist.append(part)
				outputSummary(searchDirectory,projectname,args.results)

	else:
		for root, dirs, files in os.walk(searchDirectory):
		#searchDirectory cannot end with a slash!
			for directory in dirs:
				if "Incident" in directory:
						if directory not in imagelist:
							imagelist.append(directory)
							outputSummary(str(os.path.join(root,directory)),projectname,args.results)

if __name__ == '__main__':
	main()
