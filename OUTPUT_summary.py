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
import IO_browserOperations as browser
import sys
reload(sys)
sys.setdefaultencoding('utf8')

from config import CONFIG

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

	unprocessedlist = []
	browserDict = {}
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
				if "Browser" in str(os.path.join(root,filename)):
					rawFile = str(os.path.join(root,filename))
					user = rawFile.split("Browser", 1)[1]
					user = user.split("\\", 2)[1]
					if user not in browserDict:
						browserDict[user] = []
					browserDict[user].append(rawFile)	

	#For logon accounts that is output in results folder - specific to each custodian
	for root, dirs, files in os.walk(results):
		for filename in files:
			pathFile = str(os.path.join(root,filename))
			if "-Logon Accounts.csv" in pathFile and imgname in pathFile:
				unprocessedlist.append(os.path.join(root,filename))


	fileExecution = pd.DataFrame()
	fileOpening = pd.DataFrame()
	browserData = pd.DataFrame()
	browserHistory = pd.DataFrame()
	for users in browserDict:
		files = browserDict[users]
		for file in files:
			if "Chrome" in file:
				if re.search("History$", file):
					browserData = browser.chrome_history(file)
					browserData.columns = ['URL', 'Title', 'Visit Time']
					browserData['User Profile']=users
					browserData['Web Browser']="Chrome"
					browserHistory = browserHistory.append(browserData, ignore_index=True)
			# if "Mozilla" in file:
			# if "IE" in file:

	for rawFile in unprocessedlist:
		if "Browser History.csv" in rawFile:
			print rawFile
			browserData = pd.read_csv(rawFile, header=0)
			browserData.drop('Visit Count', axis=1, inplace=True)
			browserData.drop('Visited From', axis=1, inplace=True)
			browserData.drop('Browser Profile', axis=1, inplace=True)
			browserData.drop('URL Length', axis=1, inplace=True)
			browserData.drop('Typed Count', axis=1, inplace=True)
			browserData = clean(browserData, list(browserData))
			browserHistory = browserHistory.append(browserData,ignore_index=True)
			
			#Webcache	

	# 		if "USER" in rawFile and ".dat" in rawFile:
	# 			currentWorkingDirectory = os.getcwd()
	# 			outputFile = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname + "\\" + os.path.splitext(os.path.basename(rawFile))[0] + "_Ripped_Report.txt"
	# 			outputdir = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname
	# 			if not os.path.exists(outputdir):
	# 				try:
	# 					os.makedirs(outputdir)
	# 				except:
	# 					logging.error("Unable to create results folder")
	# 					sys.exit()
	# 			os.chdir('.\Tools\RegRipper')
	# 			with open(outputFile, "a") as outfile:
	# 				subprocess.call(['perl','rip2.pl', '-r', rawFile, '-f', 'ntuser'], stdout=outfile)
	# 			os.chdir(currentWorkingDirectory)

	# 	if "USBParser.xlsx" in rawFile:
	# 		usbResults = pd.read_excel(rawFile, sheetname=0)
	# 		usbResults = clean(usbResults, list(usbResults))
	# 		usbResults.to_excel(writer, sheet_name="USB", index=False)

	# 	if "FileExecutionParser.xlsx" in rawFile:
	# 		#fileExecutionResults = pd.read_excel(rawFile, header=None, parse_cols=15,sheetname=0, names=['Path','Last Modified','Last Update','Size','Exec Flag','Path_1','Launch Location_1','Last Execution_1','User_1','File Name_2','File Path_2','MRU List EX Order_2','User_2','Program Name_3','User_3'])
	# 		fileExecutionResults = pd.read_excel(rawFile, header=0, sheetname=0)
	# 		#fileExecutionResults = fileExecutionResults.applymap(lambda x: x.encode('unicode_escape').decode('utf-8') if isinstance(x,str) else x)
	# 		#fileExecutionResults = fileExecutionResults.replace(r'\s+', np.nan, regex=True)
	# 		fileExecutionResults = clean(fileExecutionResults, list(fileExecutionResults))
	# 		fileExecutionResults.to_excel(writer,sheet_name="File Execution",startcol=10,index=False,header=False,startrow=2)

	# 	if "FileOpeningParser.xlsx" in rawFile:
	# 		#fileOpeningResults = pd.read_excel(rawFile, header=None, sheetname=0, names=['File Name','MRU List EX Order','Extension','User','File Path_1','MRU List EX Order_1','Extension_1','Last Execution_1','User_1','File Name_2','File Path_2','MRU List EX Order_2','User_2','File Path_3','MRU List EX Order_3','Extension_3','User_3'])
	# 		fileOpeningResults = pd.read_excel(rawFile, header=0, sheetname=0)
	# 		#fileOpeningResults = fileOpeningResults.replace(r'\s+', np.nan, regex=True)
	# 		fileOpeningResults = clean(fileOpeningResults, list(fileOpeningResults))
	# 		fileOpeningResults.to_excel(writer,sheet_name="File or Folder Opening",startcol=15,index=False,header=False,startrow=2)

	# 	if "Prefetch Info.csv" in rawFile:
	# 		prefetch = pd.DataFrame()
	# 		rawdata = open(rawFile, "r").read()
	# 		result = chardet.detect(rawdata)
	# 		charenc = result['encoding']
	# 		rawprefetch = pd.read_csv(rawFile, encoding=charenc, skiprows=1,names=['Filename','Created Time','Modified Time','File Size','Process EXE','Process Path','Run Counter','Last Run Time','Missing Process'])

	# 		rawprefetch['Last Run Time'] = pd.to_datetime(rawprefetch['Last Run Time'], dayfirst=True)
	# 		prefetch['Source File'] = rawprefetch['Filename']
	# 		prefetch['File Path'] = rawprefetch['Process Path']
	# 		prefetch['File Name'] = rawprefetch['Process EXE']
	# 		prefetch['Last Execution'] = rawprefetch['Last Run Time']

	# 		prefetch = clean(prefetch, list(prefetch))
	# 		prefetch = prefetch.drop_duplicates(subset="File Path")
	# 		prefetch.to_excel(writer,sheet_name="File or Folder Opening",startcol=0,index=False,header=False,startrow=2)
	# 		prefetch.to_excel(writer,sheet_name="File Execution",startcol=0,index=False,header=False,startrow=2)

	# 	if "_AutomaticDestinations.tsv" in rawFile:
	# 		currentautolist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="E:J",header=1)
	# 		openLastRow = jmpRowCount
			
	# 		jmplist = pd.DataFrame()
	# 		rawdata = open(rawFile, "r").read()
	# 		result = chardet.detect(rawdata)
	# 		charenc = result['encoding']
	# 		rawjmplist = pd.read_csv(rawFile, sep='\t', encoding=charenc, skiprows=1,names=['SourceFile','SourceCreated','SourceModified','SourceAccessed','AppId','AppIdDescription','DestListVersion','LastUsedEntryNumber','EntryNumber','CreationTime','LastModified','Hostname','MacAddress','Path','PinStatus','FileBirthDroid','FileDroid','VolumeBirthDroid','VolumeDroid','TargetCreated','TargetModified','TargetAccessed','FileSize','RelativePath','WorkingDirectory','FileAttributes','HeaderFlags','DriveType','DriveSerialNumber','DriveLabel','LocalPath','CommonPath','TargetIDAbsolutePath','TargetMFTEntryNumber','TargetMFTSequenceNumber','MachineID','MachineMACAddress','TrackerCreatedOn','ExtraBlocksPresent','Arguments','Notes','Robocopy File Name'])
			
	# 		if not rawjmplist.empty:
	# 			jmpRowCount += len(rawjmplist.index)
	# 			jmplist['Source File'] = rawjmplist['SourceFile']
	# 			jmplist['File Path'] = rawjmplist['Path']
	# 			jmplist['File Name'] = rawjmplist['AppIdDescription']
	# 			jmplist['User'] = os.path.split(os.path.dirname(rawFile))[1]
	# 			jmplist['Last Execution'] = rawjmplist['LastModified']
	# 			jmplist['Source'] = "Automatic"

	# 			jmplist = clean(jmplist, list(jmplist))
	# 			jmplist.to_excel(writer,sheet_name="File or Folder Opening",startcol=4,index=False,header=False,startrow=openLastRow)
	# 			jmplist.to_excel(writer,sheet_name="File Execution",startcol=4,index=False,header=False,startrow=openLastRow)

	# 	if "_CustomDestinations.tsv" in rawFile:
	# 		currentcustomlist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="E:J",header=1)
	# 		openLastRow = jmpRowCount

	# 		jmplist = pd.DataFrame()
	# 		rawdata = open(rawFile, "r").read()
	# 		result = chardet.detect(rawdata)
	# 		charenc = result['encoding']
	# 		rawjmplist = pd.read_csv(rawFile, sep='\t', encoding=charenc, skiprows=1,names=['SourceFile','SourceCreated','SourceModified','SourceAccessed','AppId','AppIdDescription','EntryName','TargetCreated','TargetModified','TargetAccessed','FileSize','RelativePath','WorkingDirectory','FileAttributes','HeaderFlags','DriveType','DriveSerialNumber','DriveLabel','LocalPath','CommonPath','TargetIDAbsolutePath','TargetMFTEntryNumber','TargetMFTSequenceNumber','MachineID','MachineMACAddress','TrackerCreatedOn','ExtraBlocksPresent','Arguments','Robocopy File Name'])

	# 		if not rawjmplist.empty:
	# 			jmpRowCount += len(rawjmplist.index)
	# 			jmplist['Source File'] = rawjmplist['SourceFile']
	# 			jmplist['File Path'] = rawjmplist['LocalPath']
	# 			jmplist['File Name'] = rawjmplist['AppIdDescription']
	# 			jmplist['User'] = os.path.split(os.path.dirname(rawFile))[1]
	# 			jmplist['Last Execution'] = rawjmplist['SourceModified']
	# 			jmplist['Source'] = "Custom"

	# 			jmplist = clean(jmplist, list(jmplist))
	# 			jmplist.to_excel(writer,sheet_name="File or Folder Opening",startcol=4,index=False,header=False,startrow=openLastRow)
	# 			jmplist.to_excel(writer,sheet_name="File Execution",startcol=4,index=False,header=False,startrow=openLastRow)

	# 	pattern = re.compile(r'Recent LNKs\\[^\\]*\\[^\\]*\.csv')
	# 	if pattern.search(rawFile):
	# 		currentrecent = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="K:O",header=1)
	# 		openLastRow = recentRowCount

	# 		logger.info(rawFile)
	# 		recentlnk = pd.DataFrame()
	# 		rawdata = open(rawFile, "r").read()
	# 		result = chardet.detect(rawdata)
	# 		charenc = result['encoding']
	# 		try:
	# 			rawrecentlnk = pd.read_csv(rawFile, encoding=charenc, header=0)
	# 			recentRowCount += len(rawrecentlnk.index)
	# 			recentlnk['File Path'] = rawrecentlnk['Local Path']
	# 			recentlnk['File Path'].fillna(rawrecentlnk['Common Path'], inplace=True)
	# 			usersearch = re.search(r'Recent LNKs\\(.*)\\.*\.csv', rawFile, re.IGNORECASE)
	# 			if usersearch:
	# 				recentlnk['User'] = usersearch.group(1)
	# 			recentlnk['Last Accessed (UTC)'] = rawrecentlnk['Last Accessed (UTC)']
	# 			recentlnk['Date Created (UTC)'] = rawrecentlnk['Date Created (UTC)']
	# 			recentlnk['Last Modified (UTC)'] = rawrecentlnk['Last Modified (UTC)']
	# 			recentlnk = clean(recentlnk, list(recentlnk))
	# 			recentlnk.to_excel(writer,sheet_name="File or Folder Opening",startcol=10,index=False,header=False,startrow=openLastRow)
	# 		except:
	# 			logger.info(rawFile + " is empty")

	# 	if "AutoRun Info.csv" in rawFile:
	# 		rawdata = open(rawFile, "r").read()
	# 		result = chardet.detect(rawdata)
	# 		charenc = result['encoding']
	# 		autorun = pd.read_csv(rawFile, encoding=charenc, header=0, index_col=False)
	# 		autorun.to_excel(writer,sheet_name="Autoruns_locations",index=False)

	# 	if "wmi-Software.csv" in rawFile:
	# 		rawdata = open(rawFile, "r").read()
	# 		result = chardet.detect(rawdata)
	# 		charenc = result['encoding']
	# 		software = pd.read_csv(rawFile, encoding=charenc, skiprows=2,names=['Node','Description','IdentifyingNumber','InstallDate','InstallLocation','InstallState','Name','PackageCache','SKUNumber','Vendor','Version'])
	# 		software.to_excel(writer, sheet_name="Installed_software", index=False)

	# 	if "wmi-Service.csv" in rawFile:
	# 		rawdata = open(rawFile, "r").read()
	# 		result = chardet.detect(rawdata)
	# 		charenc = result['encoding']
	# 		service = pd.read_csv(rawFile, encoding=charenc, skiprows=2,names=['Node','DesktopInteract','ErrorControl','Name','PathName','ServiceType','StartMode'])
	# 		service.to_excel(writer, sheet_name="New_services_installed", index=False)

	# 	if "-Logon Accounts.csv" in rawFile:
	# 		rawdata = open(rawFile, "r").read()
	# 		result = chardet.detect(rawdata)
	# 		charenc = result['encoding']
	# 		logs = pd.read_csv(rawFile, encoding=charenc, header=0)
	# 		logs.to_excel(writer, sheet_name="Logged_on_accounts", index=False)

	browserHistory.to_excel(writer, sheet_name="Browser History", index=False)
	writer.save()

	# try: 
	# 	writer = pd.ExcelWriter('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', engine='openpyxl')
	# 	writer.book = workbook
	# 	writer.sheets = dict((ws.title,ws) for ws in workbook.worksheets)
	# 	fileExecutionColumn = ['Path','Program Name','Last Execution','Exec Flag','Source','Source File','User']
	# 	fileExecutionMerged = pd.DataFrame(columns=fileExecutionColumn)
	# 	fileOpeningColumn = ['File Path','File Name','Last Execution','Last Accessed (UTC)','Date Created (UTC)','Last Modified (UTC)','Source','Source File','User']
	# 	fileOpeningMerged = pd.DataFrame(columns=fileOpeningColumn)

	# 	prefetchlist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File Execution', parse_cols="A:D",header=1)
	# 	prefetchlist = prefetchlist.dropna(how='all')
	# 	prefetchlist['Source'] = "Prefetch"
	# 	autocustomlist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File Execution', parse_cols="E:J",header=1)
	# 	compatreg = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File Execution', parse_cols="K:O",header=1)
	# 	compatreg = compatreg.dropna(how='all')
	# 	compatreg['Source'] = "AppCompatCache"
	# 	userassistreg = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File Execution', parse_cols="P:S",header=1)
	# 	userassistreg = userassistreg.dropna(how='all')
	# 	userassistreg['Source'] = "UserAssist"
	# 	lastvisitreg = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File Execution', parse_cols="T:W",header=1)
	# 	lastvisitreg = lastvisitreg.dropna(how='all')
	# 	lastvisitreg['Source'] = "Last Visited MRU"
	# 	runreg = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File Execution', parse_cols="X:Y",header=1)
	# 	runreg = runreg.dropna(how='all')	
	# 	runreg['Source'] = "Run MRU"

	# 	fileExecutionList = [fileExecutionMerged,prefetchlist,autocustomlist,compatreg,userassistreg,lastvisitreg,runreg]
	# 	fileExecutionExcel = pd.DataFrame()
	# 	fileExecutionExcel = pd.concat(fileExecutionList, ignore_index=True)
	# 	fileExecutionExcel.to_excel(writer,sheet_name="MERGED_File Execution",index=False,header=False,columns=fileExecutionColumn,startrow=1)

	# 	prefetchlist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="A:D",header=1)
	# 	prefetchlist = prefetchlist.dropna(how='all')
	# 	prefetchlist['Source'] = "Prefetch"
	# 	autocustomlist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="E:J",header=1)
	# 	recentlnklist = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="K:O",header=1)
	# 	recentlnklist = recentlnklist.dropna(how='all')
	# 	recentlnklist['Source'] = "Recent LNK"
	# 	recentdocreg = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="P:S",header=1)
	# 	recentdocreg = recentdocreg.dropna(how='all')
	# 	recentdocreg['Source'] = "Recent Docs"
	# 	officerecentreg = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="T:X",header=1)
	# 	officerecentreg = officerecentreg.dropna(how='all')
	# 	officerecentreg['Source'] = "Office Recent Docs"
	# 	lastvisitreg = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="Y:AB",header=1)
	# 	lastvisitreg = lastvisitreg.dropna(how='all')
	# 	lastvisitreg['Source'] = "Last Visited MRU"
	# 	opensavereg = pd.read_excel('./Results/' + projectname + '/' + imgname + '-Summary-' + timestamp + '.xlsx', sheetname='File or Folder Opening', parse_cols="AC:AF",header=1)
	# 	opensavereg = opensavereg.dropna(how='all')
	# 	opensavereg['Source'] = "Open Save MRU"

	# 	fileOpeningList = [fileOpeningMerged,prefetchlist,autocustomlist,recentlnklist,recentdocreg,officerecentreg,lastvisitreg,opensavereg]
	# 	fileOpeningExcel = pd.DataFrame()
	# 	fileOpeningExcel = pd.concat(fileOpeningList, ignore_index=True)
	# 	fileOpeningExcel.to_excel(writer,sheet_name="MERGED_File or Folder Opening",index=False,header=False,columns=fileOpeningColumn,startrow=1)
	# 	writer.save()
	# except Exception as e:
	# 	logger.error(e)


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
