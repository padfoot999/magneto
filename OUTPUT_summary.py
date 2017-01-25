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

#For log file
import logging
logger = logging.getLogger('root')


#NAME:process
#INPUT: database connection handle, directory to evidence files
#OUTPUT: NONE
#DESCRIPTION:   
def outputSummary(directory):
	imgname = os.path.split(directory)[1]
	timestamp = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))
	workbook = load_workbook(filename= 'MAGNETO_Host_Analysis_Checklist_Results_template2.xlsx') 
	writer = pd.ExcelWriter('./results/' + timestamp + '_' + imgname + '_Summary.xlsx', engine='openpyxl')
	writer.book = workbook
	writer.sheets = dict((ws.title,ws) for ws in workbook.worksheets)

	unprocessedlist = [] 

	# traverse root directory, and list directories as dirs and files as files
	for root, dirs, files in os.walk(directory):
		# logger.info("root is " + root)
		# logger.info("dirs is " + str(dirs))
		# logger.info("files is " + str(files))
		for filename in files:
			#Queueing all triage output files for processing. Once processed, they are removed
			if str(os.path.join(root,filename)) not in unprocessedlist:             
				unprocessedlist.append(os.path.join(root,filename))
	
	fileExecution = pd.DataFrame()
	fileOpening = pd.DataFrame()
	for rawFile in unprocessedlist:
		if "USBParser.xlsx" in rawFile:
			usbResults = pd.read_excel(rawFile, sheetname=0)
			usbResults.to_excel(writer, sheet_name="USB", index=False)

		if "FileExecutionParser.xlsx" in rawFile:
			fileExecutionResults = pd.read_excel(rawFile, sheetname=0)
			fileExecution = fileExecution.append(fileExecutionResults)

		if "FileOpeningParser.xlsx" in rawFile:
			fileOpeningResults = pd.read_excel(rawFile, sheetname=0)
			fileOpening = fileOpening.append(fileOpeningResults)

		if "Prefetch Info.csv" in rawFile:
			prefetch = pd.DataFrame()
			prefetch2 = pd.DataFrame()
			rawdata = open(rawFile, "r").read()
			result = chardet.detect(rawdata)
			charenc = result['encoding']
			rawprefetch = pd.read_csv(rawFile, encoding=charenc, skiprows=1,names=['Filename','Created Time','Modified Time','File Size','Process EXE','Process Path','Run Counter','Last Run Time','Missing Process'])
			rawprefetch['Last Run Time'] = pd.to_datetime(rawprefetch['Last Run Time'], dayfirst=True)
			prefetch['Source File'] = rawprefetch['Filename']
			prefetch['Path'] = rawprefetch['Process Path']
			prefetch['Program Name'] = rawprefetch['Process EXE']
			prefetch['Last Execution'] = rawprefetch['Last Run Time']
			prefetch['Source'] = "Prefetch"
			prefetch2['Source File'] = rawprefetch['Filename']
			prefetch2['File Path'] = rawprefetch['Process Path']
			prefetch2['File Name'] = rawprefetch['Process EXE']
			prefetch2['Last Execution'] = rawprefetch['Last Run Time']
			prefetch2['Source'] = "Prefetch"
			prefetch = prefetch.drop_duplicates(subset="Path")
			prefetch2 = prefetch2.drop_duplicates(subset="File Path")
			fileExecution = fileExecution.append(prefetch)
			fileOpening = fileOpening.append(prefetch2)

		if "_AutomaticDestinations.tsv" in rawFile:
			jmplist = pd.DataFrame()
			jmplist2 = pd.DataFrame()
			rawdata = open(rawFile, "r").read()
			result = chardet.detect(rawdata)
			charenc = result['encoding']
			rawjmplist = pd.read_csv(rawFile, sep='|', encoding=charenc, skiprows=2,names=['SourceFile','SourceCreated','SourceModified','SourceAccessed','AppId','AppIdDescription','DestListVersion','LastUsedEntryNumber','EntryNumber','CreationTime','LastModified','Hostname','MacAddress','Path','PinStatus','FileBirthDroid','FileDroid','VolumeBirthDroid','VolumeDroid','TargetCreated','TargetModified','TargetAccessed','FileSize','RelativePath','WorkingDirectory','FileAttributes','HeaderFlags','DriveType','DriveSerialNumber','DriveLabel','LocalPath','CommonPath','TargetIDAbsolutePath','TargetMFTEntryNumber','TargetMFTSequenceNumber','MachineID','MachineMACAddress','TrackerCreatedOn','ExtraBlocksPresent','Arguments','Notes','Robocopy File Name'])
			jmplist['Source File'] = rawjmplist['SourceFile']
			jmplist['Path'] = rawjmplist['Path']
			jmplist['Program Name'] = rawjmplist['AppIdDescription']
			jmplist['User'] = os.path.split(os.path.dirname(rawFile))[1]
			jmplist['Last Execution'] = rawjmplist['LastModified']
			jmplist['Source'] = "Automatic Destination (JMP Files)"
			jmplist2['Source File'] = rawjmplist['SourceFile']
			jmplist2['File Path'] = rawjmplist['Path']
			jmplist2['File Name'] = rawjmplist['AppIdDescription']
			jmplist2['User'] = os.path.split(os.path.dirname(rawFile))[1]
			jmplist2['Last Execution'] = rawjmplist['LastModified']
			jmplist2['Source'] = "Automatic Destination (JMP Files)"
			jmplist = jmplist.drop_duplicates(subset="Path")
			jmplist2 = jmplist2.drop_duplicates(subset="File Path")
			fileExecution = fileExecution.append(jmplist)
			fileOpening = fileOpening.append(jmplist2)

		if "_CustomDestinations.tsv" in rawFile:
			jmplist = pd.DataFrame()
			jmplist2 = pd.DataFrame()
			rawdata = open(rawFile, "r").read()
			result = chardet.detect(rawdata)
			charenc = result['encoding']
			rawjmplist = pd.read_csv(rawFile, sep='|', encoding=charenc, skiprows=2,names=['SourceFile','SourceCreated','SourceModified','SourceAccessed','AppId','AppIdDescription','EntryName','TargetCreated','TargetModified','TargetAccessed','FileSize','RelativePath','WorkingDirectory','FileAttributes','HeaderFlags','DriveType','DriveSerialNumber','DriveLabel','LocalPath','CommonPath','TargetIDAbsolutePath','TargetMFTEntryNumber','TargetMFTSequenceNumber','MachineID','MachineMACAddress','TrackerCreatedOn','ExtraBlocksPresent','Arguments','Robocopy File Name'])
			jmplist['Source File'] = rawjmplist['SourceFile']
			jmplist['Path'] = rawjmplist['LocalPath']
			jmplist['Program Name'] = rawjmplist['AppIdDescription']
			jmplist['User'] = os.path.split(os.path.dirname(rawFile))[1]
			jmplist['Last Execution'] = rawjmplist['SourceModified']
			jmplist['Source'] = "Custom Destination (JMP Files)"
			jmplist2['Source File'] = rawjmplist['SourceFile']
			jmplist2['File Path'] = rawjmplist['LocalPath']
			jmplist2['File Name'] = rawjmplist['AppIdDescription']
			jmplist2['User'] = os.path.split(os.path.dirname(rawFile))[1]
			jmplist2['Last Execution'] = rawjmplist['LastModified']
			jmplist2['Source'] = "Custom Destination (JMP Files)"
			jmplist = jmplist.drop_duplicates(subset="Path")
			jmplist2 = jmplist2.drop_duplicates(subset="File Path")
			fileExecution = fileExecution.append(jmplist)
			fileOpening = fileOpening.append(jmplist2)

		pattern = re.compile(r'Recent LNKs\\[^\\]*\\[^\\]*\.csv')
		if pattern.search(rawFile):
			logger.info(rawFile)
			recentlnk = pd.DataFrame()
			rawdata = open(rawFile, "r").read()
			result = chardet.detect(rawdata)
			charenc = result['encoding']
			try:
				rawrecentlnk = pd.read_csv(rawFile, encoding=charenc, header=0)
				recentlnk['File Path'] = rawrecentlnk['Local Path']
				recentlnk['File Path'].fillna(rawrecentlnk['Common Path'], inplace=True)
				#recentlnk['Last Execution'] = rawrecentlnk['']
				recentlnk['Source'] = "Recent LNKs"
				usersearch = re.search(r'Recent LNKs\\(.*)\\.*\.csv', rawFile, re.IGNORECASE)
				if usersearch:
					recentlnk['User'] = usersearch.group(1)
				fileOpening = fileOpening.append(recentlnk)
			except:
				logger.info(rawFile + " is empty")

		if "AutoRun Info.csv" in rawFile:
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
	
	fileExecution = clean(fileExecution, list(fileExecution))		
	fileExecution.to_excel(writer,sheet_name="File Execution",index=False)
	fileOpening = clean(fileOpening, list(fileOpening))
	fileOpening.to_excel(writer,sheet_name="File or Folder Opening",index=False)

	writer.save()

def clean(df, columns):
	for col in df.select_dtypes([np.object]).columns[1:]:
		df[col] = df[col].str.replace('[\000-\010]|[\013-\014]|[\016-\037]', '')
	return df

def main():
	parser = argparse.ArgumentParser(description="Process triage, network or memory dump evidence file(s), sorted by projects for correlation")
	parser.add_argument('-d', dest='directory', required=True, type=str, help="Directory containing evidence files")
	args = parser.parse_args()

	outputSummary(args.directory)
	
if __name__ == '__main__':
	main()

