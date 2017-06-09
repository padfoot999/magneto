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

systeminformation_files = []
networkinformation_files = []
registry_files = []
evidencecollection_files =[]
browser_files = []
wmic = []
volumeshadowcopies = []
options = []
kpmgcustomscripts = []

#NAME:process
#INPUT: database connection handle, directory to evidence files
#OUTPUT: NONE
#DESCRIPTION:   
def postTriage(directory,projectname):
	timestamp = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))
	pathParts = directory.split('\\')
	for part in pathParts:
		if "Incident" in part:
			imgname = part

	unprocessedlist = []

	dir = os.getcwd()
	resultsDir = dir + "/Results"
	if not os.path.exists(resultsDir):
		try:
			os.makedirs(resultsDir)
		except:
			logging.error("Unable to create results folder")
			sys.exit()

	projResultsDir = dir + "/Results/" + projectname 
	if not os.path.exists(projResultsDir):
		try:
			os.makedirs(projResultsDir)
		except:
			logging.error("Unable to create Project results folder")
			sys.exit() 

	# traverse root directory, and list directories as dirs and files as files
	for root, dirs, files in os.walk(directory):
		for filename in files:
			#Queueing all triage output files for processing. Once processed, they are removed
			if str(os.path.join(root,filename)) not in unprocessedlist:             
				unprocessedlist.append(os.path.join(root,filename))
	
	for rawFile in unprocessedlist:
		if "SRUDB.dat" in rawFile:
			currentWorkingDirectory = os.getcwd()
			outputfile = currentWorkingDirectory + "\Results\\" + projectname + "\\" + imgname + "-SRUM DUMP Report-" + timestamp + ".xls"
			os.chdir('.\Tools\srum-dump')
			with open(currentWorkingDirectory + "\Results\\" + projectname + "\\" + imgname + "-SRUM DUMP Log-" + timestamp + ".txt", "a") as logfile:
				subprocess.call(['srum_dump.exe', '-i', rawFile, '-o', outputfile], stdout=logfile)
			os.chdir(currentWorkingDirectory)

		if "WebCacheV01.dat" in rawFile:
			currentWorkingDirectory = os.getcwd()
			outputfiles = currentWorkingDirectory + "\Results\\" + projectname + "\\WebCache_Tables-" + imgname + "\WebCache_*.csv"
			outputdir = currentWorkingDirectory + "\Results\\" + projectname + "\\WebCache_Tables-" + imgname
			if not os.path.exists(outputdir):
				try:
					os.makedirs(outputdir)
				except:
					logging.error("Unable to create results folder")
					sys.exit()
			os.chdir('.\Tools\\nirsoft_package\\NirSoft')
			subprocess.call(['esedatabaseview.exe','/table', rawFile, '*', '/scomma', outputfiles])
			os.chdir(currentWorkingDirectory)

		if "SYSTEM_" in rawFile:
			currentWorkingDirectory = os.getcwd()
			outputFile = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname + "\SYSTEM_Ripped_Report.txt"
			outputdir = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname
			if not os.path.exists(outputdir):
				try:
					os.makedirs(outputdir)
				except:
					logging.error("Unable to create results folder")
					sys.exit()
			os.chdir('.\Tools\RegRipper')
			with open(outputFile, "a") as outfile:
				subprocess.call(['perl','rip2.pl', '-r', rawFile, '-f', 'system'], stdout=outfile)
			os.chdir(currentWorkingDirectory)

		if "SOFTWARE_" in rawFile:
			currentWorkingDirectory = os.getcwd()
			outputFile = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname + "\SOFTWARE_Ripped_Report.txt"
			outputdir = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname
			if not os.path.exists(outputdir):
				try:
					os.makedirs(outputdir)
				except:
					logging.error("Unable to create results folder")
					sys.exit()
			os.chdir('.\Tools\RegRipper')
			with open(outputFile, "a") as outfile:
				subprocess.call(['perl','rip2.pl', '-r', rawFile, '-f', 'software'], stdout=outfile)
			os.chdir(currentWorkingDirectory)

		if "SAM_" in rawFile:
			currentWorkingDirectory = os.getcwd()
			outputFile = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname + "\SAM_Ripped_Report.txt"
			outputdir = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname
			if not os.path.exists(outputdir):
				try:
					os.makedirs(outputdir)
				except:
					logging.error("Unable to create results folder")
					sys.exit()
			os.chdir('.\Tools\RegRipper')
			with open(outputFile, "a") as outfile:
				subprocess.call(['perl','rip2.pl', '-r', rawFile, '-f', 'sam'], stdout=outfile)
			os.chdir(currentWorkingDirectory)

		if "SECURITY_" in rawFile:
			currentWorkingDirectory = os.getcwd()
			outputFile = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname + "\SECURITY_Ripped_Report.txt"
			outputdir = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname
			if not os.path.exists(outputdir):
				try:
					os.makedirs(outputdir)
				except:
					logging.error("Unable to create results folder")
					sys.exit()
			os.chdir('.\Tools\RegRipper')
			with open(outputFile, "a") as outfile:
				subprocess.call(['perl','rip2.pl', '-r', rawFile, '-f', 'security'], stdout=outfile)
			os.chdir(currentWorkingDirectory)

		# if "HKCU_" in rawFile:
		# 	currentWorkingDirectory = os.getcwd()
		# 	outputFile = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname + "\NTUSER_Ripped_Report.txt"
		# 	outputdir = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname
		# 	if not os.path.exists(outputdir):
		# 		try:
		# 			os.makedirs(outputdir)
		# 		except:
		# 			logging.error("Unable to create results folder")
		# 			sys.exit()
		# 	os.chdir('.\Tools\RegRipper')
		# 	with open(outputFile, "a") as outfile:
		# 		subprocess.call(['perl','rip2.pl', '-r', rawFile, '-f', 'ntuser'], stdout=outfile)
		# 	os.chdir(currentWorkingDirectory)
		
		if "_1.dat" in rawFile:
			currentWorkingDirectory = os.getcwd()
			os.chdir('.\Tools\RegRipper')
			subprocess.call(['perl','rip2.pl', '-r', rawFile, '-p', 'usbParser'])
			subprocess.call(['perl','rip2.pl', '-r', rawFile, '-p', 'fileOpeningParser'])
			subprocess.call(['perl','rip2.pl', '-r', rawFile, '-p', 'fileExecutionParser'])
			os.chdir(currentWorkingDirectory)

		if "Evidence" in rawFile:
			if "USER" in rawFile and ".dat" in rawFile:
				currentWorkingDirectory = os.getcwd()
				outputFile = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname + "\\" + os.path.splitext(os.path.basename(rawFile))[0] + "_Ripped_Report.txt"
				outputdir = currentWorkingDirectory + "\Results\\" + projectname + "\\RegRipper-" + imgname
				if not os.path.exists(outputdir):
					try:
						os.makedirs(outputdir)
					except:
						logging.error("Unable to create results folder")
						sys.exit()
				os.chdir('.\Tools\RegRipper')
				with open(outputFile, "a") as outfile:
					subprocess.call(['perl','rip2.pl', '-r', rawFile, '-f', 'ntuser'], stdout=outfile)
				os.chdir(currentWorkingDirectory)

		if "$MFTcopy" in rawFile:
			currentWorkingDirectory = os.getcwd()
			outputfile = currentWorkingDirectory + "\Results\\" + projectname + "\\" + imgname + "-MFT-" + timestamp + ".csv"
			subprocess.call(['python','.\Tools\\analyzeMFT-master\\analyzeMFT.py', '-f', rawFile, '-c', outputfile])

		if "RecentFileCache.bcf" in rawFile:
			parentDirectory = os.path.abspath(os.path.join(rawFile, os.pardir))
			outputfile = parentDirectory + "\\RecentFileCache-Output.csv"
			with open(outputfile, "a") as outfile:
				subprocess.call(['python','.\Resources\\rfcparse.py', '-f', rawFile], stdout=outfile)


	users = []
	if os.path.isdir(directory + "\\Evidence\\Jump Lists"):
		for root, dirs, files in os.walk(directory + "\\Evidence\\Jump Lists"):
			users.extend(dirs)
			break
	for user in users:
		if not any((fname.endswith('CustomDestinations.tsv') or fname.endswith('AutomaticDestinations.tsv')) for fname in os.listdir(directory + "\\Evidence\\Jump Lists\\" + user)):
			subprocess.call(['.\Tools\JLECmd-master\JLECmd-master\JLECmd\\bin\Debug\JLECmd.exe', '-d', directory + "\\Evidence\\Jump Lists\\" + user + "\\Automatic", '--csv', directory + "\\Evidence\\Jump Lists\\" + user])
			subprocess.call(['.\Tools\JLECmd-master\JLECmd-master\JLECmd\\bin\Debug\JLECmd.exe', '-d', directory + "\\Evidence\\Jump Lists\\" + user + "\\Custom", '--csv', directory + "\\Evidence\\Jump Lists\\" + user])

def main():
	parser = argparse.ArgumentParser(description="Process triage, network or memory dump evidence file(s), sorted by projects for correlation")
	parser.add_argument('-d', dest='directory', required=True, type=str, help="Directory containing evidence files")
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
				postTriage(searchDirectory,projectname)
				
	else:
		for root, dirs, files in os.walk(searchDirectory):
		#searchDirectory cannot end with a slash!
			for directory in dirs:
				if "Incident" in directory:
						if directory not in imagelist:
							imagelist.append(directory)
							postTriage(str(os.path.join(root,directory)),projectname)

if __name__ == '__main__':
	main()

 