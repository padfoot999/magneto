import os
import subprocess
import argparse
import datetime
import logging
import sys
import re
logger = logging.getLogger('root')
date = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))

#NAME: eseDatabase
#INPUT: Mountpoint of evidence file (i.e. G:\)
#OUTPUT: CSV Files of each table within Windows.edb in Results folder
#DESCRIPTION: Carves out data from Windows.edb in Evidence file
def eseDatabase(mountpoint):
	mainDirectory = os.path.dirname(os.getcwd())
	resultsDirectory = mainDirectory + "\\results\\" + date + "-" + mountpoint[0] + "-WindowsForensics"
	toolsDirectory = mainDirectory + "\\Tools"

	if not os.path.exists(resultsDirectory):
		try:
			os.makedirs(resultsDirectory)
		except:
			logging.error("Unable to create results folder")
			sys.exit()

	edbPaths = ["Documents and Settings\\All Users\\Application Data\\Microsoft\\Search\\Data\\Applications\\Windows", "ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows"]
	edbFile=""
	for path in edbPaths:
		if os.path.exists(mountpoint + "\\" + path):
			edbFile = mountpoint + path + "\\Windows.edb"
			pass

	if edbFile:
		subprocess.call([toolsDirectory+"\\nirsoft_package\\NirSoft\\esedatabaseview.exe", "/table", edbFile, "*", "/scomma", resultsDirectory+"\\WindowsEDB_*.csv"])
		
	print resultsDirectory

#NAME: thumbsViewer
#INPUT: Mountpoint of evidence file (i.e. G:\)
#OUTPUT: Thumbs information in CSV format and thumbnail images in Results folder
#DESCRIPTION: Extracts information from thumbscache files
def thumbsViewer(mountpoint):
	mainDirectory = os.path.dirname(os.getcwd())
	resultsDirectory = mainDirectory + "\\results\\" + date + "-" + mountpoint[0] + "-WindowsForensics\\ThumbsCache"
	toolsDirectory = mainDirectory + "\\Tools"

	if not os.path.exists(resultsDirectory):
		try:
			os.makedirs(resultsDirectory)
		except:
			logging.error("Unable to create results folder")
			sys.exit()
	thumbdbPaths = []
	thumbdbPaths = ['Users\\%s\\AppData\\Local\\Microsoft\\Windows\\Explorer' % name for name in os.listdir(mountpoint+"Users\\.") if os.path.isdir(mountpoint+"Users\\")]		
	for thumbdbPath in thumbdbPaths:
		print mountpoint + thumbdbPath
		if os.path.isdir(mountpoint + thumbdbPath):
			print mountpoint + thumbdbPath
			thumbcaches = [f for f in os.listdir(mountpoint + "\\" + thumbdbPath) if os.path.isfile(os.path.join(mountpoint + "\\" + thumbdbPath, f)) and re.search(r'(\w+\_\d+)', f)]
			for thumbcache in thumbcaches:
				subprocess.call([toolsDirectory+"\\thumbcacheviewer.exe", "-o", resultsDirectory, "-c", mountpoint+thumbdbPath+"\\"+thumbcache]) 

#NAME: recycleBin
#INPUT: Mountpoint of evidence file (i.e. G:\)
#OUTPUT: CSV containing information of files in the Recycle Bin
#DESCRIPTION: Examine contents of Recycle Bin using Rifiuti
def recycleBin(mountpoint):
	mainDirectory = os.path.dirname(os.getcwd())
	resultsDirectory = mainDirectory + "\\results\\" + date + "-" + mountpoint[0] + "-WindowsForensics"
	toolsDirectory = mainDirectory + "\\Tools"

	#For Windows 95/98/ME
	if os.path.isdir(mountpoint+"RECYCLED"):
		binDirectories = [(mountpoint+"RECYCLED\\%s\\INFO2") % name for name in os.listdir(mountpoint+"RECYCLED")]
	#For Windows NT/2K/XP
	if os.path.isdir(mountpoint+"RECYCLER"):
		binDirectories = [(mountpoint+"RECYCLER\\%s\\INFO2") % name for name in os.listdir(mountpoint+"RECYCLER")]
	#For Windows Vista & above
	if os.path.isdir(mountpoint+"$Recycle.Bin"):
		binDirectories = [(mountpoint+"$Recycle.Bin\\%s") % name for name in os.listdir(mountpoint+"$Recycle.Bin")]

	for file in  binDirectories:
		if os.path.isfile(file):
			subprocess.call([toolsDirectory+"\\rifiuti2\\x64\\rifiuti.exe", "-t", "','", "-o", "..\\results\\"+date + "-" + mountpoint[0] + "-WindowsForensics\\"+ file.split("\\")[2] + "-RecycleBinInfo.csv", "--localtime", file])
		else:
			subprocess.call([toolsDirectory+"\\rifiuti2\\x64\\rifiuti-vista.exe", "-t", "','", "-o", "..\\results\\"+date + "-" + mountpoint[0] + "-WindowsForensics\\"+ file.split("\\")[2] + "-RecycleBinInfo.csv", "--localtime", file])

#NAME: recycleBin
#INPUT: Mountpoint of evidence file (i.e. G:\)
#OUTPUT: CSV reports in PrefectParserResults folder within Results folder
# 		1. distinct_path: Contains all distinct paths
#		2. distinct_path_files: Contains distinct paths and associated prefetch file
#		3. layout_ini: Contains information of programs/prefetch files in the layout ini file
#		4. prefetch_file_detail: Contains File Load Path and File Name of prefetch file
#		5. prefetch_file_info: Contains Actual File Name, Number Time Run and UTC Time of prefetch file
#DESCRIPTION: Examine contents of Recycle Bin using Rifiuti
def prefetchParser(mountpoint):
	mainDirectory = os.path.dirname(os.getcwd())
	resultsDirectory = mainDirectory + "\\results\\" + date + "-" + mountpoint[0] + "-WindowsForensics\\PrefetchParserResults"
	toolsDirectory = mainDirectory + "\\Tools"

	if not os.path.exists(resultsDirectory):
		try:
			os.makedirs(resultsDirectory)
		except:
			logging.error("Unable to create results folder")
			sys.exit()

	if os.path.isdir(mountpoint+"Windows\\Prefetch"):
		subprocess.call([toolsDirectory+"\\parse_prefetch_info_v1.5\\parse_prefetch_info.exe", "-p", mountpoint+"Windows\\Prefetch", "-d", "..\\results\\"+ date + "-" + mountpoint[0] + "-WindowsForensics\\PrefetchParserResults\\prefetch.db3", "-r", "CSV", "-w", "XP", "-o", resultsDirectory])
	else:
		logger.error("Unable to find Prefetch Parser file!")

#NAME: main
#INPUT: Mountpoint of evidence file (i.e. G:\)
#OUTPUT: 
#DESCRIPTION: Extracts information from mounted image file
def main():
    parser = argparse.ArgumentParser(description="Baseline all information related to the project")
    parser.add_argument('-m', dest='mountpoint', type=str, required=True, help="Mountpoint of evidence file (i.e. G:\)")        
    args = parser.parse_args()    
    eseDatabase(args.mountpoint)
    thumbsViewer(args.mountpoint)
    recycleBin(args.mountpoint)
    prefetchParser(args.mountpoint)
    outlookpst(args.mountpoint)

if __name__ == '__main__':
    main()