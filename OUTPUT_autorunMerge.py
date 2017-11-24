#!/usr/bin/python -tt
__description__ = 'Whitelist'

import collections
import csv
import os
import datetime
import argparse
import re
import sys
from openpyxl import Workbook, load_workbook
from config import CONFIG
import pandas as pd
import csv
import numpy as np
import chardet

import logging
logger = logging.getLogger('root')

import sys  
reload(sys)  
sys.setdefaultencoding('utf8')

def autorunMerge(directory, projectname):
	date = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))
	incidentFolders={}
	autorunMerged=pd.DataFrame()

	for root, dirs, files in os.walk(directory):
		for directory in dirs:
			if "Incident" in directory:
				if str(os.path.join(root,directory)) not in incidentFolders:
					incidentFolders[directory] = os.path.join(root,directory)

	for incidentFolder in incidentFolders.keys():
		logger.debug(incidentFolder)
		for root, dirs, files in os.walk(incidentFolders[incidentFolder]):
			for filename in files:
				if filename == "AutoRun Info.csv":
					rawFile = os.path.join(root,filename)
					logger.debug(rawFile)
					rawdata = open(rawFile, "r").read()
					result = chardet.detect(rawdata)
					charenc = result['encoding']
					autorun = pd.read_csv(rawFile, encoding=charenc, skiprows=1,names=['Time','Entry','Location','Entry','Enabled','Category','Profile','Description','Publisher','Image Path', 'Version','Launch String'])
					autorun['Incident File'] = incidentFolder
					autorunMerged = autorunMerged.append(autorun, ignore_index=True)

	autorunMerged.to_csv('./Results/' + projectname + '/' + date + '_AutoRunMerged.csv', index=False)

#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():
	parser = argparse.ArgumentParser(description="Baseline all information related to the project")
	parser.add_argument('-d', dest='directory', type=str, help="Directory containing evidence files")
	parser.add_argument('-p', dest='projectname', type=str, required=True, help="Codename of the project that the evidence is part of")        
	args = parser.parse_args()    
	autorunMerge(args.directory, args.projectname)
	
if __name__ == '__main__':
	main()