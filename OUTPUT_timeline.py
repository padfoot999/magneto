#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
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
def outputTimeline(directory, projectname, results):
	imgname = os.path.split(directory)[1]
	timestamp = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))
	workbook = load_workbook(filename= 'MAGNETO_Timeline_template.xlsx')
	writer = pd.ExcelWriter('./Results/' + projectname + '/' + imgname + '-Timeline-' + timestamp + '.xlsx', engine='openpyxl')
	writer.book = workbook
	writer.sheets = dict((ws.title,ws) for ws in workbook.worksheets)
	writer.save()

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
	
	for root, dirs, files in os.walk(results):
		for filename in files:
			pathFile = str(os.path.join(root,filename))
			if "-MFT-" in pathFile and imgname in pathFile:
				unprocessedlist.append(os.path.join(root,filename))

	timeline_column = ['Date','Time','Source','Type','Short','Description']
	timeline = pd.DataFrame()
	timeline_merged = pd.DataFrame()
	timeline_merged_column = ['Date','Time','MACB','Source','Type','Short','Description']
	for rawFile in unprocessedlist:
		if "Timeline-" in rawFile:
			timeline = pd.read_excel(rawFile, sheetname=0, header=None, names=timeline_column)
			timeline = clean(timeline, list(timeline))
			timeline["MACB"] = ""
			timeline_merged = timeline_merged.append(timeline, ignore_index=True)
		if "MFT" in rawFile:
			mft_column = ['Date', 'Time', 'Timezone', 'MACB', 'Source', 'Type', '1' , 'user', 'host', 'Description', 'Desc', 'Version', 'Filename', 'Inode', 'Notes', "Format", "Extra"]
			timeline = pd.read_csv(rawFile, sep='|', header=None, names=mft_column)
			del timeline['Timezone']
			del timeline['1']
			del timeline['user']
			del timeline['host']
			del timeline['Desc']
			del timeline['Version']
			del timeline['Filename']
			del timeline['Inode']
			del timeline['Notes']
			del timeline['Format']
			del timeline['Extra']
			timeline_merged = timeline_merged.append(timeline, ignore_index=True)
	timeline_merged.to_excel(writer,sheet_name="Timeline",index=False,header=False,columns=timeline_merged_column,startrow=1)
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
	parser = argparse.ArgumentParser(description="Generates timeline file for Triage Incident files")
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
				outputTimeline(searchDirectory,projectname,args.results)

	else:
		for root, dirs, files in os.walk(searchDirectory):
		#searchDirectory cannot end with a slash!
			for directory in dirs:
				if "Incident" in directory:
						if directory not in imagelist:
							imagelist.append(directory)
							outputTimeline(str(os.path.join(root,directory)),projectname,args.results)

if __name__ == '__main__':
	main()
