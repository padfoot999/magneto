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
def outputSummary(directory):
	with open(directory + "\\OutputChecking.txt", "wb") as outfile: 
		for rawFile in unprocessedlist:
			if os.stat(rawFile).st_size == 0:
				outfile.write(rawFile + " has no output!" + "\n")

def main():
	parser = argparse.ArgumentParser(description="Process triage, network or memory dump evidence file(s), sorted by projects for correlation")
	parser.add_argument('-d', dest='directory', required=True, type=str, help="Directory containing evidence files")
	args = parser.parse_args()

	outputSummary(args.directory)
	
if __name__ == '__main__':
	main()

