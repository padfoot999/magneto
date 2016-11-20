from collections import defaultdict
from pprint import pprint as pp
import glob, os
import io
import re
import csv
import datetime
import subprocess
import zipfile
import argparse
import logging

oledumppath = ".\Tools\oledump_V0_0_25\oledump.py"
pdfidpath = ".\Tools\pdfid\pdfid.py"

#flag for macro in office extension like ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"
def anomalyDetect(directory):
	filedatetime = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))
	unprocessedlist=[]
	for root, dirs, files in os.walk(directory):
		path = root.split('\\')
        # logger.info("root is " + root)
        # logger.info("dirs is " + str(dirs))
        # logger.info("files is " + str(files))
		for filename in files:
			if str(os.path.join(root,filename)) not in unprocessedlist:             
				unprocessedlist.append(os.path.join(root,filename))

	with io.open('./results/' + filedatetime + '-MaliciousFileChecklist.csv', 'ab') as csvfile:
		fieldnames = ['Filename', 'Extension', 'MZ Header', 'Macro', 'Script']
		writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
		writer.writeheader()
		for file in unprocessedlist:
			macroVar = ""
			scriptVar = ""
			mzVar = ""
			extVar = os.path.splitext(file)[1]

			#process and flag javascript in pdf files detected by pdfid		
			if file.endswith(".pdf"):
				#get the full command to drive oledump and retrieve the output
				pdfcommand = "python " + pdfidpath + " " + file
				scriptoutput = "" + os.popen(pdfcommand).read()
				jscount = re.findall("/JS *(\d*)", scriptoutput)
				javascriptcount = re.findall("/JavaScript *(\d*)", scriptoutput)
				if not jscount:
					jscount.append("0")
				if not javascriptcount:
					javascriptcount.append("0")
				if int(jscount[0])>0 or int(javascriptcount[0])>0:
					scriptVar = "S"
			#process and flag macro in all other office files detected by oledump
			else:	
				#get the full command to drive oledump and retrieve the output
				olecommand = "python " + oledumppath + " " + file
				macrooutput = "" + os.popen(olecommand).read()
				if ": m" in macrooutput or ": M" in macrooutput:
					macroVar = "M"

			#process and flag for MZ Header in all files to see if they are truly executable
			#get the full path of the office file
			f = io.open(file, 'rb')
			fileContent = f.read(100)
			#pp(someRawContent)
			if fileContent[:2] == "MZ":
				mzVar = "MZ"

			writer.writerow({'Filename': file, 'Extension': extVar, 'MZ Header': mzVar, 'Macro': macroVar, 'Script': scriptVar})

def main():

	parser = argparse.ArgumentParser(description="Flag macro, javascripts and files that are not executable but contain mz header")
	group = parser.add_mutually_exclusive_group(required=True)   
	group.add_argument('-d', dest='directory', type=str, help="Directory containing evidence files")
	group.add_argument('-f', dest='file', type=str, help="Path to single evidence file")
	parser.add_argument('-p', dest='projectname', type=str, help="Codename of the project that the evidence is part of")
	args = parser.parse_args()

	if not args.directory:
		searchDirectory = args.file
	else:
		searchDirectory = args.directory

	name = args.projectname

	anomalyDetect(searchDirectory)

if __name__ == '__main__':
    main()
