__description__ = 'Generates an Excel Workbook containing list of IP addresses related to process and hyperlinks IP Address to another workbook containing more information about host'
import numpy as num
import xlwings as xw
import pandas as pd
import openpyxl
import os
import sys
sys.path.append(directory)
from config import CONFIG
from sqlalchemy import create_engine

#NAME:retrieve
#INPUT: Cell number and Excel Worksheet name that trigerred Python script
#OUTPUT: Excel Workbook containing hyperlinks 
#DESCRIPTION:  
def retrieve(cell, sheet):
	queryList = {
		'baseline-mem_envars_path':'SELECT DISTINCT system.triage_sysinfo_nicip.ipadd FROM environment_variables.mem_envars_path INNER JOIN system.triage_sysinfo_nicip ON environment_variables.mem_envars_path.imagename = system.triage_sysinfo_nicip.imagename WHERE environment_variables.mem_envars_path.path=%(process)s',
		'baseline-triage_sysvar_path':'SELECT DISTINCT system.triage_sysinfo_nicip.ipadd FROM environment_variables.triage_sysvariables_path INNER JOIN system.triage_sysinfo_nicip ON environment_variables.triage_sysvariables_path.imagename = system.triage_sysinfo_nicip.imagename WHERE environment_variables.triage_sysvariables_path.path=%(process)s',
		'baseline-triage_sysinfo_app':'SELECT DISTINCT system.triage_sysinfo_nicip.ipadd FROM system.triage_sysinfo_applications INNER JOIN system.triage_sysinfo_nicip ON system.triage_sysinfo_applications.imagename = system.triage_sysinfo_nicip.imagename WHERE system.triage_sysinfo_applications.appname=%(process)s',
		'baseline-triage_sysinfo_hotfix':'SELECT DISTINCT system.triage_sysinfo_nicip.ipadd FROM system.triage_sysinfo_hotfix INNER JOIN system.triage_sysinfo_nicip ON system.triage_sysinfo_hotfix.imagename = system.triage_sysinfo_nicip.imagename WHERE system.triage_sysinfo_hotfix.description=%(process)s',
		'baseline-mem_pslist':'SELECT DISTINCT system.triage_sysinfo_nicip.ipadd FROM process_list.mem_pslist INNER JOIN system.triage_sysinfo_nicip ON process_list.mem_pslist.imagename = system.triage_sysinfo_nicip.imagename WHERE process_list.mem_pslist.procname=%(process)s',
		'baseline-mem_pstree':'SELECT DISTINCT system.triage_sysinfo_nicip.ipadd FROM process_list.mem_pstree INNER JOIN system.triage_sysinfo_nicip ON process_list.mem_pstree.imagename = system.triage_sysinfo_nicip.imagename WHERE process_list.mem_pstree.procname=%(process)s',
		'baseline-mem_psxview':'SELECT DISTINCT system.triage_sysinfo_nicip.ipadd FROM process_list.mem_psxview INNER JOIN system.triage_sysinfo_nicip ON process_list.mem_psxview.imagename = system.triage_sysinfo_nicip.imagename WHERE process_list.mem_psxview.procname=%(process)s',
		'baseline-triage_processes':'SELECT DISTINCT system.triage_sysinfo_nicip.ipadd FROM process_list.triage_processes INNER JOIN system.triage_sysinfo_nicip ON process_list.triage_processes.imagename = system.triage_sysinfo_nicip.imagename WHERE process_list.triage_processes.procname=%(process)s'
	}

	#Creates an instance of sqlalchemy engine used by pandas when querying sql database
	wb = xw.Book.caller()
	DATABASE = CONFIG['DATABASE']
	url = 'postgresql://{}:{}@{}:{}/{}'
	user = DATABASE['USER'].replace("'", "")
	password=DATABASE['PASSWORD'].replace("'", "")
	host=DATABASE['HOST'].replace("'", "")
	port=5432
	db=DATABASE['DATABASENAME'].replace("'", "")
	url = url.format(user, password, host, port, db)
	engine = create_engine(url, client_encoding='utf8')

	#Queries for all distinct IP addresses related to (i.e. ProcessName)
	cellNumber = 'A' + str(cell)
	processName = wb.sheets[sheet].range(cellNumber).value
	query = queryList[sheet]
	ipaddress_data = pd.read_sql(query, engine, params={"process":processName})

	#Creates a new Excel Workbook containing all IP addresses
	newBook = xw.Book()
	newBook.sheets[0].range('A1').value = processName
	newBook.sheets[0].range('B1').options(index=False, header=False).value = ipaddress_data

	#Finds the number of rows containing data 
	row = ipaddress_data.shape[0]
	string = 'B1:B' + str(row+1)

	#Finds for latest copy of Sys Info Nic IP Merge File
	hostinfofile = ""
	resultsDirectory = directory + "\\results"
	for root, dirs, files in os.walk(resultsDirectory):
		files.sort()
		for filename in files:
			if filename.find("-SysInfoNicIPMerge.xlsx") is not -1:
				hostinfofile = filename

	#Finds the first cell containing that particular IP address in the Sysinfo NicIP Merge File and 
	#creates hyperlinks at the newly generated excel workbook to it
	hostinfowb = openpyxl.load_workbook(filename=resultsDirectory + "/" + hostinfofile)
	hostinfowsname = "sysinfo_nicip"
	hostinfows = hostinfowb[hostinfowsname]

	for originalindex, ipaddress in enumerate(newBook.sheets[0].range(string).value):
		for index, row in enumerate(hostinfows.iter_rows()):
			cellCoord = 'B' + str(index+1)
			if ipaddress == (hostinfows[cellCoord].value):
				link = resultsDirectory + "/" + hostinfofile + "#\'" + hostinfowsname + "\'!B" + str(index+1)
				newBook.sheets[0].range('B' + str(originalindex + 1)).add_hyperlink(link, ipaddress) 
				break

	

