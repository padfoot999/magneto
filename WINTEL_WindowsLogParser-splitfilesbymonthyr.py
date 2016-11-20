#!/usr/bin/python -tt
__description__ = 'To split WindowsLogParser.ps1 output by year or month'
import pandas as pd
import datetime
import argparse
import re

#NAME: separateLogs
#INPUT: String filepath, Boolean month
#OUTPUT: CSV file
#DESCRIPTION: Function splits CSV input file into years and month.
# If month is not provided, file at filepath will be split by year only
def separateLogs(filepath, month):
	date = str(datetime.datetime.strftime(datetime.datetime.today(),'%Y%m%d%H%M%S'))
	fields = ['Message','Id','Version','Qualifiers','Level','Task','Opcode','Keywords','RecordId','ProviderName','ProviderId','LogName','ProcessId','ThreadId','MachineName','UserId','TimeCreated','ActivityId','RelatedActivityId','ContainerLog','MatchedQueryIds','Bookmark','LevelDisplayName','OpcodeDisplayName','TaskDisplayName','KeywordsDisplayNames','Properties']
	df = pd.read_csv(filepath, dtype= object, skipinitialspace=True, usecols=fields, parse_dates=[16],dayfirst=True)
	#df['TimeCreated'] = pd.to_datetime(df['TimeCreated'])
	df['Year'] = df['TimeCreated'].dt.year
	outputYearFiles=[]

	for year in df['Year'].unique():
		filename = "./" + str(year) + "Logs-" + date + ".csv"
		outputYearFiles.append(filename)
		yearly = df.loc[df['Year']==year]
		yearly = yearly.drop('Year', 1)
		yearly.to_csv(filename, index=False, header=True)
		#[df['Year']==i].to_csv(filename, index=False, cols=fields)

	if(month):
		for file in outputYearFiles:
			df = pd.read_csv(file, skipinitialspace=True, usecols=fields, parse_dates=[16],dayfirst=True)
			df['Month'] = df['TimeCreated'].dt.month
			year = re.search('(\d{4})', file).groups()[0]
			for month in df['Month'].unique():
				filename = "./" + year + "-" + str(month) + "-" + "Logs-" + date + ".csv"
				monthly = df.loc[df['Month']==month]
				monthly = monthly.drop('Month', 1)
				monthly.to_csv(filename, index=False, header=True)


def main():
    parser = argparse.ArgumentParser(description="Baseline all information related to the project")
    parser.add_argument('-m', action='store_true', help="Separate logs by month")
    parser.add_argument('-f', dest='filepath', type=str, required=True, help="Path of Merged CSV File")    
    args = parser.parse_args() 
    separateLogs(args.filepath, args.m)   

if __name__ == '__main__':
    main()