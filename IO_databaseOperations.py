#!/usr/bin/python -tt
__description__ = 'Handle all database operations'

#For database operations
import psycopg2
import sys

#For ordered dictionary
import collections
from config import CONFIG

import logging
logger = logging.getLogger('root')

#NAME: databaseInitiate
#INPUT: string databaseHost, string databaseName, string databaseUser, string databasePassword
#OUTPUT: 
#DESCRIPTION: Setup database
def databaseInitiate():

    DATABASE = CONFIG['DATABASE']
    databaseHandle = databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    print str(databaseHandle)
    databaseCursor = databaseHandle.cursor()
    
    try:

        databaseCursor.execute("CREATE SCHEMA environment_variables;")
        databaseCursor.execute("CREATE TABLE environment_variables.mem_envars(imagename text,pid numeric, procname text, block text, variable text, pathvalue text);")
        databaseCursor.execute("CREATE TABLE environment_variables.mem_envars_path(imagename text, path text);")

        #Changed from sys_variables_path to triage_sys_variables_path                                             
        databaseCursor.execute("CREATE TABLE environment_variables.triage_sysvariables_path(imagename text, path text);")

        #Note that __compat_layer is intentional as this is what triage names it. Note that all the field are text, hence auto populate can be used. A mix of numeric and text does not allow auto populate.
        databaseCursor.execute("CREATE TABLE environment_variables.triage_sysvariables(imagename text, allusersprofile text, appdata text, commonprogramfiles text, commonprogramw6432 text, computername text, comspec text, fp_no_host_check text, homedrive text, homepath text, localappdata text, logonserver text, number_of_processors text, os text, processor_architecture text, processor_architew6432 text, processor_identifier text, processor_level numeric, processor_revision text, programdata text, programfiles text, programw6432 text, prompt text, psmodulepath text, public text, systemdrive text, systemroot text, temp text, tmp text, userdomain text, userdomain_roamingprofile text, username text, userprofile text, windir text, __compat_layer text, commonprogramfilesx86 text, programfilesx86 text, path text, pathext text, moz_plugin_path text, sessionname text);")
        
        #This is not used by any of the PARSER script
        databaseCursor.execute("CREATE SCHEMA ip_blacklist;")
        databaseCursor.execute("CREATE TABLE ip_blacklist.blacklistedip(ipaddress text, blackliststatus text, reversedns text, asn text, asnowner text, isp text, continent text, countrycode text, latitude_longitude text, city text, region text);")
        
        databaseCursor.execute("CREATE SCHEMA network;")
        databaseCursor.execute("CREATE TABLE network.mem_netscan(imagename text, protocol text, source text, sourceport numeric, destination text, destinationport numeric, state text, pid numeric, owner text, timecreated text, memoryoffset text);")                                                                
        databaseCursor.execute("CREATE TABLE network.triage_network_connections(imagename text, destination text, source text, state text, pid numeric, sourceport numeric, destinationport numeric, protocol text);")
        
        databaseCursor.execute("CREATE SCHEMA process_list;")
        #Note that start and exit is changed from timestamp without time zone to text. Should not have an impact on insertion
        databaseCursor.execute("CREATE TABLE process_list.mem_pslist(imagename text, offsetv text, procname text, ppid numeric, pid numeric, thds numeric, hnds numeric, sess numeric, wow64 numeric, start text, exit text);")
        
        #Note time is changed to ttime as time is a special key word        
        databaseCursor.execute("CREATE TABLE process_list.mem_pstree(imagename text, offsetv text, procname text, pid numeric, ppid numeric, thds numeric, hnds numeric, ttime text);")

        #Note that exit is changed from timestamp without time zone to text. Should not have an impact on insertion
        databaseCursor.execute("CREATE TABLE process_list.mem_psxview(imagename text, offsetp text, procname text, pid numeric, pslist text, psscan text, thrdproc text, pspcid text, csrss text, session text, deskthrd text, exit text);")

        databaseCursor.execute("CREATE TABLE process_list.triage_processes(imagename text, procname text, pid numeric, services text);")
        databaseCursor.execute("CREATE TABLE process_list.triage_processes_tree(imagename text, procname text, pid numeric, pri numeric, thd numeric, hnd numeric, priv numeric, cputime text, elapsedtime text, vm numeric, ws numeric);")
        
        databaseCursor.execute("CREATE SCHEMA project;")
        databaseCursor.execute("CREATE TABLE project.project_image_mapping(projectname text, imagename text);")
        
        databaseCursor.execute("CREATE SCHEMA system;")
        databaseCursor.execute("CREATE TABLE system.triage_sysinfo(imagename text, uptime text, kernelversion text, producttype text, productversion numeric, servicepack numeric, kernelbuildnumber numeric, registeredorganization text, registeredowner text, ieversion numeric, systemroot text, processors numeric, processorspeed text, processortype text, physicalmemory text, videodriver text, hostname text, osname text, osversion text, osmanufacturer text, osconfiguration text, osbuildtype text, productid text, systemmanufacturer text, systemmodel text, systemtype text, biosversion text, procinstalled text, windowsdirectory text, systemdirectory text, bootdevice text, systemlocale text, inputlocale text, timezone text, totalphysicalmemory text, availablephysicalmemory text, virtualmemory_maxsize text, virtualmemory_available text, virtualmemory_inuse text, pagefilelocation text, domain text, logonserver text, vmmonitormodeextensions text, virtualizationenabledinfirmware text, secondleveladdresstranslation text, dataexecutionpreventionavailable text, systemboottime text, originalinstalldate text);")
        databaseCursor.execute("CREATE TABLE system.triage_sysinfo_applications(imagename text, appname text);")
        databaseCursor.execute("CREATE TABLE system.triage_sysinfo_hotfix(    imagename text, totalnum numeric, hotfixid text, description text);")
        databaseCursor.execute("CREATE TABLE system.triage_sysinfo_nic(imagename text, nicid integer, nictype text, connectionname text, dhcpenabled text, totalinstalled integer, status character varying, dhcpserver character varying);")
        databaseCursor.execute("CREATE TABLE system.triage_sysinfo_nicip(imagename text, ipid numeric, ipadd text, nicid integer);")
        databaseCursor.execute("CREATE TABLE system.triage_sysinfo_partitions(imagename text, volumetype text, format text, label text, size text, free text, freepercent text);")
        databaseCursor.execute("CREATE TABLE system.triage_sysinfo_processors(imagename text, procid numeric, description text);")
        
        databaseCursor.execute("CREATE SCHEMA vt_hash_check;")
        #Changed from results to virustotal_results
        databaseCursor.execute("CREATE TABLE vt_hash_check.virustotal_results(md5 text, hits integer);")
        databaseCursor.execute("CREATE SCHEMA vulnerability;")
        databaseCursor.execute("CREATE TABLE vulnerability.windows_patch_level(cveid text, dateposted text, bulletinid text, bulletinkb text, bulletinkbseverity text, bulletinkbimpact text, title text, affectedproduct text, componentkb text, affectedcomponent text, componentkbimpact text, componentkbseverity text, supersedes text, reboot text);")
        databaseCursor.execute("CREATE TABLE vulnerability.cve_details(cveID text, status text, description text, references_ text, phase text, votes text, comments text, publishedDate text, cvssScore text);")
        databaseCursor.execute("CREATE TABLE vulnerability.product(product text, version text, cveID text);")
        databaseCursor.execute("CREATE TABLE vulnerability.manufacturer(manufacturer text, product text);")
        
        #Save changes
        databaseHandle.commit()
    except:
        pass


#NAME: databaseConnect
#INPUT: string databaseHost, string databaseName, string databaseUser, string databasePassword
#OUTPUT: Returns database connection handle if successful
#DESCRIPTION: Connects to database as specified by function parameters
def databaseConnect(databaseHost, databaseName, databaseUser, databasePassword):
    databaseConnectionString = "host=" + databaseHost + " dbname=" + databaseName + " user=" + databaseUser + " password=" + databasePassword
    logger.info("databaseConnectionString is " + databaseConnectionString + "\n")
    try:
        databaseConnectionHandle = psycopg2.connect(databaseConnectionString)
    except psycopg2.OperationalError as e:
        logger.error(('Unable to connect!\n{0}').format(e))
        sys.exit(1)
    else:        
        return databaseConnectionHandle

#NAME: cleanStrings
#INPUT: dictionary dictValues
#OUTPUT: dictionary dictValues
#DESCRIPTION: Initialize all string values within input dict to None datatype for new queries
def cleanStrings(dictValues):
    for key in dictValues.keys():
        if dictValues[key] == '':
            dictValues[key] = None
        else:
            if isinstance(dictValues[key], basestring):
                dictValues[key] = dictValues[key].replace("'", "")
                dictValues[key] = dictValues[key].replace('"', "")
    return dictValues

def cleanBlankStrings(dictValues):
    for key in dictValues.keys():
        if dictValues[key] == '':
            dictValues[key] = None
    return dictValues

#NAME: databaseInsert
#INPUT: psycopg2-db-handle databaseConnectionHandle, string databaseSchema, string databaseTable, collections-ordered dictionary dictValues
#OUTPUT: NONE
#DESCRIPTION: Insert dictValues keys AND values into database specified
def databaseInsert(databaseConnectionHandle, databaseSchema, databaseTable, dictValues):

    cur = databaseConnectionHandle.cursor()
    query = "INSERT INTO " + databaseSchema + "." + databaseTable + " ("

    #Creating SQL query statement
    for key in dictValues.iterkeys():
        query += key
        query+=", "
    query = query[:-2]
    query += ") VALUES ("
    for i in range(0,len(dictValues)):
        query += "%s, "
    query = query[:-2]
    query += ");"
    
    dictValues = cleanBlankStrings(dictValues)

    try:
        logger.info("query is " + query + "\n")
        logger.info("dictValues.values() is " + str(dictValues.values()) + "\n")
        cur.execute(query, dictValues.values())
        logger.info("%s row(s) inserted!" % cur.rowcount)        
        databaseConnectionHandle.commit()
    except psycopg2.OperationalError as e:
        logger.error(('Unable to INSERT!\n{0}').format(e))
        sys.exit(1)

def databaseExistInsert(databaseConnectionHandle, databaseSchema, databaseTable, dictValues):
    rowsInserted = 0
    value = None
    cur = databaseConnectionHandle.cursor()
    query = "INSERT INTO " + databaseSchema + "." + databaseTable + " ("
    query2 = ""
    query3 = ""
    dictValues = cleanStrings(dictValues)
    #Creating SQL query statement
    for key, value in dictValues.items():
        if value is not None:
            query += key
            query +=", "
            query2 +="'" + value + "'"
            query2 +=", "
            query3 += key + "='" + value + "'"
            query3 +=" AND "
    query = query[:-2]
    query2 = query2[:-2]
    query3 = query3[:-5]
    query += ") SELECT " + query2 + " WHERE NOT EXISTS (SELECT * FROM " + databaseSchema + "." + databaseTable + " WHERE " + query3 + ");"

    try:
        logger.info("query is " + query + "\n")
        logger.info("dictValues.values() is " + str(dictValues.values()) + "\n")
        cur.execute(query)
        logger.info("%s row(s) inserted!" % cur.rowcount)
        rowsInserted = cur.rowcount        
        databaseConnectionHandle.commit()
    except psycopg2.OperationalError as e:
        logger.error(('Unable to INSERT!\n{0}').format(e))
        sys.exit(1)
    return rowsInserted

#NAME: databaseUpdate
#INPUT: psycopg2-db-handle databaseConnectionHandle, string databaseSchema,
# string databaseTable, collections-ordered dictionary dictSetValues,
# collections-ordered dictionary dictWhereValues
#OUTPUT: NONE
#DESCRIPTION: Update dictSetValues keys AND values into database specified where row fits the criteria defined in dictWhereValues
def databaseUpdate(databaseConnectionHandle, databaseSchema, databaseTable, dictSetValues, dictWhereValues):

    cur = databaseConnectionHandle.cursor()
    query = "UPDATE " + databaseSchema + "." + databaseTable + " SET "

    #Creating SQL query statement
    for key in dictSetValues.iterkeys():
        query += key
        query +="=%s, "
    #Remove the comma
    query = query[:-2]

    query += " WHERE "
    for key in dictWhereValues.iterkeys():
        query+= key
        query +="=%s AND "
    #Remove the comma
    query = query[:-4]

    dictSetValues = cleanStrings(dictSetValues)
    dictWhereValues = cleanStrings(dictWhereValues)

    updateExecutionList = dictSetValues.values() + dictWhereValues.values()
    logger.info("dictSetValues.values() is " + str(dictSetValues.values()) + "\n")
    logger.info("dictWhereValues.values() is " + str(dictWhereValues.values()) + "\n")
    logger.info("updateExecutionList is " + str(updateExecutionList) + "\n")

    try:
        logger.info("query is " + query + "\n")
        cur.execute(query, updateExecutionList)
        logger.info("%s row(s) inserted!" % cur.rowcount)
        databaseConnectionHandle.commit()
    except psycopg2.OperationalError as e:
        logger.error(('Unable to UPDATE!\n{0}').format(e))
        sys.exit(1)



#NAME: databaseWhitelist
#INPUT: psycopg2-db-handle databaseConnectionHandle, string databaseSchema, string databaseTable, string groupTransaction, string columnCounted, integer orderRow
#OUTPUT: Returns result list if successful
#DESCRIPTION: Count a specific column uniquely and sorts results by ascending or descending count
#DECRIPTION: example of a query=>
    #SELECT DISTINCT col1, COUNT(DISTINCT col2) 
    #FROM schema.table GROUP BY col1
    #ORDER BY count DESC;
def databaseWhitelist(databaseConnectionHandle, project, databaseSchema, databaseTable, groupTransaction, columnCounted, orderRow=0):

    logger.info("PROJECT IS " + project)
    
    try:
        cur = databaseConnectionHandle.cursor()
    except psycopg2.OperationalError as e:
        logger.error(('Unable to connect!\n{0}').format(e))
        sys.exit(1)

    query = "SELECT DISTINCT "
    query += groupTransaction + ", COUNT (DISTINCT "
    query += columnCounted + ") "
    query += "FROM " + databaseSchema + "." + databaseTable
    query += " WHERE imagename IN (SELECT DISTINCT imagename FROM project.project_image_mapping WHERE projectname='" + project + "')"
    query += " GROUP BY " + groupTransaction
    query += " ORDER BY count "
    if orderRow == 0:
        query += "DESC;"
    else:
        query += "ASC;"

    try:
        logger.info("query is " + query + "\n")
        cur.execute(query)
    except psycopg2.OperationalError as e:
        logger.error(('Unable to SELECT!\n{0}').format(e))
        sys.exit(1)

    rows = cur.fetchall()
    databaseConnectionHandle.commit()
    return rows



#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

    #database configuration for project MAGNETO
    #These are sort of like constant, hence the CAPITALS.
    #Variables should NOT be in caps.

    #Sample test code
    #Note that all dictValues needs to be an ordered dictionary!!!
    dbhandle = databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    print "dbhandle is " + str(dbhandle) + "\n"

    sampleSchema = "path"
    sampleTable = "mem_envars"

    databaseDropTable(dbhandle,sampleSchema,sampleTable)

    #Testing TABLE CREATE function.
    #This is for mem_envars.
    #ZFZFTODO: To save a CreateTable library template for all schema
    sampleTableValue = collections.OrderedDict()
    sampleTableValue['imagename'] = "text NOT NULL"
    sampleTableValue['pid'] = "integer NOT NULL"
    sampleTableValue['procname'] = "text NOT NULL"
    sampleTableValue['block'] = "text"
    sampleTableValue['variable'] = "text NOT NULL"
    sampleTableValue['pathvalue'] = "text"
    databaseCreateTable(dbhandle,sampleSchema,sampleTable,sampleTableValue)

    #Testing SELECT function with NO VALUES
    sampleSelectValue1 = collections.OrderedDict()
    sampleSelectValue1['imagename'] = []
    sampleSelectValue1['pid'] = []
    sampleSelectValue1['procname'] = []
    sampleSelectValue1['block'] = []
    sampleSelectValue1['variable'] = []
    sampleSelectValue1['pathvalue'] = []
    sampleSelectValue2 = collections.OrderedDict()

    result1 = databaseSelect(dbhandle,sampleSchema,sampleTable,sampleSelectValue1,sampleSelectValue2)
    print "SELECT result is " + str(result1)

    #Testing SELECT function with VALUES
    sampleSelectValue1 = collections.OrderedDict()
    sampleSelectValue2 = collections.OrderedDict()
    sampleSelectValue2['imagename'] = "filename"
    sampleSelectValue2['pid'] = 98765,

    result2 = databaseSelect(dbhandle,sampleSchema,sampleTable,sampleSelectValue1,sampleSelectValue2)
    print "SELECT result is " + str(result2)

    #Testing INSERT function
    sampleInsertValue = collections.OrderedDict(),
    sampleInsertValue['imagename'] ="filename"
    sampleInsertValue['pid'] = 98765,
    sampleInsertValue['procname'] = "smss.exe"
    sampleInsertValue['block'] = "0x0000009e3e402080"
    sampleInsertValue['variable'] = "Path"
    sampleInsertValue['pathvalue'] = "C:\WINDOWS\System32"
    databaseInsert(dbhandle,sampleSchema,sampleTable,sampleInsertValue)

    #Verify INSERT
    sampleSelectValue3 = collections.OrderedDict()
    sampleSelectValue3['imagename'] = []
    sampleSelectValue3['pid'] = []
    sampleSelectValue3['procname'] = []
    sampleSelectValue3['block'] = []
    sampleSelectValue3['variable'] = []
    sampleSelectValue3['pathvalue'] = []
    result3 = databaseSelect(dbhandle,sampleSchema,sampleTable,sampleSelectValue3)
    print "INSERT result is " + str(result3)

    #Testing DELETE function
    sampleDeleteValue = collections.OrderedDict()
    sampleDeleteValue['pid'] = 98765,
    databaseDelete(dbhandle,sampleSchema,sampleTable,sampleDeleteValue)

    #Verify DELETE
    sampleSelectValue4 = collections.OrderedDict()
    sampleSelectValue4['imagename'] = []
    sampleSelectValue4['pid'] = []
    sampleSelectValue4['procname'] = []
    sampleSelectValue4['block'] = []
    sampleSelectValue4['variable'] = []
    sampleSelectValue4['pathvalue'] = []
    result4 = databaseSelect(dbhandle,sampleSchema,sampleTable,sampleSelectValue4)
    print "DELETE result is " + str(result4)

if __name__ == '__main__':
    main()
