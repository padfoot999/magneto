#!/usr/bin/python -tt
__description__ = 'Parse saved text result from Memory PSXView'

import collections
import IO_databaseOperations as db
import IO_fileProcessor as fp
from config import CONFIG

import logging
logger = logging.getLogger('root')

#NAME:parseAndPopulate
#INPUT:psycopg2-db-handle databaseConnectionHandle, string filename
#OUTPUT: NONE
#DESCRIPTION: Parse and insert values into database process_list.mem_psxview
def parseAndPopulate(databaseConnectionHandle, filename):

    logger.debug("databaseConnectionHandle is " + str(databaseConnectionHandle) + "\n")
    logger.debug("filename is " + filename + "\n")

    fileBuffer = fp.dequeFile(filename)

    path = filename.split('\\')

    #Skip thru the buffer until the title line
    while fileBuffer[0] != ['Offset(P)', 'Name', 'PID', 'pslist', 'psscan', 'thrdproc', 'pspcid', 'csrss', 'session', 'deskthrd', 'ExitTime']:
        fileBuffer.popleft()

    #Remove the title
    fileBuffer.popleft()

    #Remove the ---- line
    fileBuffer.popleft()

    while fileBuffer:
        temp = fileBuffer.popleft()

        #To handle process name with spaces
        procname = ""
        totalNameItems = 0
        for index, value in enumerate(temp):
            if not index == 0:
                totalNameItems += 1
                if not value.isdigit():
                    if procname:
                        procname += " "
                    procname += str(value)
                    logger.debug("procname is " + str(procname))
                    logger.debug("Number of items to form a name : " + str(totalNameItems))
                else:
                    totalNameItems-=1
                    break

        offsetp = temp[0]

        if len(temp)-totalNameItems+1 < 10:
            logger.error("Psxview: Problem processing the following line as some fields are missing : " + str(temp))            
        else:
            #for line with Exittime
            if len(temp)-totalNameItems+1 > 11:
                logger.debug("temp is " + str(temp) + "\n")

                #We need to work backwards due to the possibility of procname with spaces
                try:
                    pid = temp[-11]
                except (ValueError,IndexError) as e:
                    pid = ""
                    logger.error("Psxview: Problem assigning pid due to " + str(e))
                    pass

                try:
                    pslist = temp[-10]
                except (ValueError,IndexError) as e:
                    pslist = ""
                    logger.error("Psxview: Problem assigning pslist due to " + str(e))
                    pass

                try:
                    psscan = temp[-9]
                except (ValueError,IndexError) as e:
                    ppsscanid = ""
                    logger.error("Psxview: Problem assigning psscan due to " + str(e))
                    pass

                try:
                    thrdproc = temp[-8]
                except (ValueError,IndexError) as e:
                    thrdproc = ""
                    logger.error("Psxview: Problem assigning thrdproc due to " + str(e))
                    pass

                try:
                    pspcid = temp[-7]
                except (ValueError,IndexError) as e:
                    pspcid = ""
                    logger.error("Psxview: Problem assigning pspcid due to " + str(e))
                    pass

                try:
                    csrss = temp[-6]
                except (ValueError,IndexError) as e:
                    csrss = ""
                    logger.error("Psxview: Problem assigning csrss due to " + str(e))
                    pass

                try:
                    session = temp[-5]
                except (ValueError,IndexError) as e:
                    session = ""
                    logger.error("Psxview: Problem assigning session due to " + str(e))
                    pass

                try:
                    deskthrd = temp[-4]
                except (ValueError,IndexError) as e:
                    deskthrd = ""
                    logger.error("Psxview: Problem assigning deskthrd due to " + str(e))
                    pass

                #combine subsequent elements as they belong to the same field
                try:
                    exit = " ".join(temp[-3:])
                except (ValueError,IndexError) as e:
                    exit = ""
                    logger.error("Psxview: Problem assigning exit due to " + str(e))
                    pass

            else:
                try:
                    pid = temp[-8]
                except (ValueError,IndexError) as e:
                    pid = ""
                    logger.error("Psxview: Problem assigning pid due to " + str(e))
                    pass

                try:
                    pslist = temp[-7]
                except (ValueError,IndexError) as e:
                    pslist = ""
                    logger.error("Psxview: Problem assigning pslist due to " + str(e))
                    pass

                try:
                    psscan = temp[-6]
                except (ValueError,IndexError) as e:
                    psscan = ""
                    logger.error("Psxview: Problem assigning psscan due to " + str(e))
                    pass

                try:
                    thrdproc = temp[-5]
                except (ValueError,IndexError) as e:
                    thrdproc = ""
                    logger.error("Psxview: Problem assigning thrdproc due to " + str(e))
                    pass

                try:
                    pspcid = temp[-4]
                except (ValueError,IndexError) as e:
                    pspcid = ""
                    logger.error("Psxview: Problem assigning pspcid due to " + str(e))
                    pass

                try:
                    csrss = temp[-3]
                except (ValueError,IndexError) as e:
                    csrss = ""
                    logger.error("Psxview: Problem assigning csrss due to " + str(e))
                    pass

                try:
                    session = temp[-2]
                except (ValueError,IndexError) as e:
                    session = ""
                    logger.error("Psxview: Problem assigning session due to " + str(e))
                    pass

                try:
                    deskthrd = temp[-1]
                except (ValueError,IndexError) as e:
                    deskthrd = ""
                    logger.error("Psxview: Problem assigning deskthrd due to " + str(e))
                    pass

                exit = None

            logger.debug("offsetp is " + offsetp + "\n")
            logger.debug("procname is " + procname + "\n")
            logger.debug("pid is " + pid + "\n")
            logger.debug("pslist is " + pslist + "\n")
            logger.debug("psscan is " + psscan + "\n")
            logger.debug("thrdproc is " + thrdproc + "\n")
            logger.debug("pspcid is " + pspcid + "\n")
            logger.debug("csrss is " + csrss + "\n")
            logger.debug("session is " + session + "\n")
            logger.debug("deskthrd is " + deskthrd + "\n")
            logger.debug("exit is " + str(exit) + "\n")

            insertValue = collections.OrderedDict.fromkeys(['imagename', 'offsetp', 'procname', 'pid','pslist','psscan','thrdproc', 'pspcid', 'csrss', 'session', 'deskthrd', 'exit'])

            #Searching for triage naming convention for evidence whereby "Incident_" is always in the name. This is the imagename.
            for tempImageName in path:
                if "Incident_" in tempImageName:
                    break
            insertValue['imagename'] = tempImageName   
            
            insertValue['offsetp'] = offsetp
            insertValue['procname'] = procname

            skip = False

            if pid.isdigit():
                insertValue['pid'] = pid
            else:
                skip = True
                logger.error("Psxview: Problem processing the following line as pid field is NOT numeric :")
                print "pid is " + pid
                print str(temp)

            #Continue to insert without the errorneous field
            insertValue['pslist'] = pslist
            insertValue['psscan'] = psscan
            insertValue['thrdproc'] = thrdproc
            insertValue['pspcid'] = pspcid
            insertValue['csrss'] = csrss
            insertValue['session'] = session
            insertValue['deskthrd'] = deskthrd
            insertValue['exit'] = exit

            if skip == False:
                Schema = "process_list"
                Table = "mem_psxview"

                logger.debug("insertValue is " + str(insertValue) + "\n")
                db.databaseInsert(databaseConnectionHandle,Schema,Table,insertValue)

            #reset
            insertValue = collections.OrderedDict.fromkeys(['imagename', 'offsetp', 'procname', 'pid','pslist','psscan','thrdproc', 'pspcid', 'csrss', 'session', 'deskthrd', 'exit'])

#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():
    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], DATABASE['DATABASENAME'], DATABASE['USER'], DATABASE['PASSWORD'])
    logger.debug("dbhandle is " + str(dbhandle) + "\n")

    parser = argparse.ArgumentParser(description="Process volatility psxview output files")    
    parser.add_argument('-d', dest='filename', type=str, required=True, help="psxview plugin text output")  
    args = parser.parse_args()    

    parseAndPopulate(dbhandle,args.filename)

if __name__ == '__main__':
    main()
