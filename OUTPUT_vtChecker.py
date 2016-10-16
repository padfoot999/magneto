#!/usr/bin/python -tt

from config import CONFIG
import json
import requests
import time
from Queue import Queue, Empty
from threading import Thread
from datetime import datetime
import IO_databaseOperations as db
import random
from collections import OrderedDict
import csv
import sys
import os
import re
import argparse
import logging

# to suppress urllib3 InsecureRequestWarning when working with MITM proxies
requests.packages.urllib3.disable_warnings()

import logging
logger = logging.getLogger('root')


timestamp = time.strftime("%Y%m%d-%H%M%S")

class virusTotalAPI():
    
    # initialize class with VT API2 key for this instance
    def __init__(self, vt_api2_key):
        self.vt_api2_key = vt_api2_key
        self.name = vt_api2_key[0:4]
        logger.debug("virusTotalAPI instance %s init with API key %s" % (self.name, self.vt_api2_key))
        self.vt_api2_wait = 15  # VT public API gives 4 requests per min -> 15sec wait
        self.last_vt2_send = False

    #NAME: getReport
    #INPUT: hash (md5/sha*) of binary in hex string to search VT
    #OUTPUT: either None, or data structures as parsed out from VT JSON response content
    #DESCRIPTION: Query VT for report based on MD5 hash
    def getReport(self, query):
        logger.debug("virusTotalAPI instance %s getReport called with query string %s" % (self.name, query))
        #url = "https://www.virustotal.com/vtapi/v2/file/rescan"
        url = "https://www.virustotal.com/vtapi/v2/file/report"

        while True:
            try:

                if self.last_vt2_send and ((datetime.now() - self.last_vt2_send).seconds < self.vt_api2_wait):
                    waitfor = self.vt_api2_wait - (datetime.now() - self.last_vt2_send).seconds + 0.5
                    logger.debug("virusTotalAPI instance %s waiting %s seconds before querying" % (self.name, waitfor))
                    time.sleep(waitfor)
                    logger.debug("virusTotalAPI instance %s done waiting" % self.name)

                self.last_vt2_send = datetime.now()
                req = requests.get(
                    url, 
                    params={'resource': query, 'apikey': self.vt_api2_key}, 
                    proxies=CONFIG['ONLINE']['PROXIES'],
                    verify=(not CONFIG['ONLINE']['MITMPROXY']))
                self.last_vt2_send = datetime.now()

                if req.status_code == 200:
                    return req.json()

            except Exception as e:
                logger.debug("virusTotalAPI instance %s caught exception %s %s" % (self.name, type(e), e.args))



#NAME: isHash
#INPUT: string test
#OUTPUT: True / False
#DESCRIPTION: tests if this is a MD5/SHA1 hash
def isHash(test=''):
    if type(test) != str:
        return False
    if re.match('^[0-9a-f]{32}$', test, re.IGNORECASE) or re.match('^[0-9a-f]{40}$', test, re.IGNORECASE):
        return True
    else:
        return False



#NAME: vtDaemon
#INPUT: vt_api2_key string API key to use; inqueue Queue; outqueue Queue; queues dictionary of all Queues
#OUTPUT: None
#DESCRIPTION: implementation of VT querying daemon thread
def vtDaemon(vt_api2_key, inqueue, outqueue, queues):

    daemonname = vt_api2_key[0:4]

    # instantiate VT query class using API key, the query class does its own backoff and retrying
    vt = virusTotalAPI(vt_api2_key)

    while True:
        try:

            # grab next queue item
            item = inqueue.get_nowait()
            logger.debug('vtDaemon %s processing hash %s' % (daemonname, item))

            # sanity check on "hash" first
            if not isHash(item):
                logger.debug('vtDaemon %s got "%s" to process, not MD5/SHA1, skipping' % (daemonname, item))
                inqueue.task_done()
                continue

            results = None

            # check for cache
            outputtxtpath = "%s/%s.txt" % (CONFIG['VTCHECKER']['VT_RESULT'], item)
            
            if os.path.isfile(outputtxtpath):
                logger.debug('vtDaemon %s using local cache file for this hash' % daemonname)
                try:
                    with open(outputtxtpath, 'r') as f:
                        results = json.load(f)
                        # logger.debug('vtDaemon %s loaded as %s' % (daemonname, results))
                except:
                    logger.debug('vtDaemon %s failed loading cache file, will move on to VT querying')
                    results = None

            # query VT
            if results == None:
                logger.debug('vtDaemon %s querying VT for %s' % (daemonname, item))
                results = vt.getReport(item)

                # write results to file, needed for consolidating results.csv
                logger.debug('vtDaemon %s writing json results of VT query for "%s" to %s' % (daemonname, item, outputtxtpath))
                with open(outputtxtpath, 'wb') as f:
                    json.dump(results, f, indent=4)

            # create hashresults tuple accordingly and put into outqueue
            if results['response_code'] == 1:
                logger.debug('vtDaemon %s hash item "%s" has report with %s positives' % (daemonname, item, results['positives']))
                outqueue.put((item, results['positives']))
            else:
                logger.debug('vtDaemon %s query "%s" has no report' % (daemonname, item))
                outqueue.put((item, -1))

            # signal VTCHECKERMaster that one more hash has been processed
            inqueue.task_done()

        except Empty:
            # do-while there are items in any queue
            if allQueuesCleared(queues):
                logger.debug('vtDaemon %s is terminating' % (daemonname))
                return
            else:
                time.sleep(10)  #backoff timing before checking queue again

        except Exception as e:
            logger.debug('vtDaemon %s caught exception %s %s, placing "%s" back in queue' % (daemonname, type(e), e.args, item))
            inqueue.task_done()
            inqueue.put(item)


# Note that this is under the assumption that NSRL is populatred in the database.
#NAME: nsrlFilterDaemon
#INPUT: inqueue Queue; outqueue Queue; queues dictionary of all Queues
#OUTPUT: None
#DESCRIPTION: filters through input queue and removes hashes that are found in NSRL, and passes the rest into outqueue for VT query daemons to pick up
def nsrlFilterDaemon(inqueue, outqueue, queues):

    if not CONFIG["VTCHECKER"]["ENABLE_NSRL_FILTER"]:
        time.sleep(0.1)
        logger.debug("nsrlFilterDaemon disabled, transferring all hashes to VT queue")
        while True:
            try:
                outqueue.put(inqueue.get_nowait())
                inqueue.task_done()
            except Empty:
                # do-while there are items in the inqueue: i.e. inqueue.get_nowait() does not throw a Queue.empty exception
                return

    # setup pgsql connection db:magneto schema:nsrl table:file column:md5
    DATABASE = CONFIG['DATABASE']
    dbhandle = db.databaseConnect(DATABASE['HOST'], "'magneto'", DATABASE['USER'], DATABASE['PASSWORD'])

    while True:
        try:

            item = inqueue.get_nowait()
            logger.debug("nsrlFilterDaemon checking %s" % item)

            # query NSRL database db:magneto schema:nsrl table:file column:md5
            # NSRL database hash values are in uppercase
            whereValue = OrderedDict.fromkeys(['md5'])
            whereValue['md5'] = item.upper()
            nsrlhits = db.databaseSelect(dbhandle, 'nsrl', 'file', OrderedDict.fromkeys(['md5']), whereValue, limit=1)

            # if at least one tuple returned, take it that NSRL has a hit
            if len(nsrlhits) > 0:
                logger.debug("nsrlFilterDaemon NSRL hit")
                # create hashresults tuple accordingly and put into resultsqueue
                queues['resultsqueue'].put((item, -2))
            else:
                outqueue.put(item)

            inqueue.task_done()

        except Empty:
            # do-while there are items in the inqueue: i.e. inqueue.get_nowait() does not throw a Queue.empty exception
            return



# "Global" data structure to store summary
class SummaryText(object):
    def __init__(self):
        self.text = ''

    def appendLine(self, message=''):
        self.text += '%s\n' % message

    def getText(self):
        return self.text



# "Global" data structure to better manage hash-filepath information
# stores data in self.data
'''
- hashes stored as keys, in lowercase.
self.dictset = {
    'hash1': set(['filepath1','filepath2']),
    'hash2': set(['filepath3'])}
'''
class HashFilePath(object):
    def __init__(self):
        self.dictset = {}

    def addHashFilePath(self, hashhexstring='', filepath=''):
        if not isHash(hashhexstring):
            logger.debug('"%s" is not a hash hex string, not adding to data structure.' % hashhexstring)
        else:
            hashhexstring = hashhexstring.lower()
            if hashhexstring not in self.dictset:
                self.dictset[hashhexstring] = set()
            self.dictset[hashhexstring].add(filepath)



#NAME: allQueuesCleared
#INPUT: dictionary containing all processing queues
#OUTPUT: True/False
#DESCRIPTION: checks if all queues are cleared and does not have any unfinished_tasks
def allQueuesCleared(queues={}):
    for queue in queues.itervalues():
        if queue.unfinished_tasks > 0:
            return False
    return True



#NAME: VTCHECKERMaster
#INPUT: HashFilePath object containing all hashes and filepaths.
#OUTPUT: None
#DESCRIPTION: master VTCHECKER dispatcher/monitor/results collater thread
#TAKE NOTE! db:magneto schema:hashcheck table:results column:md5,hits stores MD5 hashes in lowercase
def VTCHECKERMaster(hpf=HashFilePath()):

    logger.debug("Starts")
    
    #Check if results folder exist, if not, create it.
    resultsDir = CONFIG['VTCHECKER']['VT_RESULT']    
    dir = os.getcwd()
    fullResultsDir = dir + "/" + resultsDir
    logger.debug("fullResultsDir is " + str(fullResultsDir))
    if not os.path.exists(fullResultsDir):
        try:
            os.makedirs(fullResultsDir)
        except:
            logging.error("Unable to create results folder")
            sys.exit()

    # for VTCHECKER summary to show/store in file at the end of this run
    summarytext = SummaryText()
    summarytext.appendLine('========================')
    summarytext.appendLine('Virus Total Hash checker')
    summarytext.appendLine('========================')
    summarytext.appendLine()
    summarytext.appendLine('Started at %s' % datetime.now())

    if len(hpf.dictset) == 0:
        logger.debug("ERROR in VTCHECKERMaster: no hashes to process.")

    # setup pgsql connection first db:magneto schema:hashcheck table:results column:md5,hits
    if CONFIG['VTCHECKER']['ENABLE_DB_RESULTS_FILTER'] or CONFIG['VTCHECKER']['RESULTS_TO_DB']:
        DATABASE = CONFIG['DATABASE']
        dbhandle = db.databaseConnect(DATABASE['HOST'], "'magneto'", DATABASE['USER'], DATABASE['PASSWORD'])

    queues = {}

    # resultsqueue will contain tuples for each hash in this format: (hash string, signed integer)
    # signed integer can take on these values:
    # -2: found in NSRL, so not queried on VT
    # -1: not found in NSRL, but no VT report found for that hash (i.e. no one has submitted that binary for analysis before)
    # 0..n: not found in NSRL, queried against VT and found a report, and 
    # example:
    # ("99017f6eebbac24f351415dd410d522d", 50)
    # ("99017f6eebbac24f351415dd410d522e", -1)
    queues['resultsqueue'] = Queue()

    # filter hashes to process based on:
    # 1. whether they already have VT reports (i.e. no need to query again) (hits >= 0)
    # 2. whether they already have NSRL hits (hits = -2)
    # leaving behind these to be processed:
    # 3. those with no VT reports (hits = -1)
    # 4. those not found in DB (never been processed before)
    if CONFIG['VTCHECKER']['ENABLE_DB_RESULTS_FILTER']:
        logger.debug("Checking database and removing hashes already stored in db")
        counter = 0
        toremove = set()
        for hashhexstring in hpf.dictset.iterkeys():
            whereValue = OrderedDict.fromkeys(['md5'])
            whereValue['md5'] = hashhexstring
            searchhits = db.databaseSelect(dbhandle, 'vt_hash_check', 'results', OrderedDict.fromkeys([]), whereValue, limit=1)
            if len(searchhits) > 0:
                if (searchhits[0][1] >= 0) or (searchhits[0][1] == -2):
                    toremove.add(hashhexstring)
                    queues['resultsqueue'].put((hashhexstring, searchhits[0][1]))
            counter += 1
            if counter % (len(dedup)/100) == 0:
                logger.debug("Checked %s hashes, %s to be removed from processing queue" % (counter, len(toremove)))
        while len(toremove) > 0:
            hpf.dictset.pop(toremove.pop(), None)
        logger.debug("VTCHECKERMaster hashlist has %s items after removing hashcheck results already there" % len(hpf.dictset))
        summarytext.appendLine("%s hashes to process after filtering through hashcheck database for present results" % len(hpf.dictset))

    # nsrlqueue will contain initial hashes as input into VTCHECKERMaster for processing
    # nsrlFilterDaemon will filter through this for NSRL hits, and pass on non-hits to next queue
    logger.debug("Generating first queue for processing")
    queues['nsrlqueue'] = Queue()
    for hashhexstring in hpf.dictset.iterkeys():
        queues['nsrlqueue'].put(hashhexstring)

    logger.debug("Hashlist has %s items for processing" % queues['nsrlqueue'].qsize())
    summarytext.appendLine("hashlist has %s items for processing" % queues['nsrlqueue'].qsize())

    # hashqueryqueue will contain only strings of hashes (md5/sha1) for querying against VT
    queues['hashqueryqueue'] = Queue()

    # create as many VT query daemons as allowed (in CONFIG['VTCHECKER']['MAX_VT_DAEMONS']) and possible (number of VT API2 keys we have) and needed (number of hashes left to query)
    daemoncount = min(
        CONFIG['VTCHECKER']['MAX_VT_DAEMONS'], 
        len(CONFIG['VTCHECKER']['VT_API2_KEYS']), 
        queues['nsrlqueue'].qsize())

    # filter hashlist against NSRL, remove items that appear in NSRL, populate resultsqueue accordingly for these hashes
    logger.debug("VTCHECKERMaster NSRL queue has %s hashes" % queues['nsrlqueue'].qsize())
    thread = Thread(target=nsrlFilterDaemon, args=(queues['nsrlqueue'], queues['hashqueryqueue'], queues))
    thread.setDaemon(True)
    thread.start()
    if not CONFIG['VTCHECKER']['ENABLE_NSRL_FILTER']:
        summarytext.appendLine("NSRL filtering is NOT enabled.  All dedup'ed hashes will be queried against VT.")

    logger.debug("VTCHECKERMaster will be attempting to start %s vtDaemons, please wait %s seconds" % (daemoncount, daemoncount))
    if daemoncount > 0:

        # shallow copy of API keys for random selection later
        keypool = CONFIG['VTCHECKER']['VT_API2_KEYS'][:]

        for i in xrange(daemoncount):
            # randomly select a key from the list and create a daemon using that key
            key = random.choice(keypool)
            keypool.remove(key)
            logger.debug("VTCHECKERMaster creating vtDaemon thread using API key %s" % key)
            thread = Thread(target=vtDaemon, args=(key, queues['hashqueryqueue'], queues['resultsqueue'], queues))
            thread.setDaemon(True)
            thread.start()
            # backoff about 1 second before starting next daemon
            time.sleep(1)

    # summary counters
    nsrlhitcount = 0
    noreportcount = 0
    cleancount = 0
    dirtycount = 0
    resulttuples = []

    # monitor queues for processing and output status
    while True:

        logger.debug("VTCHECKERMaster monitoring status: nsrlqueue %s, hashqueryqueue %s, resultsqueue %s" % (queues['nsrlqueue'].qsize(), queues['hashqueryqueue'].qsize(), queues['resultsqueue'].qsize()))

        # grab next batch of result tuples from resultsqueue if available
        if queues['resultsqueue'].qsize() > 0:

            counter = 0
            while True:

                resulttuple = queues['resultsqueue'].get_nowait()
                resulttuples.append(resulttuple)

                # populate summary numbers
                if resulttuple[1] == -2:
                    nsrlhitcount += 1
                elif resulttuple[1] == -1:
                    noreportcount += 1
                elif resulttuple[1] == 0:
                    cleancount += 1
                else:
                    dirtycount += 1

                if CONFIG["VTCHECKER"]["RESULTS_TO_DB"]:

                    # and check hashcheck results in db for currently existing entry
                    whereValue = OrderedDict.fromkeys(['md5'])
                    whereValue['md5'] = resulttuple[0].lower()
                    if len(db.databaseSelect(dbhandle, 'vt_hash_check', 'results', OrderedDict.fromkeys(['md5']), whereValue, limit=1)) == 0:

                        # insert into database if new
                        logger.debug("VTCHECKERMaster inserting hashcheck results (%s,%s)" % (resulttuple[0], resulttuple[1]))
                        dictValues = OrderedDict.fromkeys(['md5', 'hits'])
                        dictValues['md5'] = resulttuple[0]
                        dictValues['hits'] = resulttuple[1]
                        db.databaseInsert(dbhandle, 'vt_hash_check', 'results', dictValues)

                    else:

                        # otherwise do an update
                        logger.debug("VTCHECKERMaster updating hashcheck results (%s,%s)" % (resulttuple[0], resulttuple[1]))
                        setValue = OrderedDict.fromkeys(['hits'])
                        setValue['hits'] = resulttuple[1]
                        whereValue = OrderedDict.fromkeys(['md5'])
                        whereValue['md5'] = resulttuple[0]
                        db.databaseUpdate(dbhandle, 'vt_hash_check', 'results', setValue, whereValue)


                counter += 1
                queues['resultsqueue'].task_done()
                if queues['resultsqueue'].qsize() == 0:
                    logger.debug("VTCHECKERMaster: batch of %s results processed" % counter)
                    break

        # wait in between checks
        time.sleep(10)
        # stop when all queues have no unfinished_tasks
        if allQueuesCleared(queues):
            break

    # populate and write CSV results file
    if CONFIG["VTCHECKER"]["RESULTS_TO_CSV"]:
        if len(resulttuples) > 0:

            csvresultsfieldlist = ["scan_id", "sha1", "resource", "response_code", "scan_date", "permalink", "verbose_msg", "sha256", "positives", "total", "md5"]

            logger.debug("VTCHECKERMaster collecting headers for CSV result file")
            for resulttuple in resulttuples:
                # prep list of headers
                with open("%s/%s.txt" % (CONFIG['VTCHECKER']['VT_RESULT'], resulttuple[0]), 'rb') as f:
                    vtresult = json.load(f)
                    if 'scans' in vtresult:
                        for av in vtresult['scans'].iterkeys():
                            if av not in csvresultsfieldlist:
                                csvresultsfieldlist.append(av)

            # write only up to CSV_LINES_MAX per CSV file to allow applications to open

            # create file pointers and CSV writers+headers
            fp = []
            dw = []
            for i in xrange( (len(resulttuples)/CONFIG["VTCHECKER"]["CSV_LINES_MAX"]) + 1 ):
                fp.append(open(fullResultsDir + "../" + '%s_VTChecker-results%s.csv' % (timestamp, i), 'wb'))
                dw.append(csv.DictWriter(fp[-1], fieldnames=csvresultsfieldlist))
                dw[-1].writeheader()

            # write lines
            logger.debug("VTCHECKERMaster writing CSVs into %s parts" % len(fp))
            counter = 0
            for resulttuple in resulttuples:
                with open("%s/%s.txt" % (CONFIG['VTCHECKER']['VT_RESULT'], resulttuple[0]), 'rb') as f:
                    vtresult = json.load(f)

                    # fill in dictionary for AV items/keys under 'scans', and empty strings for missing keys
                    for key in csvresultsfieldlist:
                        if key not in vtresult:
                            if 'scans' in vtresult:
                                if key in vtresult['scans']:
                                    vtresult[key] = vtresult['scans'][key]['result']
                                else:
                                    vtresult[key] = ''
                            else:
                                vtresult[key] = ''
                    # remove 'scans' key for DictWriter to work properly
                    vtresult.pop('scans', None)

                    dw[ counter / CONFIG["VTCHECKER"]["CSV_LINES_MAX"] ].writerow(vtresult)
                    counter += 1

            # cleanup
            for f in fp:
                f.close()

        else:
            logger.debug("VTCHECKERMaster has no hash results to write")


    # prep, print, write out summary report
    summarytext.appendLine('Scanning completed at %s' % datetime.now())
    summarytext.appendLine('Total files processed: %s' % (nsrlhitcount + noreportcount + cleancount + dirtycount))
    summarytext.appendLine('Total files with NSRL hits: %s' % nsrlhitcount)
    summarytext.appendLine('Total files that have never been uploaded to VT before: %s' % noreportcount)
    summarytext.appendLine('Total files that are deemed clean using VT: %s' % cleancount)
    summarytext.appendLine('Total files with malicious content: %s' % dirtycount)
    summarytext.appendLine()
    summarytext.appendLine('MD5 and filepaths of files with malicious content:')

    logger.info("summary report (refer to summary.txt for malicious file hash+filepath listings)\n%s" % summarytext.getText())

    # populate dirty hashes and filepaths if they exist
    for resulttuple in resulttuples:
        if resulttuple[1] > 0:
            summaryline = '%s' % resulttuple[0]
            for filepath in hpf.dictset[resulttuple[0]]:
                summaryline += ',"%s"' % filepath
            summarytext.appendLine(summaryline)
    
    with open(fullResultsDir + "../" + "%s_VTChecker-summary.txt" % timestamp, 'wb') as f:
        f.write(summarytext.getText())

    logger.debug("Completed")



def main():

    #argument parsing
    parser = argparse.ArgumentParser(description="Parses an Encase files export or md5sum-generated file and looks through virustotal for results.")
    group = parser.add_mutually_exclusive_group(required=True)    
    group.add_argument("-e", "--encase", help="Encase export file, either .txt tab delimited or .csv are accepted.  Must contain the Hash Value and Full Path fields.")
    group.add_argument("-m", "--md5sum", help="md5sum-generated file.")
    args = parser.parse_args()
    
    #Initiate the dictionary to store Hash and Full Path
    hpf = HashFilePath()

    if args.encase:
        logger.debug('Reading Encase export file %s' % args.encase)
        with open(args.encase, 'rU') as f:
            reader = csv.DictReader(f)
            print reader.fieldnames
            if len(reader.fieldnames) == 1:
                f.seek(0)
                reader = csv.DictReader(f, dialect = csv.excel_tab)
                print reader.fieldnames
            counter = 0
            for row in reader:
                if 'Full Path' in row:
                    hpf.addHashFilePath(row['Hash Value'], row['Full Path'])
                else:
                    hpf.addHashFilePath(row['Hash Value'])
                counter += 1
                if CONFIG['VTCHECKER']['SHOW_LINE_COUNTER']:
                    print counter,
                    sys.stdout.flush()
                elif counter % 10000 == 0:
                    print ".",
                    sys.stdout.flush()
                if counter % 1000000 == 0:
                    logging.info("Read %s lines into %s deduped hashes" % (counter, len(hpf.dictset)))
            logging.info("Read %s lines into %s deduped hashes" % (counter, len(hpf.dictset)))

    if args.md5sum:
        logger.debug('Reading md5sum-generated file %s' % args.md5sum)
        with open(args.md5sum, 'rU') as f:
            counter = 0
            for line in f:
                # extract md5 and filepath thereafter
                match = re.match('^([0-9a-f]+)  (.*)$', line.strip())

                #Note that match.group(0) is the entire match, match.group(1) is the first parenthesized subgroup, match.group(2) is the 2nd parenthesized subgroup.          
                
                hpf.addHashFilePath(match.group(1), match.group(2))

                counter += 1
                if CONFIG['VTCHECKER']['SHOW_LINE_COUNTER']:
                    print counter,
                    sys.stdout.flush()
                elif counter % 10000 == 0:
                    print ".",
                    sys.stdout.flush()
                if counter % 1000000 == 0:
                    logging.info("Read %s lines into %s deduped hashes" % (counter, len(hpf.dictset)))
            logging.info("Read %s lines into %s deduped hashes" % (counter, len(hpf.dictset)))

    
    logger.debug('Calling VTCHECKERMaster with %s items in hashlist' % len(hpf.dictset))
    VTCHECKERMaster(hpf)



if __name__ == '__main__':
    main()

