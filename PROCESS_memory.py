#!/usr/bin/python -tt

__author__ = "ZF"
__description__ = 'To run selective volatility plugins to process memory dump'

import subprocess
import sys
import datetime
import time
import getopt
import os
import argparse

import logging
logger = logging.getLogger('root')

def processMemory(rawMemoryFilePath):


    #Path to vol.py binary
    #VOLATILITY_PATH = "/usr/bin/vol.py"
    VOLATILITY_PATH = "/opt/volatility/vol.py"

    #Profiles supported by above version of volatility
    SUPPORTED_WINDOWS_PROFILES = [
    "VistaSP0x64",
    "VistaSP0x86",
    "VistaSP1x64",
    "VistaSP1x86",
    "VistaSP2x64",
    "VistaSP2x86",
    "Win10x64",
    "Win10x86",
    "Win2003SP0x86",
    "Win2003SP1x64",
    "Win2003SP1x86",
    "Win2003SP2x64",
    "Win2003SP2x86",
    "Win2008R2SP0x64",
    "Win2008R2SP1x64",
    "Win2008SP1x64",
    "Win2008SP1x86",
    "Win2008SP2x64",
    "Win2008SP2x86",
    "Win2012R2x64",
    "Win2012x64",
    "Win7SP0x64",
    "Win7SP0x86",
    "Win7SP1x64",
    "Win7SP1x86",
    "Win8SP0x64",
    "Win8SP0x86",
    "Win8SP1x64",
    "Win8SP1x86",
    "WinXPSP1x64",
    "WinXPSP2x64",
    "WinXPSP2x86",
    "WinXPSP3x86"]


    logger.info(str(rawMemoryFilePath))

    unprocessedlist = []
    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(rawMemoryFilePath):
        path = root.split('\\')        
        for filename in files:
            #Queueing all triage output files for processing. Once processed, they are removed
            if filename.endswith(('.raw')):
                if filename not in unprocessedlist:
                    unprocessedlist.append(os.path.join(root,filename))

    logger.debug("This is the full list " + str(unprocessedlist))
    for memDumpFile in unprocessedlist:

        
        #Running imageinfo to get Windows profile automatically. Assuming last profile is the correct one.
        #It would be faster to get the profile from triage info based on the hostname
        
        log_command = 'python ' + VOLATILITY_PATH + ' imageinfo -f ' + '"' + memDumpFile + '"'
        logger.info(log_command)     
        
        #COMMENTED OUT TO SPEED UP TESTING!
        proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
        with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-imageinfo.txt', 'w') as file:
            for line in proc.stdout:
                file.write(line)
                if "Suggested Profile" in line:
                    profile = line.split()[3]
                    profile = profile.rstrip(',')
                    logger.info("The identified profile is " + profile)
                    if not profile in SUPPORTED_WINDOWS_PROFILES:
                        logger.error("The identified profile of " + profile + " is NOT supported")
                        sys.exit()
            #ZFZFTOD: Should we save this to another csv file? Or save to database? 
            logger.info("The identified profile is " + profile)
        
        # profile = "Win7SP0x86"

        #ZFZFTODO: Verify if windows 8 is accurate
        #For Windows 8, imageinfo is NOT accurate. Run kdbgscan first and pass the virtual address of KdCopyDataBlock rather than the address of the kdbg when running scans
        # E.g vol.py -f memory.dmp --profile=Win8SP1x64 --kdbg=0xf802b65e66d8 pslist
        # SRC: http://www.brimorlabsblog.com/2014/08/analysis-of-windows-8-memory-dump-with.html

        #If OS profile is Win 8, run kdbgscan and extract KdCopyDataBlock value
        # if profile == "Win8SP0x64":
        #     logger.debug("running kdbgscan")
        #     log_command = 'python ' + VOLATILITY_PATH + ' -f ' + rawMemoryFilePath + ' kdbgscan'
        #     logging.write( '\n'+ (str(datetime.datetime.now()) + " : " + log_command + '\n') )
        #     proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
        #     line_count = 0
        #     profile_line = 0
        #     for line in proc.stdout:
        #         if "AS Win8SP0x64" in line:
        #             profile_line = line_count
        #         #Assuming that the line "KdCopyDataBlock (V) : xxx" is always 3 lines after "Instantiating KDBG using: Kernel AS Win8SP0x64"
        #         if line_count == profile_line + 3 and "KdCopyDataBlock" in line:
        #             KdCopyDataBlock = line.split()[3]
        #             profile = "Win8SP0x64 --kdbg=" + KdCopyDataBlock
        #         line_count += 1


        #=================================================================================
        #Detecting Rogue Processes : Direct Kernel Object Manipulation
        #Checking linked list for missing entries: pslist psscan thrdproc pspcid csrss session deskthrd      

        #Whitelisted processes. These would not show up rogue processes  
        whitelist_psxview = ['lsass.exe',
                             'services.exe',
                             'lsm.exe',
                             'svchost.exe',
                             'System',
                             'csrss.exe',
                             'cmd.exe',
                             'csrss.exe',
                             'smss.exe',
                             'HOSTNAME.EXE']
        
        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' psxview --profile=' + profile
        logger.info(log_command) 
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-psxview.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)
                    if "False" in line:
                        process_name = line.split()[1]
                        if not process_name in whitelist_psxview:
                            pid = line.split()[2]                  
                            logger.info("MEMORY - Possible DKOM Detected: " + process_name + " " + pid)
                            #ZFZFTOD: Should we save this to another csv file? Or save to database? 
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running psxview due to " + str(e))
            pass


        #Ensuring that smss is the first process created.
        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' pslist --profile=' + profile
        logger.info(log_command)
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-pslist.txt', 'w') as file:        
                line_count = 0
                firstCachedLine = ""
                for line in proc.stdout:
                    file.write(line)
                    #Start counting lines after the title line
                    if "Offset" in line:
                        firstCachedLine = line
                    if "-----" in line and firstCachedLine:
                        #pslist header detected. Resetting process instantiating count.
                        firstCachedLine = ""
                        line_count = 0
                    #Assuming that the formatting for pslist does NOT change and smss.exe is always the 2nd process created. First one is "System"
                    if "smss.exe" in line and not line_count == 2:
                        #ZFZFTOD: Should we save this to another csv file? Or save to database? 
                        logger.info("MEMORY - Possible DKOM Detected: smss.exe is not the 2nd process to be instantiated! It is instantiated at " + str(line_count))

                    line_count += 1
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running pslist due to " + str(e))
            pass
                


        #=================================================================================
        #Detecting Rogue Processes : Legitimate Parent-Child Relationship
        
        #Initializing variables        
        svchost_parent = []
        csrss_parent = []
        service_pid = 0
        wininit_parent = 0
        winlogon_parent = 0

        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' pstree --profile=' + profile
        logger.info(log_command) 
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-pstree.txt', 'w') as file:        
                for line in proc.stdout:
                    file.write(line)
                    temp_process_name = line.split()[0]
                    temp_pid = line.split()[1]
                    temp_ppid = line.split()[2]
                    if "." == temp_process_name or ".." in temp_process_name:
                        temp_process_name = line.split()[1]
                        temp_pid = line.split()[2]
                        temp_ppid = line.split()[3]

                    if "services.exe" in temp_process_name:
                        service_pid = temp_pid

                    if "svchost.exe" in temp_process_name:
                        svchost_parent.append(temp_ppid)

                    if "wininit.exe" in temp_process_name:
                        wininit_parent = temp_ppid

                    if "winlogon.exe" in temp_process_name:
                        winlogon_parent = temp_ppid

                    if "csrss.exe" in temp_process_name:
                        csrss_parent.append(temp_ppid)
            #Checking if wininit.exe and csrss.exe have the same parent
            if wininit_parent not in csrss_parent:        
                logger.info("MEMORY - Possible Rogue Process detected: wininit.exe and csrss.exe does not have the same parent!")

            #Checking if winlogon.exe and subsequent csrss.exe have the same parent
            if winlogon_parent not in csrss_parent:        
                logger.info("MEMORY - Possible Rogue Process detected: winlogon.exe and csrss.exe does not have the same parent!")

            #Checking for svchost.exe not having services.exe as parent
            for i in svchost_parent:
                if not i == service_pid:
                    logger.info("MEMORY - Possible Rogue Process detected: Check the following svchost.exe with the pid : " + i)

        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running pstree due to " + str(e))
            pass
        #=================================================================================
        #Detecting Suspicious Objects : Search Order Hijacking - Path Modification
        
        #ZFZFTODO: Compare this envar with triage path!

        #Whitelisted path. These would not show up as envars anomalies
        whitelist_path = ["C:\Windows\system32",
                      "C:\Windows",
                      "C:\Windows\System32\Wbem",
                      "C:\Windows\System32\WindowsPowerShell\\v1.0\\",
                      "C:\Program Files (x86)\Skype\Phone",
                      "C:\Program Files\Common Files\Microsoft Shared\Windows Live",
                      "C:\Program Files\Intel\Intel(R) Management Engine Components\DAL",
                      "C:\Program Files\Intel\Intel(R) Management Engine Components\IPT",
                      "C:\Program Files\Windows Live\Shared"
                      ]

        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' envars --profile=' + profile
        logger.info(log_command) 
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-envars.txt', 'w') as file:        
                for line in proc.stdout:
                    file.write(line)

                    temp_process_name = line.split()[1]
                    temp_variable=line.split()[3]

                    if temp_process_name == "csrss.exe" and "Path" == temp_variable:
                        temp_path = line.split('Path', 1)[1]
                        itemized_path = temp_path.split(';')
                        #to track matches against whitelisted paths
                        temp_match_found = 0
                        for j in itemized_path:
                            for i in whitelist_path:
                                if i.lower() == j.lstrip().lower():
                                    temp_match_found += 1
                            if temp_match_found == 0:
                                logger.info("MEMORY - Possible Search Order Hijacking detected: Check the env path : " + j.lstrip())
                            #reset whitelist match count                                         
                            temp_match_found = 0

        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running envars due to " + str(e))
            pass
        
        #=================================================================================
        #Detecting Suspicious Objects : Search Order Hijacking - DLL Loaded path
        false_positive_dll_path = 0
        legit_dll_path = "C:\Windows\System32"
        whitelist_dll_path = ["C:\Windows",
                              "C:\Program Files\VMware\VMware Tools",
                              "C:\ProgramData\Microsoft\Windows Defender",
                              "C:\Program Files\Common Files\VMware\Drivers",
                              "C:\Program Files\Common Files\microsoft shared",
                              "C:\Program Files\Internet Explorer\ieproxy.dll",
                              "C:\Users\user\Documents\NotMyFault\\x86\NotMyfault.exe"]
        
        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' dlllist --profile=' + profile
        logger.info(log_command) 
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-dlllist.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)

                    if "Command line" in line:
                        if "C:" in line:
                            if not legit_dll_path.lower() in line.lower():
                                for i in whitelist_dll_path:
                                    if i.lower() in line.lower():
                                        false_positive_dll_path += 1
                                if false_positive_dll_path > 0:
                                    false_positive_dll_path = 0
                                else:                            
                                    logger.info("MEMORY - Possible Search Order Hijacking detected: Check the DLL Location : " + line.split('line :',1)[1])
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running dlllist due to " + str(e))
            pass


        #=================================================================================
        #Detecting Suspicious Objects : List down Remotely Mapped Drives

        whitelist_smb_share = ["DC\memdumpcollection"]

        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' handles -t File --profile=' + profile
        logger.info(log_command) 
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-handles-File.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)            
                    if "\Device\Mup\;" in line:
                        for i in whitelist_smb_share:
                            if i.lower() not in line.lower():
                                logger.info("MEMORY - Possible Suspicious Object detected: Check if the following smb network share is legitimate : " + line)
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running handles -t File due to " + str(e))
            pass
        #=================================================================================
        #Detecting Suspicious Network Artifacts
        sockscan_result = {}
        pid_match = 0
        
        #Socket plugin only works for WinXP
        if "WinXP" in profile:
            
            log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' sockets --profile=' + profile
            logger.info(log_command) 
            try:
                proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
                with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-sockets.txt', 'w') as file:
                    for line in proc.stdout:
                        file.write(line)                
                        if not "PID" in line:
                            if not "---" in line:
                                #Saving sockets result for comparison with sockscan
                                temp_pid = line.split()[1]
                                temp_port = line.split()[2]
                                sockscan_result[temp_pid] = temp_port
            except (ValueError,IndexError) as e:
                logger.error("ERROR SystemInfo: Problem running sockets due to " + str(e))
                pass

            log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' sockscan --profile=' + profile
            logger.info(log_command)
            try:
                proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
                with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-sockscan.txt', 'w') as file:
                    for line in proc.stdout:
                        file.write(line)             
                        if not "PID" in line:
                            if not "---" in line:
                                temp_pid = line.split()[1]
                                temp_port = line.split()[2]
                                for key,var in sockscan_result.items():
                                    if temp_pid == key and temp_port == var:
                                        pid_match += 1
                                if pid_match > 0:
                                    pid_match = 0
                                else:                        
                                    logger.info("MEMORY - Possible Suspicious Network Artifacts DKOM detected: Check the following hidden network connection : " + line)
            except (ValueError,IndexError) as e:
                logger.error("ERROR SystemInfo: Problem running sockets due to " + str(e))
                pass

        #For non-WinXP
        else:
            #Run netscan for the rest of the OS and save the result. 
            #ZFZFTODO: Cross check this result with triage!!!
            log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' netscan --profile=' + profile        
            logger.info(log_command)
            try:
                proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
                with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-netscan.txt', 'w') as file:
                    for line in proc.stdout:
                        file.write(line)            
            except (ValueError,IndexError) as e:
                logger.error("ERROR SystemInfo: Problem running netscan due to " + str(e))
                pass
        #=================================================================================
        #Detecting Code Injection
        
        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' ldrmodules --profile=' + profile
        logger.info(log_command)
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-ldrmodules.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)            
                    inload_status = line.split()[3]
                    ininit_status = line.split()[4]
                    inmem_status = line.split()[5]
                    mapped_path = line.split()[-1]
                    if inload_status == "True" and ininit_status == "True" and inmem_status == "True":
                        if mapped_path == "False":                    
                            logger.info("MEMORY - Possible Code injection detected: Check the following : " + line)

        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running ldrmodules due to " + str(e))
            pass

        #=================================================================================
        #Detecting Rootkits - Listing Autoruns 

        whitelist_runkey_values = ["C:\Program Files\VMware\VMware Tools",
                                   "%SYSTEMROOT%\SYSTEM32\WerFault.exe"]

        #printkey for Win10 is known to fail
        if "Win10" not in profile:
            log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' printkey -K "Microsoft\Windows\CurrentVersion\Run" --profile=' + profile
            logger.info(log_command)
            try:
                proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
                with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-printkeyRun.txt', 'w') as file:
                    for line in proc.stdout:
                        file.write(line)        
                        if "REG_" in line:
                            for i in whitelist_runkey_values:
                                if i.lower() not in line.lower():
                                    logger.info("MEMORY - Possible Suspicious Run key detected: Check if the following Autorun is legitimate : " + line)                                              
            except (ValueError,IndexError) as e:
                logger.error("ERROR SystemInfo: Problem running printkeyRun due to " + str(e))
                pass
            log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' printkey -K "Microsoft\Windows\CurrentVersion\Runonce" --profile=' + profile        
            logger.info(log_command)
            try:
                proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
                with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-printkeyRunonce.txt', 'w') as file:
                    for line in proc.stdout:
                        file.write(line)                        
                        if "REG_" in line:
                            for i in whitelist_runkey_values:
                                if i.lower() not in line.lower():
                                    logger.info("MEMORY - Possible Suspicious Runonce key detected: Check if the following Autorun is legitimate : " + line.split('(S)',1)[1])                           

            except (ValueError,IndexError) as e:
                logger.error("ERROR SystemInfo: Problem running printkeyRunonce due to " + str(e))
                pass

        #=================================================================================
        #Detecting Rootkits - svcscan 
        #ZFZFTODO: BrokenPipe detected for Windows 8. Need to do the try-except for all vol modules!
        whitelist_service_path = ["C:\Windows\system32",
                                  "\driver\\",
                                  "\\filesystem\\",
                                  "c:\windows\servicing\\trustedinstaller.exe",
                                  "c:\program files\\vmware\\vmware tools"]


        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' svcscan --profile=' + profile
        logger.info(log_command)
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-svcscan.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)                      
                    if "Process ID:" in line:
                        temp_pid = line.split()[-1]
                    if "Service State:" in line:
                        temp_service_state = line.split()[-1]
                    if "Binary Path" in line:
                        temp_binary_path = line
                        if temp_service_state == "SERVICE_RUNNING":
                            for i in whitelist_service_path:
                                if i.lower() not in temp_binary_path.lower():
                                    logger.info("MEMORY - Possible Suspicious svc detected: " + line)                            
                                    # logger.info(line.split('line :',1)[1])
                                    # logger.info(temp_binary_path.split('path: ',1)[1].lower())
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running svcscan due to " + str(e))
            pass
                                    
        #=================================================================================
        #Detecting Rootkits - Interrupt Descriptor Table Hooking

        whitelist_idt_entries = ["hal.dll"]

        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' idt --profile=' + profile
        logger.info(log_command)
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-idt.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)    

                    #ZFZFTODO: High FP rate due to negative comparison which includes error messages! Need a single true select statement to weed out FP!
                    if not "Module" in line:
                        if not "---" in line:
                            if not "ntoskrnl.exe" in line:
                                if not line.split()[-1] == "UNKNOWN":
                                    for i in whitelist_idt_entries:
                                        if i.lower() not in line.lower():
                                            logger.info("MEMORY - Possible IDT Hooking detected: " + line)
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running idt due to " + str(e))
            pass                            
        #=================================================================================
        #Detecting Rootkits - ssdt

        whitelist_ssdt_entries = [""]

        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' ssdt --profile=' + profile
        logger.info(log_command)
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-ssdt.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)

                    if "owned by" in line:
                        temp_module = line.split()[-1]
                        if not temp_module == "ntoskrnl.exe":
                            if not temp_module == "win32k.sys":
                                for i in whitelist_ssdt_entries:
                                    if i.lower() not in temp_module.lower():
                                        logger.info("MEMORY - Possible Suspicious ssdt detected: " + line)    
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running ssdt due to " + str(e))
            pass                
        #=================================================================================
        #Detecting Rootkits - Driver Hooking
        
        whitelist_driver_entries = [ "C:\Program Files\VMware\VMware Tools",
                                     "C:\Program Files\Common Files\VMware\Drivers",
                                     "C:\Windows\system32\drivers\myfault.sys"]

        #This modules_list is used for modscan and unloadedmodules comparison
        modules_list = []
                            
        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' modules --profile=' + profile
        logger.info(log_command)

        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-modules.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)

                    if not "Offset" in line:
                        if not "---" in line:
                            temp_module = line.split()[1]                    
                            modules_list.append(temp_module)
                            if not "SystemRoot\system32".lower() in line.lower():
                                for i in whitelist_driver_entries:
                                    if i.lower() not in line.lower():
                                        logger.info("MEMORY - Possible Suspicious drivers not loaded from system32 detected : " + line)    
                                    
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running modules due to " + str(e))
            pass

        #=================================================================================
        #Detecting Rootkits - Driver Hooking 2
        
        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' modscan --profile=' + profile
        logger.info(log_command)
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-modscan.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)

                    if not "Offset" in line:
                        if not "---" in line:
                            temp_module = line.split()[1]
                            if not temp_module in modules_list:
                                logger.info("MEMORY - Possible Suspicious modules detected : " + line)  
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running modscan due to " + str(e))
            pass
       
        #=================================================================================
        #Detecting Rootkits - Driver Hooking 3
        
        whitelist_unloaded_module = ["agp440.sys"]

        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' unloadedmodules --profile=' + profile
        logger.info(log_command)
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-unloadedmodules.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)

                    if not "EndAddress" in line:
                        if not "---" in line:
                            temp_module = line.split()[0]
                            if not temp_module in modules_list:
                                if not temp_module in whitelist_unloaded_module:
                                    logger.info("MEMORY - Possible Suspicious unloaded modules detected : " + line)
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running unloadedmodules due to " + str(e))
            pass
        
        #=================================================================================
        #Detecting Rootkits - Driver IRP

        whitelist_driverirp = ["HIDCLASS.SYS",
                               "Unknown",
                               "Wdf01000.sys",
                               "HdAudio.sys",
                               "ks.sys",
                               "portcls.sys",
                               "VIDEOPRT.SYS",
                               "ndis.sys",
                               "wanarp.sys",
                               "dxgkrnl.sys",
                               "USBPORT.SYS",
                               "PCIIDEX.SYS",
                               "CLASSPNP.SYS",
                               "ataport.SYS",
                               "storport.sys",
                               "hal.dll"]


        log_command = 'python ' + VOLATILITY_PATH + ' -f ' + '"' + memDumpFile + '"' + ' driverirp --profile=' + profile
        logger.info(log_command)
        try:
            proc = subprocess.Popen(log_command, stdout=subprocess.PIPE, shell=True)
            with open(os.path.dirname(memDumpFile) + "/" + datetime.datetime.now().strftime('%Y%m%d_%H%M%S-') + '-memory-driverirp.txt', 'w') as file:
                for line in proc.stdout:
                    file.write(line)

                    if "DriverName" in line:
                        temp_drivername = line.split()[-1].lower()
                    if "IRP_MJ" in line:
                        temp_device_driver = line.split()[-1].lower()
                        if not temp_drivername.lower() in temp_device_driver.lower():
                            if not "ntoskrnl" in temp_device_driver:
                                for i in whitelist_driverirp:
                                    if i.lower() not in temp_device_driver.lower():
                                        #ZFZFTODO: Too noisy, need to cut out the last column delimited by space/tab for the driver name and uniq it!
                                        logger.info("MEMORY - Possible Suspicious driverirp detected : " + line)
        except (ValueError,IndexError) as e:
            logger.error("ERROR SystemInfo: Problem running driverirp due to " + str(e))
            pass

def main():
  parser = argparse.ArgumentParser(description="Process windows based raw memory dump .raw files")    
  parser.add_argument('-d', dest='directory', type=str, required=True, help="Directory containing memory dump file")  
  args = parser.parse_args()

  processMemory(args.directory)

if __name__ == '__main__':
    main()