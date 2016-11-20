##############################################################################
#  README: REMEMBER TO "Set-ExecutionPolicy RemoteSigned" using an administrative powershell console!!!
#  Script: 
#    Date: 
# Version: 
#  Author: 
# Purpose: Parse and extract critical event IDs that may be helpful for an incident responder. 
#          Note that this is only for Windows 7 onwards. XP uses a different set of event IDs
#   Legal: Script provided "AS IS" without warranties or guarantees of any
#          kind.  USE AT YOUR OWN RISK.  Public domain, no rights reserved.
##############################################################################

<#
.SYNOPSIS
This is a simple Powershell script to explain how to create help
REMEMBER TO "Set-ExecutionPolicy RemoteSigned" using an administrative powershell console!!!


.DESCRIPTION
The script will parse all evtx logs in the directory passed to it as an argument.
It will extract all suspicious event IDs that may be helpful to the incident responder in resolving an incident.

.EXAMPLE
Process native logs on host machine.
./WindowsLogParser.ps1

Split parsed output. Note that you will have only 1 merged output.
./WindowsLogParser.ps1 d:\HOSTXYZ-WorkingCopy

Split parsed output by month. Note that you will have 2 copies of the same output - Merged, Month
./WindowsLogParser.ps1 d:\HOSTXYZ-WorkingCopy -month

Split parsed output by year. Note that you will have 2 copies of the same output - Merged, Year
./WindowsLogParser.ps1 d:\HOSTXYZ-WorkingCopy -year

Split parsed output by month AND year. Note that you will have 3 copies of the same output - Merged, Year, Month
./WindowsLogParser.ps1 d:\HOSTXYZ-WorkingCopy -year -month

.NOTES
Note that this is part of project MAGNETO, along with other useful tools.
For more information, refer to the below link.

.LINK
https://github.com/padfoot999/magneto

#>

#Following artifacts should be extracted to identify what happened
# 1 ) Event Info - (Event ID, Category, Description)
# 1 ) Date/Time - Provide a temporal picture of what happened (Timestamp)
# 2 ) Users Involved - User Attribution (User Account, Description)
# 3 ) Systems Involved - In a networked environment, we will very commonly find references to systems other than the
# host as resources are accessed remotely. Originally, only the Netbios name was recorded, making tracking and
# attribution much more difficult. In systems post-Windows 2000, IP addresses are now recorded within the event
# logs (when applicable). (Hostname, IP Address)
# 4 ) Resources Accessed - With nearly every resource considered an object, this provides very powerful
# auditing. E.g this can help identify attempted access to unauthorized files on a system. (Files, Folders, Printers, Services)

#To use named parameters, param keyword must be the first executable line in the script
#Default to C:\Windows\System32\winevt\Logs if not variables are passed in
param ([String] $logPath = "C:\Windows\System32\winevt\Logs",[switch] $year, [switch] $month)
Write-Host "logPath is "$logPath
$YYMMDD = Get-Date -format yyMMHHmmss
$scriptPath = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path 
Write-Host $scriptPath
$scriptName = (Get-Variable MyInvocation).Value.MyCommand.Name
Write-Host $scriptName

#Change working directory to directory with all the scripts. This path needs to be writable
Set-Location $scriptPath

$incidentLogFile = $scriptPath + "\IncidentLog-" + $YYMMDD + ".txt"
$mergedCsvFile = $scriptPath + "\AllLogs-" + $YYMMDD + ".csv"

function getEvent ($logFile, $eventID) 
{ 
    Try
    {	
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evtx"; ID=$eventID} -ErrorAction SilentlyContinue -ErrorVariable errVariable
        $YYMMDD_2 = Get-Date -format "yyyy-MM-dd HH:mm:ss"
        $YYMMDD_2 + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $logPath +"\" + $logFile + ".evtx ; ID=" + $eventID + "}" | out-file -append $incidentLogFile
        return $totalHits         
    }
    Catch
    {
        Write-Host "Error parsing "$logPath $logFile".evtx for events "$eventID
    }
}

function getEventOfInterest ($logFile, $eventID) 
{ 
    Try
    {	
        Write-Host "Log File is "$logFile
        Write-Host "Event IDs are "$eventID
	    $resultsOutputFile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $eventID + ".txt"
        $errorOutputFile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $eventID + "-ERROR.txt"
        Write-Host "Results Output File is "$resultsOutputFile
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evtx"; ID=$eventID} -ErrorAction SilentlyContinue -ErrorVariable errVariable
        $YYMMDD_2 = Get-Date -format "yyyy-MM-dd HH:mm:ss"
        $YYMMDD_2 + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $logPath +"\" + $logFile + ".evtx ; ID=" + $eventID + "}" | out-file -append $incidentLogFile
        Write-Host "Total Hits is/are "$totalHits.Count
        $hitsMessage = "Total Event Count is/are "+$totalHits.Count

        #If command executes with error, change output file
        if($errVariable) {                
			$resultsOutputFile = $errorOutputFile
        }
        #Output to CSV Files (Merged, Year, Month)
        $totalHits | Export-Csv -Append $mergedCsvFile -NoTypeInformation
        if($year.IsPresent -or $month.IsPresent) {splitFiles -totalHits $totalHits}
        #Output events to txt file
        $totalHits | Format-List | Out-File $resultsOutputFile
        #Output errors to txt file
        $errVariable | Format-List | out-file -append $resultsOutputFile    
        $hitsMessage | out-file -append $resultsOutputFile
        if([string]$eventID -eq "4625 4634 4647 4672") {parseResults -logfile $logFile -eventID $eventID -totalHits $totalHits}        
    }
    Catch
    {
        Write-Host "Error parsing "$logPath $logFile".evtx for events "$eventID
	    $error = $_	    
	    $error | Format-List | out-file $errorOutputFile
    }
}

function getEventOfInterestFromAll ($eventID) 
{ 
    Try
    {	
        Write-Host "Processing All Logs"
        Write-Host "Event IDs are "$eventID
	    $resultsOutputFile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $eventID + ".txt"
        $errorOutputFile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $eventID + "-ERROR.txt"
        $files = Get-ChildItem $logPath -Filter *.evtx | ForEach-Object {
            $content = $_.FullName
            $totalHits = Get-WinEvent -FilterHashtable @{Path=$content; ID=$eventID} -ErrorAction SilentlyContinue -ErrorVariable errVariable
            $YYMMDD_2 = Get-Date -format "yyyy-MM-dd HH:mm:ss"
            $YYMMDD_2 + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $content + " ; ID=" + $eventID + "}" | out-file -append $incidentLogFile
            Write-Host "Total Hits is/are "$totalHits.Count
            $hitsMessage = "Total Event Count is/are "+$totalHits.Count

            #If command executes with error, change output file
            if($errVariable) {                
			    $resultsOutputFile = $errorOutputFile
            }
            #Append hits, errors and hit count to file regardless of errors
            $totalHits | Export-Csv -Append $mergedCsvFile -NoTypeInformation
            if($year.IsPresent -or $month.IsPresent) {splitFiles -totalHits $totalHits}
            $errVariable | Format-List | out-file -append $resultsOutputFile    
            $hitsMessage | out-file -append $resultsOutputFile
        }    
    }
    Catch
    {
        Write-Host "Error parsing "$logPath $logFile".evtx for events "$eventID
	    $error = $_	    
	    $error | Format-List | out-file $errorOutputFile
    }
}

#Note: Ignores errors raised because of "Where-Object" condition 
function getEventOfInterestWithMsg ($logFile, $msg) 
{ 
    Try
    {	
        Write-Host "Log File is "$logFile
        Write-Host "Message to search is "$eventID
	    $resultsOutputFile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $msg + ".txt"
        $errorOutputFile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $msg + "-ERROR.txt"
        Write-Host "Results Output File is "$resultsOutputFile
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evtx"} -ErrorAction SilentlyContinue -ErrorVariable errVariable | Where-Object {$_.Message -like '*'+$msg+'*'}
        $YYMMDD_2 = Get-Date -format "yyyy-MM-dd HH:mm:ss"
        $YYMMDD_2 + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $logPath +"\" + $logFile + ".evtx} | Where-Object {$_.Message -like " + $msg +"}" | out-file -append $incidentLogFile
        Write-Host "Total Hits is/are "$totalHits.Count
        $hitsMessage = "Total Event Count is/are "+$totalHits.Count

        #Append hits, errors and hit count to file regardless of errors
        $totalHits | Export-Csv -Append $mergedCsvFile -NoTypeInformation
        if($year.IsPresent -or $month.IsPresent) {splitFiles -totalHits $totalHits}
        $totalHits | Format-List | Out-File $resultsOutputFile        
        $hitsMessage | out-file -append $resultsOutputFile 
    }
    Catch
    {
        Write-Host "Error parsing "$logPath $logFile".evtx for events "$eventID
	    $error = $_	    
	    $error | Format-List | out-file $errorOutputFile
    }
}

function getEventOfInterestWithLevel ($logFile, $lvl) 
{ 
    Try
    {	
        Write-Host "Log File is "$logFile
        Write-Host "Level to search is "$lvl
	    $resultsOutputFile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $lvl + ".txt"
        $errorOutputFile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $lvl + "-ERROR.txt"
        Write-Host "Results Output File is "$resultsOutputFile
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evtx"; Level=$lvl} -ErrorAction SilentlyContinue -ErrorVariable errVariable
        $YYMMDD_2 = Get-Date -format "yyyy-MM-dd HH:mm:ss"
        $YYMMDD_2 + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $logPath +"\" + $logFile + ".evtx; level=" + $lvl +"} | Measure-Object -Line" | out-file -append $incidentLogFile
        Write-Host "Total Hits is/are "$totalHits.Count
        $hitsMessage = "Total Event Count is/are "+$totalHits.Count

        #If command executes with error, change output file
        if($errVariable) {                
			$resultsOutputFile = $errorOutputFile
        }
        #Append hits, errors and hit count to file regardless of errors
        $totalHits | Export-Csv -Append $mergedCsvFile -NoTypeInformation
        if($year.IsPresent -or $month.IsPresent) {splitFiles -totalHits $totalHits}
        $totalHits | Format-List | Out-File $resultsOutputFile
        $errVariable | Format-List | out-file -append $resultsOutputFile  
        $hitsMessage | out-file -append $resultsOutputFile  
    }
    Catch
    {
        Write-Host "Error parsing "$logPath $logFile".evtx for events "$eventID
	    $error = $_	    
	    $error | Format-List | out-file $errorOutputFile
    }
}

function parseResults ($logFile, $eventID, $totalHits)
{
    Try
    {
        Write-Host "Parsing " $logFile
        Write-Host "Event IDs are "$eventID
        ForEach($event in $totalHits) {
            $timestamp = $event.TimeCreated.ToString()
            $eventXML = [xml]$event.ToXml()
            if([string]$eventID -eq "4625 4634 4647 4672") {
                $csvfile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $eventID + "(PARSED)" + ".csv"
                $logonType=$eventXML.Event.EventData.Data | where {$_.name -eq "LogonType"}
                $logonType = $logonType.InnerText
                $account = $eventXML.Event.EventData.Data | where {$_.name -eq "TargetUserName"}
                $account = $account.InnerText
                $eventID = $eventXML.Event.System.EventID
                $computer = $eventXML.Event.System.Computer
                $wrapper = New-Object PSObject -Property @{ LogonType = $logonType; Account = $account; Timestamp = $timestamp; EventID = $eventID; Computer = $computer}}
            else{ if([string]$eventID -eq "4625") {
                $csvfile = $scriptPath + "\EvidenceIdentifier-" + $YYMMDD + "-" + $logFile + "-" + $eventID + "-BruteForce Attempts" + ".csv"
                $workstation=$eventXML.Event.EventData.Data | where {$_.name -eq "WorkstationName"}
                $workstation = $logonType.InnerText
                $ipaddress= $eventXML.Event.EventData.Data | where {$_.name -eq "IpAddress"}
                $ipaddress = $ipaddress.InnerText
                $ipport= $eventXML.Event.EventData.Data | where {$_.name -eq "IpPort"}
                $ipport=$ipport.InnerText
                $wrapper = New-Object PSObject -Property @{ WorkstationName = $workstation; IPAddress = $ipaddress; IPPort = $ipport; Timestamp = $timestamp}}}
            Export-Csv -InputObject $wrapper -Append $csvfile -NoTypeInformation
        }
    }
    Catch
    {
        Write-Host "Error parsing "$logPath $logFile".evtx for events "$eventID
        $error = $_
        Write-Host $error
        
    }
}


function splitFiles($totalHits)
{
    ForEach($event in $totalHits) {
        $y = $event.TimeCreated.Year
        $m = $event.TimeCreated.Month
        if($year.IsPresent) {
            $outputFile = $scriptPath + "\" + $y + "Logs-" + $YYMMDD + ".csv"
            $event | Export-Csv -Append $outputFile -NoTypeInformation
        }
        if($month.IsPresent) {
            $outputFile = $scriptPath + "\" + $y + "-" + $m + "-Logs-" + $YYMMDD + ".csv"
            $event | Export-Csv -Append $outputFile -NoTypeInformation    
        }
    }
}

#ZFTODO: ADD WIN XP EQUIVALENT event IDs FOR COMPLETENESS. Can we install and use powershell on XP machines?

#Purpose: Detect metasploit psexec
#Description: Pull SYSTEM events 7030 (Track Errors) and 7045 (service creation)
getEventOfInterest -logfile "System"  -eventid 7030,7045

#Purpose: Unauthorized user account creation for use as a backdoor
#Description: Pull SECURITY events 4720 (user account created), 4722 (user account enabled), 4724 (attempt to reset password), 4738(user account changed)
getEventOfInterest -logfile "Security"  -eventid 4720,4722,4724,4738

#Purpose: Unauthorized user account creation for use as a backdoor: net localgroup administrators group /add
#Description: Pull SECURITY event 4732 (member added to security-enabled local group).
getEventOfInterest -logfile "Security"  -eventid 4732

#Purpose: Covering tracks using meterpreter: clearev
#Description: Pull SECURITY event 1102 (audit log was cleared) and SYSTEM event 104
getEventOfInterest -logfile "Security"  -eventid 1102
getEventOfInterest -logfile "System"  -eventid 104

#Purpose: Evidence of meterpreter running activity: run getgui -e
#Description: Pull SYSTEM event 1056 (creation of self signed SSL certificate)
getEventOfInterest -logfile "System"  -eventid 1056

#Purpose: Identifying USB Hardware insertion
#Description: Pull SYSTEM event 7045, 10000, 100001, 10100, 20001, 20002, 24576, 24577, 24579
getEventOfInterest -logfile "System"  -eventid 7045,10000,100001,10100,20001,20002,24576,24577,24579

#Purpose: Identifying changes in firewall rules
#Description: Pull FIREWALL event 2003 
getEventOfInterest -logfile "Microsoft-Windows-Windows Firewall with Advanced Security%4Firewall"  -eventid 2003

#Purpose: Tracking Account Usage
#Description: Pull SECURITY event 4624 (successful logon)
getEventOfInterest -logfile "Security"  -eventid 4624
#Note: Can be used to detect lateral movement if the logon type is network logon (Type 2)
#XP Equivalent: 528 540  

#Purpose: Tracking Bruteforce Password Attack
#Description: Pull SECURITY event 4625 (failed logon), 4634 (Log off), 4647(Log off), 4672 (Admin logon) 
getEventOfInterest -logfile "Security"  -eventid 4625,4634,4647,4672
# (DONE) ZFTODO: Parse and save the following info: Logon Type, Account, Timestamp, EventID, Computer 
#Information is in Column 1: Message, parseResults function is already written
#ZFTODO: Compute each logon and log off pair to compute the session time. Type2,10,11,12 sessions should be long. Type3,5 sessions are for scripts and should be short.
#Note: In Windows 8 onwards, Microsoft online account can be used to log in and they are Type 12. 
#Note: Windows does not reliably log 4634, especially for interactive logons, therefore we check for 4647 as well.
#Note: If a log off cannot be link to a log on, it may be indicative of a backdoor that logon via an exploit!
#Note: Logon Type 11 for cached credential is dangerous if found on a server as it could be exploited to harvest other accounts!
# (DONE) ZFTODO : Bruteforce password attempt should have alot of 4625 event. Check Network Information field for details about the logon (Workstation Name, Source Network Address, Source Port)
$totalHits = getEvent -logFile "Security"  -eventid 4625
parseResults -logFile "Security" -eventid 4625 -totalHits $totalHits
#XP Equivalent: 528-552

#Description: Pull SECURITY event 4800 (Lock Workstation), 4801 (Unlock Workstation)
getEventOfInterest -logfile "Security"  -eventid 4800,4801
#ZFTODO: Similarly compute session time

#Purpose: Tracking Remote Desktop Protocol
#Description: Pull SECURITY event 4778 (Session Connected/Reconnected), 4779(Session Disconnected), Used to detect RDP. 
# Possible FP is Windows "Fast User Switching" feature
getEventOfInterest -logfile "Security"  -eventid 4778,4779
#Note: Should see 4779 followed by a 4778 as only one interactive logon is permitted at a time
#Note: 4778 and 4624 should occur together, 4779 and 4647 should occur together
#XP Equivalent: 528 683 682

#Purpose: Detect Account Logons - NTLM/Kerberos bruteforce password attacks
#Description: Pull SECURITY event 4776 (NTLM Account Auth Success and Failure),
#4768 (Kerberos successful logon), 
#4769 (Kerberos successful authentication to a server resource such as file share), 
#4771 (Kerberos Pre-authentication failed) 
getEventOfInterest -logfile "Security"  -eventid 4776,4768,4769,4771
#Note: This is Account Logon Event and not Logon Event. Logon Events are activities that happen on actual system and event logs are hence stored locally.
#Account Logon Event are 3rd party authorization of credentials that are provided DURING THE LOGON event. These are stored at the DC!!!
#ZFTODO: Correlate these with the host LOGON events on the client machines
#ZFTODO: If Account Logon event (4776) EXIST on a client machine along with the logon event (4624 Type 3), 
#it means a local account (rogue) is used for logon!!!
#ZFTODO: 4776 and 4771 event description contain reason codes for the failure and can be used to detect password guessing attacks
#XP Equivalent: 672, 673, 675, 680

#Purpose: Tracking remote connections
#Description: Pull Microsoft-Windows-RemoteDesktopServices-RdpCoreTS event 131 (RDP Session Initiation), 98 (Successful TCP RDP).
getEventOfInterest -logfile "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational"  -eventid 131,98 
#Note that this log records attempted RDP sessions as well but SECURITY event 4778/4779 only log successful events
#ZFTODO: Correlate with SECURITY event 4778/4779

#Description: Pull Microsoft-Windows-TaskSchedule event 119 (Account Logons)
getEventOfInterest -logfile "Microsoft-Windows-TaskScheduler%4Operational"  -eventid 119
#ZFTODO: Scheduled tasks are often used as malware persistence mechanism. Correlate with event 4624 and identify isolated 119 events

#Purpose: Identify user who have attempted to access protected files, folder or reg keys
#Description: Pull SECURITY event 4656 (Handle to a resource is requested by a user),
#4663(Success for 4656),
#4660(Audit resources deleted, either 4656 or 4663 deleted)
getEventOfInterest -logfile "Security"  -eventid 4656,4663,4660 
#Note: These events identify which users have attempted to access a protected file, folder, registry key, or other audited resource
#Note: Its a good security practice to "audit write access" to Windows and System32 folders. These should only change on Windows updates.
#Note: These logs are only present if "Audit File System" and "Audit Handle Manipulation" within the Object Access audit category are set to audit Success/Failure
#Note: This can be used to identify insider using scripts to copy restricted shared network contents!
#XP Equivalent: 560 564 567

#Purpose: Application Installation
#Description: Pull APPLICATION event 1033 (Installation completed, can be success or failure)
#1034 (Application removal completed)
#11707 (Installation completed successfully)
#11708 (Installation operation failed)
#11724 (Application removal completed successfully)
getEventOfInterest -logfile "Application"  -eventid 1033,1034,11707,11708,11724
#Need to search for Events with Source as "MsiInstaller" Any overlap?
#ZFTODO: Search for abnormal times and dates of installation (or within incident date)
#Note: If Security Identifier (SID) is represented in the User column, it means that the account has been deleted!
#XP Equivalent: Same

#Purpose: Malware Execution
#Description: Pull SECURITY event 4688 (New process created) and check its exceutable path
getEventOfInterest -logfile "Security"  -eventid 4688
#ZFTODO: Search SYSTEM and APPLICATION for Warning and Error events from anti virus or other security applications such as the LSASS from Source: Winlogon, following by a reboot or crash!
#XP Equivalent: 592

#Purpose: Command Line / Powershell Execution
#Description: Pull SECURITY event 4688 (Process creation event)
#Note: Only available in server 2012R2 and is NOT enabled by default.
#Contains account used, process info and FULL command line information!
#XP Equivalent: None

#Purpose: Suspicious services running at boot time / started or stopped during incident period
#Description: Pull SYSTEM event 7034 (service crashed unexpectedly)
#7035 (Service sent a start/stop control)
#7036 (Service started/stopped)
#7040 (Service start type changed)
#7045 (Service installed on system FOR THE FIRST TIME) Only on Win2008R2+ *** VERY USEFUL
getEventOfInterest -logfile "System"  -eventid 7034,7035,7036,7040,7045
#SECURITY event 4697 (Service installed on system). Only available if "Audit Security System Extension" is enabled
getEventOfInterest -logfile "Security"  -eventid 4697
#ZFTODO: Correlate 4697 with 7045 for a comprehensive picture
#Note: Services should rarely use a user account to run automatically
#Note: Service Name with GUID or other random name should be examined
#XP Equivalent: 7034 7035 7036 7040

#Purpose: Timestomping
#Description: Pull SYSTEM event 1, 
#SECURITY event 4616. Contains Account Name. Only available if "Security State Change Auditing" is enabled
getEventOfInterest -logfile "Security"  -eventid 4616
#XP Equivalent: 520

#Purpose: USB, BYOB or other hardware devices plugged in previously
#Description: SYSTEM event 20001 (plug and play driver install attempted), shows only first time a device was plugged in
getEventOfInterest -logfile "System"  -eventid 20001
#SECURITY event 4663 (Attempt to access removable storage obj), identifies EVERY SINGLE TIME device was plugged in! Only available if "Audit Remvoable Storage" is enabled!
#SECURITY event 4656 (Failure to access removable storage obj), identifies EVERY SINGLE TIME device was plugged in!
getEventOfInterest -logfile "Security"  -eventid 4663,4656
#Account logged in can be identified from the field "Account Name"

#Purpose: Wireless Network Geolocation
#Description: Pull Microsoft-Windows-WLAN-Autoconfig/Operational event 11000 (Wireless network association started)
#8001 (Successful connection to wireles network)
#8002 (Failed conection to wireless network)
getEventOfInterest -logfile "Microsoft-Windows-WLAN-AutoConfig%4Operational"  -eventid 11000,8001,8002
#SYSTEM event 6100 (Network diagnostics)
getEventOfInterest -logfile "System"  -eventid 6100
#NOTE: The registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\ 
#keeps a record of the last connection. 8001 and 8002 keeps a record of ALL connections!
#Note the SSID and BSSID and refer to geolocation databases

#Purpose: Log Deletion
#Description: Pull 1102 from ALL LOGS!!! Once a log is cleared, event 1102 is inserted!
getEventOfInterestFromAll -eventID 1102
#Note: Administrator rights are required to clear logs. No selective deletion are available in windows logging.
#Note the user account when it happened!

#Description: Pull APPLOCKER event 8003 (audit mode exe/dll allowed to run), 8004 (audit mode script/msi allowed to run), 8006(enforce mode exe blocked), 8007(enforce mode script blocked)
getEventOfInterest -logfile "Microsoft-Windows-AppLocker%4EXE and DLL"  -eventid 8003,8004,8006,8007
#Description: Search for events containing the string "USB" in the file system.evtx:
getEventOfInterestWithMsg -logfile "System" -msg 'USB'
#Description: Pull all errors (level=2) from application.evtx and count the number of lines ('wc'-style):
getEventOfInterestWithLevel -logfile "Application" -lvl 2