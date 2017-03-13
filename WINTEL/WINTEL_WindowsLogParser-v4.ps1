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
./WindowsLogParser.ps1 -logPath d:\HOSTXYZ-WorkingCopy -project ARGON

Split parsed output by month. Note that you will have 2 copies of the same output - Merged, Month
./WindowsLogParser.ps1 -logPath d:\HOSTXYZ-WorkingCopy -project ARGON -month

Split parsed output by year. Note that you will have 2 copies of the same output - Merged, Year
./WindowsLogParser.ps1 -logPath d:\HOSTXYZ-WorkingCopy -project ARGON -year

Split parsed output by month AND year. Note that you will have 3 copies of the same output - Merged, Year, Month
./WindowsLogParser.ps1 -logPath d:\HOSTXYZ-WorkingCopy -project ARGON -year -month

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
param (
    [Parameter(Mandatory=$True,Position=1)][String] $logPath = "C:\Windows\System32\winevt\Logs",
    [Parameter(Mandatory=$True)][String] $project,
    [switch] $year, 
    [switch] $month
)
#Wintel Folder
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$parentPath = Split-Path -Parent $scriptPath
Write-Host $parentPath

$scriptName = (Get-Variable MyInvocation).Value.MyCommand.Name
Write-Host $scriptName

Set-Location $logPath
$imagename = Split-Path (Split-Path (Split-Path $logPath -Parent) -Parent) -Leaf

#Change working directory to directory with all the scripts. This path needs to be writable
$RESULTSDIR = $parentPath + "\Results\"
$PROJECTDIR = $parentPath + "\Results\" + $project
$IMAGEOUTPUTDIR = $parentPath + "\Results\" + $project + "\Logs-" + $imagename

if(!(Test-Path -Path $RESULTSDIR )){
    New-Item -ItemType directory -Path $RESULTSDIR
}
if(!(Test-Path -Path $PROJECTDIR )){
    New-Item -ItemType directory -Path $PROJECTDIR
}
if(!(Test-Path -Path $IMAGEOUTPUTDIR )){
    New-Item -ItemType directory -Path $IMAGEOUTPUTDIR
}

$incidentLogFile = $parentPath + "\Results\" + $project+ "\Logs-" + $imagename + "\IncidentLog.txt"
$mergedCsvFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\AllLogs.csv"
$eventCountFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EVENT DETAILS COUNT LOG.txt"

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
        $resultsOutputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EVENT COUNT LOG.txt"
        $errorOutputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename +"\ERROR LOG.txt"
        
        #Filter event logs for specific event IDs
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evtx"; ID=$eventID} -ErrorAction SilentlyContinue -ErrorVariable errVariable
        
        #Incident Log File Output
        $YYMMDD = Get-Date -format "yyyy-MM-dd HH:mm:ss"
        $YYMMDD + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $logPath +"\" + $logFile + ".evt ; ID=" + $eventID + "}" | out-file -append $incidentLogFile

        #If command executes with error, change output file
        if($errVariable) {                
			$resultsOutputFile = $errorOutputFile
        }
        Write-Host "Results Output File is "$resultsOutputFile
        
        #Output to CSV Files (Merged, Year, Month)
        $totalHits | Export-Csv -Append $mergedCsvFile -NoTypeInformation
        if($year.IsPresent -or $month.IsPresent) {splitFiles -totalHits $totalHits}
        
        $errVariable | Format-List | out-file -append $resultsOutputFile
        "Event Count Hits for " + $logFile + " is: " | out-file -append $resultsOutputFile    
        $totalHits | Group-Object -property id | select count, name | out-file -append $resultsOutputFile
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
        $resultsOutputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EVENT COUNT LOG.txt"
        $errorOutputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename +"\ERROR LOG.txt"
        
        $files = Get-ChildItem $logPath -Filter *.evtx | ForEach-Object {
            $content = $_.FullName
            $totalHits = Get-WinEvent -FilterHashtable @{Path=$content; ID=$eventID} -ErrorAction SilentlyContinue -ErrorVariable errVariable
            
            $YYMMDD = Get-Date -format "yyyy-MM-dd HH:mm:ss"
            $YYMMDD + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $content + " ; ID=" + $eventID + "}" | out-file -append $incidentLogFile
            
            #If command executes with error, change output file
            if($errVariable) {                
			    $resultsOutputFile = $errorOutputFile
            }
            Write-Host "Results Output File is "$resultsOutputFile
            
            #Append hits, errors and hit count to file regardless of errors
            $totalHits | Export-Csv -Append $mergedCsvFile -NoTypeInformation
            if($year.IsPresent -or $month.IsPresent) {splitFiles -totalHits $totalHits}
            
            $errVariable | Format-List | out-file -append $resultsOutputFile    
            $totalHits | Group-Object -property id | select count, name | out-file -append $resultsOutputFile
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
        $resultsOutputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EvidenceIdentifier-" + $logFile + "-" + $msg + ".txt"
        $errorOutputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename +"\EvidenceIdentifier-" + $logFile + "-" + $msg + "-ERROR.txt"
        Write-Host "Results Output File is "$resultsOutputFile
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evtx"} -ErrorAction SilentlyContinue -ErrorVariable errVariable | Where-Object {$_.Message -like '*'+$msg+'*'}
        $YYMMDD_2 = Get-Date -format "yyyy-MM-dd HH:mm:ss"
        $YYMMDD_2 + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $logPath +"\" + $logFile + ".evt} | Where-Object {$_.Message -like " + $msg +"}" | out-file -append $incidentLogFile
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
        $resultsOutputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EvidenceIdentifier-" + $logFile + "-" + $lvl + ".txt"
        $errorOutputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename +"\EvidenceIdentifier-" + $logFile + "-" + $lvl + "-ERROR.txt"
        Write-Host "Results Output File is "$resultsOutputFile
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evtx"; Level=$lvl} -ErrorAction SilentlyContinue -ErrorVariable errVariable
        $YYMMDD_2 = Get-Date -format "yyyy-MM-dd HH:mm:ss"
        $YYMMDD_2 + " > Executed Command: " + "Get-WinEvent -FilterHashtable @{Path=" + $logPath +"\" + $logFile + ".evt; level=" + $lvl +"} | Measure-Object -Line" | out-file -append $incidentLogFile
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
                $csvfile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EvidenceIdentifier-" + $logFile + "-" + $eventID + "(PARSED)" + ".csv"
                $logonType=$eventXML.Event.EventData.Data | where {$_.name -eq "LogonType"}
                $logonType = $logonType.InnerText
                $account = $eventXML.Event.EventData.Data | where {$_.name -eq "TargetUserName"}
                $account = $account.InnerText
                $id = $eventXML.Event.System.EventID
                $computer = $eventXML.Event.System.Computer
                $wrapper = New-Object PSObject -Property @{ LogonType = $logonType; Account = $account; Timestamp = $timestamp; EventID = $id; Computer = $computer}}
            else{ if([string]$eventID -eq "4625") {
                $csvfile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EvidenceIdentifier-" + $logFile + "-" + $eventID + "-BruteForce Attempts" + ".csv"
                $workstation=$eventXML.Event.EventData.Data | where {$_.name -eq "WorkstationName"}
                $workstation = $logonType.InnerText
                $ipaddress= $eventXML.Event.EventData.Data | where {$_.name -eq "IpAddress"}
                $ipaddress = $ipaddress.InnerText
                $ipport= $eventXML.Event.EventData.Data | where {$_.name -eq "IpPort"}
                $ipport=$ipport.InnerText
                $wrapper = New-Object PSObject -Property @{ WorkstationName = $workstation; IPAddress = $ipaddress; IPPort = $ipport; Timestamp = $timestamp}}
                else{
                    if ([string]$eventID -eq "4624 4625 4634") {
                        $csvfile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EvidenceIdentifier-" + $logFile + "-" + $eventID + "-Logon Accounts" + ".csv"
                        $id = $eventXML.Event.System.EventID
                        $workstation=$eventXML.Event.EventData.Data | where {$_.name -eq "WorkstationName"}
                        $workstation = $logonType.InnerText
                        $ipaddress= $eventXML.Event.EventData.Data | where {$_.name -eq "IpAddress"}
                        $ipaddress = $ipaddress.InnerText
                        $logontype= $eventXML.Event.EventData.Data | where {$_.name -eq "LogonType"}
                        $logontype=$logontype.InnerText
                        $subjectusersid = $eventXML.Event.EventData.Data | where {$_.name -eq "SubjectUserSid"}
                        $subjectusersid=$subjectusersid.InnerText
                        $subjectusername = $eventXML.Event.EventData.Data | where {$_.name -eq "SubjectUserName"}
                        $subjectusername=$subjectusername.InnerText
                        $subjectdomain = $eventXML.Event.EventData.Data | where {$_.name -eq "SubjectDomainName"}
                        $subjectdomain=$subjectdomain.InnerText
                        $targetusersid = $eventXML.Event.EventData.Data | where {$_.name -eq "TargetUserSid"}
                        $targetusersid=$targetusersid.InnerText
                        $targetusername = $eventXML.Event.EventData.Data | where {$_.name -eq "TargetUserName"}
                        $targetusername=$targetusername.InnerText
                        $targetdomain = $eventXML.Event.EventData.Data | where {$_.name -eq "TargetDomainName"}
                        $targetdomain=$targetdomain.InnerText
                        $processname = $eventXML.Event.EventData.Data | where {$_.name -eq "ProcessName"}
                        $processname=$processname.InnerText
                        $logonprocessname = $eventXML.Event.EventData.Data | where {$_.name -eq "LogonProcessName"}
                        $logonprocessname=$logonprocessname.InnerText
                        $wrapper = New-Object PSObject -Property @{ EventID = $id; SubjectUserSid = $subjectusersid; SubjectUserName = $subjectusername;
                         SubjectDomainName = $subjectdomain; TargetUserSid = $targetusersid; TargetUserName = $targetusername; TargetDomainName = $targetdomain;
                         ProcessName = $processname; LogonProcessName = $logonprocessname; 
                         WorkstationName = $workstation; IPAddress = $ipaddress; LogonType = $logontype; Timestamp = $timestamp}}
                }}
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
            $outputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\" + $y + "Logs-" + $YYMMDD + ".csv"
            $event | Export-Csv -Append $outputFile -NoTypeInformation
        }
        if($month.IsPresent) {
            $outputFile = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\" + $y + "-" + $m + "-Logs-" + $YYMMDD + ".csv"
            $event | Export-Csv -Append $outputFile -NoTypeInformation    
        }
    }
}

function outputMsg ($msg, [int[]]$eventid) {
    $outputMsg = $msg+ "`r`n"
    $count = $parentPath + "\Results\" + $project + "\Logs-" + $imagename + "\EVENT COUNT LOG.txt"
    $logfile = Get-Content $count
    $i=0
    $entry = New-Object PsObject
    do {
        $matches = $null
        if ($logfile[$i] -match "\s*(\d*)\s*(\d*)") {
            if (($matches[2] -ne '') -and ($matches[2] -ne $null)){
                $entry | add-member noteproperty -name $matches[2] -value $matches[1]
        }}
        $i++
    }
    while ($i -lt ($logfile.length))
    foreach ($event in $eventid) {
        if ($entry.$event -eq $null) {
            $outputMsg += "$event : 0`r`n"}
        else {
            $outputMsg += "$event : $($entry.$event)`r`n"
        }
    }
    $outputMsg += "`r`n"
    $outputMsg | Add-Content $eventCountFile
}

#ZFTODO: ADD WIN XP EQUIVALENT event IDs FOR COMPLETENESS. Can we install and use powershell on XP machines?

#Purpose: Unauthorized user account creation for use as a backdoor
#Description: Pull SECURITY events 4720 (user account created), 4722 (user account enabled), 4724 (attempt to reset password), 4738(user account changed)
#Purpose: Unauthorized user account creation for use as a backdoor: net localgroup administrators group /add
#Description: Pull SECURITY event 4732 (member added to security-enabled local group).
#Purpose: Tracking Account Usage
#Description: Pull SECURITY event 4624 (successful logon)
#Note: Can be used to detect lateral movement if the logon type is network logon (Type 2)
#XP Equivalent: 528 540
#Purpose: Tracking Bruteforce Password Attack
#Description: Pull SECURITY event 4625 (failed logon), 4634 (Log off), 4647(Log off), 4672 (Admin logon)
#Description: Pull SECURITY event 4800 (Lock Workstation), 4801 (Unlock Workstation)
#Purpose: Tracking Remote Desktop Protocol
#Description: Pull SECURITY event 4778 (Session Connected/Reconnected), 4779(Session Disconnected), Used to detect RDP. 
# Possible FP is Windows "Fast User Switching" feature
#Note: Should see 4779 followed by a 4778 as only one interactive logon is permitted at a time
#Note: 4778 and 4624 should occur together, 4779 and 4647 should occur together
#XP Equivalent: 528 683 682   
#Purpose: Detect Account Logons - NTLM/Kerberos bruteforce password attacks
#Description: Pull SECURITY event 4776 (NTLM Account Auth Success and Failure),
#4768 (Kerberos successful logon), 
#4769 (Kerberos successful authentication to a server resource such as file share), 
#4771 (Kerberos Pre-authentication failed) 
#Note: This is Account Logon Event and not Logon Event. Logon Events are activities that happen on actual system and event logs are hence stored locally.
#Account Logon Event are 3rd party authorization of credentials that are provided DURING THE LOGON event. These are stored at the DC!!!
#ZFTODO: Correlate these with the host LOGON events on the client machines
#ZFTODO: If Account Logon event (4776) EXIST on a client machine along with the logon event (4624 Type 3), 
#it means a local account (rogue) is used for logon!!!
#ZFTODO: 4776 and 4771 event description contain reason codes for the failure and can be used to detect password guessing attacks
#XP Equivalent: 672, 673, 675, 680
#Purpose: Identify user who have attempted to access protected files, folder or reg keys
#Description: Pull SECURITY event 4656 (Handle to a resource is requested by a user),
#4663(Success for 4656),
#4660(Audit resources deleted, either 4656 or 4663 deleted)
#Note: These events identify which users have attempted to access a protected file, folder, registry key, or other audited resource
#Note: Its a good security practice to "audit write access" to Windows and System32 folders. These should only change on Windows updates.
#Note: These logs are only present if "Audit File System" and "Audit Handle Manipulation" within the Object Access audit category are set to audit Success/Failure
#Note: This can be used to identify insider using scripts to copy restricted shared network contents!
#XP Equivalent: 560 564 567
#Purpose: Malware Execution
#Description: Pull SECURITY event 4688 (New process created) and check its exceutable path
#ZFTODO: Search SYSTEM and APPLICATION for Warning and Error events from anti virus or other security applications such as the LSASS from Source: Winlogon, following by a reboot or crash!
#XP Equivalent: 592
#Purpose: Timestomping
#Description: Pull SYSTEM event 1, 
#SECURITY event 4616. Contains Account Name. Only available if "Security State Change Auditing" is enabled
#XP Equivalent: 520
#SECURITY event 4663 (Attempt to access removable storage obj), identifies EVERY SINGLE TIME device was plugged in! Only available if "Audit Remvoable Storage" is enabled!
#SECURITY event 4656 (Failure to access removable storage obj), identifies EVERY SINGLE TIME device was plugged in!
#SECURITY event 4697 (Service installed on system). Only available if "Audit Security System Extension" is enabled
#ZFTODO: Correlate 4697 with 7045 for a comprehensive picture
#Note: Services should rarely use a user account to run automatically
#Note: Service Name with GUID or other random name should be examined
#XP Equivalent: 7034 7035 7036 7040
#Account logged in can be identified from the field "Account Name"
getEventOfInterest -logfile "Security" -eventid 1102,4616,4624,4625,4634,4647,4656,4660,4663,4672,4688,4697,4720
getEventOfInterest -logfile "Security" -eventid 4722,4724,4732,4738,4768,4769,4771,4776,4778,4779,4800,4801

#Purpose: Covering tracks using meterpreter: clearev
#Description: Pull SECURITY event 1102 (audit log was cleared) and SYSTEM event 104
#Purpose: Evidence of meterpreter running activity: run getgui -e
#Description: Pull SYSTEM event 1056 (creation of self signed SSL certificate)
#Purpose: Identifying USB Hardware insertion
#Description: Pull SYSTEM event 7045, 10000, 100001, 10100, 20001, 20002, 24576, 24577, 24579
#Purpose: Detect metasploit psexec
#Description: Pull SYSTEM events 7030 (Track Errors) and 7045 (service creation)
#SYSTEM event 6100 (Network diagnostics)
#Purpose: Suspicious services running at boot time / started or stopped during incident period
#Description: Pull SYSTEM event 7034 (service crashed unexpectedly)
#7035 (Service sent a start/stop control)
#7036 (Service started/stopped)
#7040 (Service start type changed)
#7045 (Service installed on system FOR THE FIRST TIME) Only on Win2008R2+ *** VERY USEFUL
#Purpose: USB, BYOB or other hardware devices plugged in previously
#Description: SYSTEM event 20001 (plug and play driver install attempted), shows only first time a device was plugged in
getEventOfInterest -logfile "System" -eventid 104,1056,7030,7045,10000,100001,10100,20001,20002,24576,24577,24579,6100,7034,7035,7036,7040

#Purpose: Identifying changes in firewall rules
#Description: Pull FIREWALL event 2003 
getEventOfInterest -logfile "Microsoft-Windows-Windows Firewall with Advanced Security%4Firewall" -eventid 2003

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
$totalHits = getEvent -logfile "Security"  -eventid 4624,4625,4634
parseResults -logFile "Security" -eventid 4624,4625,4634 -totalHits $totalHits
#XP Equivalent: 528-552

#Purpose: Tracking remote connections
#Description: Pull Microsoft-Windows-RemoteDesktopServices-RdpCoreTS event 131 (RDP Session Initiation), 98 (Successful TCP RDP).
getEventOfInterest -logfile "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational"  -eventid 131,98 
#Note that this log records attempted RDP sessions as well but SECURITY event 4778/4779 only log successful events
#ZFTODO: Correlate with SECURITY event 4778/4779

#Description: Pull Microsoft-Windows-TaskSchedule event 119 (Account Logons)
getEventOfInterest -logfile "Microsoft-Windows-TaskScheduler%4Operational"  -eventid 119
#ZFTODO: Scheduled tasks are often used as malware persistence mechanism. Correlate with event 4624 and identify isolated 119 events

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

#Purpose: Wireless Network Geolocation
#Description: Pull Microsoft-Windows-WLAN-Autoconfig/Operational event 11000 (Wireless network association started)
#8001 (Successful connection to wireles network)
#8002 (Failed conection to wireless network)
getEventOfInterest -logfile "Microsoft-Windows-WLAN-AutoConfig%4Operational"  -eventid 11000,8001,8002
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

outputMsg -msg "Detect metasploit exec" -eventid @(7030,7045)
outputMsg -msg "Unauthorized user account creation for use as a backdoor" -eventid @(4720,4722,4724,4738)
outputMsg -msg "Unauthorized user account creation for use as a backdoor: net localgroup administrators group /add" -eventid @(4732)
outputMsg -msg "Covering tracks using meterpreter: clearev" -eventid @(1102,104)
outputMsg -msg "Evidence of meterpreter running activity: run getgui -e" -eventid @(1056)
outputMsg -msg "Identifying USB Hardware insertion" -eventid @(7045,10000,100001,10100,20001,20002,24576,24577,24579)
outputMsg -msg "Identifying changes in firewall rules" -eventid @(2003)
outputMsg -msg "Tracking Account Usage" -eventid @(4624)
outputMsg -msg "Tracking Workstation Lock/Unlock" -eventid @(4800,4801)
outputMsg -msg "Tracking Bruteforce Password Attack" -eventid @(4625,4634,4647,4672)
outputMsg -msg "Tracking Remote Desktop Protocol" -eventid @(4778,4779)
outputMsg -msg "Detect Account Logons - NTLM/Kerberos bruteforce password attacks" -eventid @(4776,4768,4769,4771)
outputMsg -msg "Tracking remote connections" -eventid @(131,98)
outputMsg -msg "Tracking Scheduled tasks" -eventid @(119)
outputMsg -msg "Identify user who have attempted to access protected files, folder or reg keys" -eventid @(4656,4663,4660)
outputMsg -msg "Application Installation" -eventid @(1033,1034,11707,11708,11724)
outputMsg -msg "Malware Execution" -eventid @(4688)
outputMsg -msg "Command Line / Powershell Execution" -eventid @(4688)
outputMsg -msg "Suspicious services running at boot time / started or stopped during incident period" -eventid @(7034,7035,7036,7040,7045,4697)
outputMsg -msg "Timestomping" -eventid @(4616)
outputMsg -msg "USB, BYOD or other hardware devices plugged in previously" -eventid @(20001,4663,4656)
outputMsg -msg "Wireless Network Geolocation" -eventid @(11000,8001,8002,6100)
#Log deletion checks every single evtx file, event count not stored in EVENT COUNT FILE
#outputMsg -msg "Log Deletion" -eventid @(1102)