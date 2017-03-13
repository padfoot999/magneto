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
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evt"; ID=$eventID} -ErrorAction SilentlyContinue -ErrorVariable errVariable
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
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evt"; ID=$eventID} -ErrorAction SilentlyContinue -ErrorVariable errVariable  -Oldest
        
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
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evt"} -ErrorAction SilentlyContinue -ErrorVariable errVariable | Where-Object {$_.Message -like '*'+$msg+'*'}
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
        $totalHits = Get-WinEvent -FilterHashtable @{Path=$logPath +"\" + $logFile + ".evt"; Level=$lvl} -ErrorAction SilentlyContinue -ErrorVariable errVariable
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
    $logfile = Get-Content $eventCountFile
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

getEventOfInterest -logfile "SysEvent"  -eventid 104,1056,7030,7034,7035,7036,7040,7045
getEventOfInterest -logfile "SysEvent"  -eventid 7045,10000,100001,10100,20001,20002,24576,24577,2457
getEventOfInterest -logfile "SecEvent"  -eventid 564,567,592,601,624,626,628,636,642,682,683,680,681,672,673,675,676
getEventOfInterest -logfile "SecEvent"  -eventid 520,529,530,531,532,533,534,535,536,536,538,539,551,517,528,540,560,576 
getEventOfInterest -logfile "AppEvent"  -eventid 1033,1034,6100,11707,11708,11724,20001
getEventOfInterestFromAll -eventID 104
getEventOfInterestWithMsg -logfile "SysEvent" -msg 'USB'
getEventOfInterestWithLevel -logfile "AppEvent" -lvl 2

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