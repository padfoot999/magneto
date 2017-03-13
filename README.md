# magneto
Incident response and forensic tool

Thank you for your interest. Please contact author for other essential files required to run this tool.

Features: 
1 ) Parse and process triage output files, saving them in pgsql 
2 ) Process memory captures using volatility 
3 ) Parse and process volatility output files, saving them in pgsql 
4 ) Perform baseline, long tail analysis and correlation using above data, stored in pgsql

WIP:
1 ) Identify CVE vulnerabilities based on software applications installed 
2 ) Upload file hashes to VT and automatically process unknown files through cuckoo 
3 ) Spoofed email identifier 
4 ) Windows Log Parser 
5 ) Windows malicious document identifier

## Running Magneto Scripts

### Python Magneto
* Post Triage
```
python PROCESS_postTriage.py -d <Path to Incident folder> -p <Project Name (i.e. RADIUM)>
```
* Submitting Incident Folders into Postgresql database
```
python submit.py -d <Path to Incident folder> -p <Project Name (i.e. RADIUM)>
```
* Output Baseline
```
python OUTPUT_baselineCSV.py -p <Project Name (i.e. RADIUM)>
python OUTPUT_baselineXLSX.py -p <Project Name (i.e. RADIUM)>
```
* Output Process Difference
```
python OUTPUT_processDifference.py -p <Project Name (i.e. RADIUM)>  
```
* Output Process Network Connections
```
python OUTPUT_processNetworkConn.py -p <Project Name (i.e. RADIUM)>  
```
* Output Process Network Connections
```
python OUTPUT_processNetworkConn.py -p <Project Name (i.e. RADIUM)>  
```
* Output Merged AutoRun Paths
```
python OUTPUT_autorunMerge.py -d <Path to Incident folder> -p <Project Name (i.e. RADIUM)>  
```
* Output cveChecker
```
python OUTPUT_cveChecker.py -p <Project Name (i.e. RADIUM)> 
python OUTPUT_cveChecker.py -p <Project Name (i.e. RADIUM)> -t <Image Name (i.e. 20170117115236 - AERO Incident)
```
* Output Summary File
```
python OUTPUT_summary.py -d <Path to Incident folder> -r <Output folder after running PROCESS_postTriage.py> -p <Project Name (i.e. RADIUM)>
python OUTPUT_summary.py -d "E:\\" -r "F:\\magneto v2\\results\\ARGON" -p ARGON
```
### WINTEL Powershell 
```
cd <Magneto WINTEL folder>
.\WINTEL_WindowsLogParser-v?.ps1 -logPath <...\Evidence\Logs)> -project <ARGON>
```
