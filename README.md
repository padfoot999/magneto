# magneto
Incident response and forensic tool

Thank you for your interest. Please contact author for other essential files required to run this tool.

Features: 
1 ) Parse and process triage output files, saving them in pgsql 
2 ) Process memory captures using volatility 
3 ) Parse and process volatility output files, saving them in pgsql 
4 ) Perform baseline, long tail analysis and correlation using above data, stored in pgsql

### Step by Step Guide to power up MAGNETO on Windows

1. Download Magneto Files from "https://github.com/padfoot999/magneto"
2. Install Python 2.7 (32 bit)
3. Configure Python Path in Windows System Environment Variables
4. Install PostgreSQL
5. Go to PGAdmin, create server with the following setting
        <br />Name: "magneto"
        <br />Host name/Add: "127.0.0.1"
        <br />User name: postgres
        <br />Password: password
6. After creating server, create database "magneto"
7. Install all necessary python modules (i.e. Pandas, psycopg2) using pip (C:\Python27\Scripts). Refer to requirements.txt for full list of dependencies.
8. Make sure that workstation has Powershell v4.0 and above installed
9. Install strawberry perl 
http://strawberryperl.com/
10. Open command prompt and type: 
cpan
install Parse::Win32Registry
install Regexp::Common
install Regexp::Common::time

### Triage Post-Processing

#### Proposed Workflow
1 ) Launch Ubuntu VM and process Memory (.raw) file using PROCESS_memory.py file. Save the output into the Evidence folder within each Incident folder.

2 ) Process Event Logs using Windows Powershell (WINTEL.ps1) file.

cd <Magneto WINTEL folder>
.\WINTEL_WindowsLogParser.ps1 -logPath <...\Evidence\Logs)> -project <Project Name>

3 ) Run PROCESS_postTriage File (Outputs RegRipper, SRUM-DUMP, WebCache Files, MFT, JLECMD TSV File)

python PROCESS_postTriage.py -d <Path to Incident folder> -p <Project Name>

4 ) Run submit.py file

python submit.py -d <Path to Incident folder> -p <Project Name>

5 ) Generate output (as required)

python OUTPUT_summary.py -d <Path to Incident folder> -r <Output folder after running PROCESS_postTriage.py> -p <Project Name>
python OUTPUT_timeline.py -d <Path to Incident folder>  -p <Project Name> -s <Number of workbooks to split>
python OUTPUT_baselineCSV.py -p <Project Name>
python OUTPUT_baselineXLSX.py -p <Project Name>
python OUTPUT_processDifference.py -p <Project Name>  
python OUTPUT_processNetworkConn.py -p <Project Name>  
python OUTPUT_autorunMerge.py -d <Path to Incident folder> -p <Project Name>  
python OUTPUT_cveChecker.py -p <Project Name>
python OUTPUT_cveChecker.py -p <Project Name> -t <Image Name>
python OUTPUT_baselineCSV.py -p <Project Name>
python OUTPUT_baselineXLSX.py -p <Project Name>
python OUTPUT_processDifference.py -p <Project Name>  
