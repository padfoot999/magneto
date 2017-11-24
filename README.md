# magneto

## Incident response and forensic tool

Thank you for your interest. Please contact author for other essential files required to run this tool.

Features: 
 1. Parse and process triage output files, saving them in pgsql
 2. Process memory captures using volatility
 3. Parse and process volatility output files, saving them in pgsql
 4. Perform baseline, long tail analysis and correlation using above data, stored in pgsql

## Step by Step Guide to power up MAGNETO on Windows

1. Download Magneto Files

2. Install Python 2.7 (32 bit).  Remember to check the box to configure Python Path in Windows System Environment Variables, or do it yourself.

3. Install all necessary python modules using pip.

```
C:\Python27\Scripts\pip.exe install argparse bs4 chardet fuzzywuzzy netaddr numpy openpyxl pandas psycopg2 requests scandir sqlalchemy stem win_inet_pton xlrd xlwings
```

4. Install PostgreSQL

```
Database admin account: postgres
Password: (set your own password)
```

5. Launch pgadmin and connect to local PostgreSQL server on 127.0.0.1.  Create database "magneto"

6. Make sure that workstation has Powershell v4.0 and above installed, follow this [table](https://social.technet.microsoft.com/wiki/contents/articles/21016.how-to-install-windows-powershell-4-0.aspx#Windows_Management_Framework_4_supportability_matrix).

7. Install [Strawberry Perl](http://strawberryperl.com/).

8. Install Perl modules by typing command prompt:

```
cpan
install Parse::Win32Registry Regexp::Common Regexp::Common::time
```

9. Configure the system environment variable PERL5LIB in command prompt:

```
setx PERL5LIB c:\path\to\magneto\Tools\RegRipper
```

10. Download the NVD XML 2.0 Schema feeds from NIST according to nvd_cache/README.TXT and unzip them in nvd_cache

11. Download the NirLauncher Package according to Tools/nirsoft_package/README.TXT and unzip in Tools/nirsoft_package

12. Download [sleuthkit](https://github.com/sleuthkit/sleuthkit/releases) and unzip at Tools/sleuthkit

13. Download [srum-dump](https://github.com/MarkBaggett/srum-dump) and unzip at Tools/srum-dump

## Triage Post-Processing

#### Suggested Steps

1. Launch Ubuntu VM and process Memory (.raw) file using PROCESS_memory.py file. Save the output into the Evidence folder within each Incident folder.

2. Process Event Logs using Windows Powershell (WINTEL.ps1) file by running this in a powershell console:

```
WINTEL_WindowsLogParser.ps1 -logPath c:\path\to\individual_triage\Evidence\Logs -project PROJECTNAME
```

3. Run submit.py

```
python submit.py -d c:\path\to\parent\ -p PROJECTNAME
OR
python submit.py -d c:\path\to\parent\individual_triage -p PROJECTNAME
```

4. Generate output (as required)

```
python OUTPUT_baselineCSV.py -p PROJECTNAME
python OUTPUT_baselineXLSM.py -p PROJECTNAME
python OUTPUT_baselineXLSX.py -p PROJECTNAME
and other OUTPUT_* python modules
```
