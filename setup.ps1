# <- RUN AS ADMINISTRATOR -> #

function download ($url, $installerloc){
if(!(Test-Path $installerloc)){
        $numberoftries = 5
        For($i = 0; $i -lt $numberoftries; $i++){
            Start-Sleep 1
            try{
                (New-Object System.Net.WebClient).DownloadFile($url, $installerloc)
                break
            }
            catch{ $url+' | '+$_ | Out-File $scriptpath'\DOWNLOAD ERROR LOG.txt' -append }
        }
    } else { write-host (split-path $installerloc -leaf)'already exists' -ForegroundColor Yellow }
}

function Expand-ZIPFile($file, $destination){
    $shell = new-object -com shell.application
    $zip = $shell.NameSpace($file)
    foreach($item in $zip.items()){ $shell.Namespace($destination).copyhere($item) }
}

#Unzipping the files
Write-Host `n'Unzipping Files'
$scriptpath = split-path -parent $MyInvocation.MyCommand.Definition
Expand-ZIPFile -file $scriptpath'\magneto-master.zip' -destination "C:\"
Expand-ZIPFile -file $scriptpath'\nirsoft_package.zip' -destination "C:\magneto-master\Tools\"

#Python
write-host 'Installing Python'
download -url "https://www.python.org/ftp/python/2.7.14/python-2.7.14.msi" -installerloc "$scriptpath\python-2.7.14.msi"
Start-Process msiexec.exe -Wait -ArgumentList "/i $scriptpath\python-2.7.14.msi /passive /norestart /L*v $scriptpath\PYTHON_INSTALLATION_LOG.txt"
Start-Process C:\Python27\Scripts\pip.exe -Wait -ArgumentList "install argparse bs4 chardet fuzzywuzzy netaddr numpy openpyxl pandas psycopg2 requests scandir sqlalchemy stem win_inet_pton xlrd xlwings"
Start-Process cmd.exe -wait -ArgumentList "/c C:\Python27\Scripts\pip.exe list > $scriptpath\INSTALLED_MODULES.txt"

#PostgreSQL
Write-Host 'Installing PostgreSQL'
download -url "http://get.enterprisedb.com/postgresql/postgresql-10.0-2-windows-x64.exe" -installerloc "$scriptpath\postgresql-10.0-2-windows-x64.exe"
Start-Process $scriptpath\postgresql-10.0-2-windows-x64.exe -Wait -ArgumentList "--unattendedmodeui minimal --mode unattended --superpassword password" -verb runas
Start-Process cmd.exe -wait -argumentlist "/c set PGPASSWORD=password&`"C:\Program Files\PostgreSQL\10\bin\psql.exe`" -h 127.0.0.1 -U postgres -c `"CREATE DATABASE magneto;`""

#Strawberry Perl
Write-Host 'Installing Perl'
download -url "http://www.strawberryperl.com/download/5.26.1.1/strawberry-perl-5.26.1.1-64bit.msi" -installerloc "$scriptpath\strawberry-perl-5.26.1.1-64bit.msi"
Start-Process msiexec.exe -Wait -ArgumentList "/i $scriptpath\strawberry-perl-5.26.1.1-64bit.msi /passive /norestart /L*v $scriptpath\PERL_INSTALLATION_LOG.txt" -verb runas
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") #Refreshes powershell to enable cpan to run
Start-Process cmd.exe -Wait -argumentlist "/c cpan install Parse::Win32Registry Regexp::Common Regexp::Common::time"

#Add PERL5LIB environment variable
Write-Host "Adding PERL5LIB environment variable"
setx PERL5LIB c:\magneto-master\Tools\RegRipper > $null

#Installs powershell version 4.0
Write-Host "PowerShell Version is",$PSVersionTable.PSVersion.Major
if ($PSVersionTable.PSVersion.Major -lt 4 ) {
    $OSVersion = (Get-WmiObject -class Win32_OperatingSystem).caption
    if (!(Test-path "hklm:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")){ #if registry subkey does not exist, then .NET 4.5 is not installed
        Write-Host ".NET 4.5 Framework is not installed`nInstalling .NET 4.5"
        download -url "https://download.microsoft.com/download/B/A/4/BA4A7E71-2906-4B2D-A0E1-80CF16844F5F/dotNetFx45_Full_setup.exe" -installerloc "$scriptpath\dotNetFx45_Full_setup.exe"
        Start-Process $scriptpath\dotNetFx45_Full_setup.exe -Wait -ArgumentList "/q /norestart" -verb runas
        }
    switch -wildcard ($OSVersion){
    "*Windows 7*"{
	write-host "Installing PowerShell ver 4.0"
        download -url "https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu" -installerloc "$scriptpath\Windows6.1-KB2819745-x64-MultiPkg.msu"
        Start-Process wusa.exe -wait -argumentlist "$scriptpath\Windows6.1-KB2819745-x64-MultiPkg.msu /quiet /norestart"
    }
    "*Windows Server 2008 R2*"{
	write-host "Installing PowerShell ver 4.0"
        download -url "https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu" -installerloc "$scriptpath\Windows6.1-KB2819745-x64-MultiPkg.msu"
        Start-Process wusa.exe -wait -argumentlist "$scriptpath\Windows6.1-KB2819745-x64-MultiPkg.msu /quiet /norestart"
    }
    "*Windows Server 2012*"{
	write-host "Installing PowerShell ver 4.0"
        download -url "https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows8-RT-KB2799888-x64.msu" -installerloc "$scriptpath\Windows8-RT-KB2799888-x64.msu"
        Start-Process wusa.exe -wait -argumentlist "$scriptpath\Windows8-RT-KB2799888-x64.msu /quiet /norestart"
    }
    default{ write-host "PowerShell 4.0 does not support", $OSVersion }
    }
}

[System.Media.SystemSounds]::Hand.Play()
Write-Host `n"Installation has been completed" -ForegroundColor Green
write-host "Please restart your computer to apply changes."`n
write-host "Press any key to continue ..."`n
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")