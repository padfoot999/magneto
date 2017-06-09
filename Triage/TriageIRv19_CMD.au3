;#NoTrayIcon
#Include <GUIConstantsEx.au3>
#Include <WindowsConstants.au3>
#Include <StaticConstants.au3>
#Include <Date.au3>
#Include <File.au3>
#Include <array.au3>
#include <Crypt.au3>
#include <WinAPIFiles.au3>
;DEBUGGING TIPS: Note that if you run as administrator, the LINE indicated in the error message is inaccurate. Revert to user mode for debugging accuracy.
;DEBUGGING TIP2: If there are no output for VSC functions, select Compile Script (x64) and then run the .exe file as administrator

Global 	$tStamp = @YEAR & @MON & @MDAY & @HOUR & @MIN & @SEC

;Reports Directory
Global	$RptsDir = @ScriptDir & "\" & $tStamp & " - " & @ComputerName & " Incident"

;Evidence Directory
Global	$EvDir = $RptsDir & "\Evidence\"

;Browser Directory
Global	$BrowserDir = $RptsDir & "\Browser\"

;Tools Directory
Global 	$tools = '"' &@ScriptDir & '\Tools\'

;Note that in the Tools directory contain cmd.exe from Windows XP
;ZFZF: To update this with a sanitized version

Global 	$HashDir = $RptsDir & "\Evidence"
Global	$JmpLst = $EvDir & "Jump Lists"

;Using our own cammand prompt instead of the system
Global	$shell = '"' & @ScriptDir & '\Tools\cmd.exe"'
Global 	$shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'

;KPMG Logo Image
Global	$image = "kpmgicon.jpg"

;ZFZF: How is this used?
Global 	$RecentPath = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Recent")

;Log file
Global	$Log = $RptsDir & "\Incident Log.txt"
Global 	$ini_file
Global 	$fcnt

;Parameters for WMI Execute Query
Global	$wbemFlagReturnImmediately	= 0x10
Global	$wbemFlagForwardOnly		= 0x20				;DO NOT CHANGE
Global	$strComputer = "."
Global	$compName = @ComputerName

$ini_file = "Triage-CMD.ini"

If IsAdmin() = 0 Then
	;MsgBox(64, "Insufficient Privilege Detected", 'Please restart with "RunAs /user:[admin] ' & @ScriptDir & '\TriageIR.exe" or Right-Click "Run As Administrator".')
	;Exit
EndIf

INI_Check($ini_file)
INI2Command()
Exit

Func INI_Check($ini_file)				;Check the INI file included in triage for functions and whether or not to run them

   Global 	$GUI_ini  = "No"
   Global 	$md_ini, $tm_ini
   Global 	$sysrrp_ini, $sftrrp_ini, $hkcurrp_ini, $secrrp_ini, $samrrp_ini, $ntusrrp_ini, $usrc_ini
   Global	$VS_info_ini, $VS_PF_ini, $VS_RF_ini, $VS_JmpLst_ini, $VS_EvtCpy_ini, $VS_SYSREG_ini, $VS_SECREG_ini, $VS_SAMREG_ini, $VS_SOFTREG_ini, $VS_USERREG_ini
   Global 	$SysIntAdd_ini
   Global 	$MFT_ini, $AmCache_ini
   Global 	$IPs_ini, $DNS_ini, $Arp_ini, $ConnS_ini, $routes_ini, $ntBIOS_ini, $conn_ini
   Global 	$share_ini, $shfile_ini, $fw_ini, $host_ini, $wrkgrp_ini, $exifmetadata_ini
   Global 	$pf_ini, $rf_ini, $JL_ini, $evt_ini
   Global 	$pf_target_ini, $rf_target_ini, $JL_target_ini
   Global 	$proc_ini, $sysinf_ini, $srvs_ini, $srum_ini, $UsrInfo_ini
   Global 	$fassoc_ini, $acctinfo_ini, $hostn_ini
   Global 	$autorun_ini, $AutoRun_Target_ini, $st_ini, $logon_ini
   Global 	$NTFS_ini, $mntdsk_ini, $dir_ini, $VolInfo_ini
   Global 	$md5_ini, $sha1_ini
   Global 	$compress_ini

   ;ZF added
   Global	$AutorunVTEnabled_ini, $ProcexpVTEnabled_ini
   Global	$dcInfo_ini
   Global	$wmi_tz_ini, $wmi_usr_ini, $wmi_model_ini, $wmi_hotfix_ini, $wmi_warranty_ini, $wmi_nic_ini, $wmi_manu_ini, $wmi_software_ini, $wmi_evt_ini, $wmi_proc_ini, $wmi_job_ini, $wmi_startup_ini, $wmi_domain_ini, $wmi_service_ini, $wmi_bios_ini, $wmi_hd_ini, $wmi_share_ini, $wmi_prodkey_ini
   Global	$bwsr_cache_ini, $bwsr_hist_ini, $bwsr_fav_ini, $bwsr_cookies_ini, $bwsr_dl_ini, $bwsr_autocomplete_ini, $bwsr_webcache_ini, $bwsr_password_ini

   $acctinfo_ini = "no"
   $Arp_ini = "no"
   $autorun_ini = "No"
   $AutoRun_Target_ini = "no"
   $AutorunVTEnabled_ini= "no"
   $bwsr_autocomplete_ini = "no"
   $bwsr_cache_ini = "no"
   $bwsr_cookies_ini = "no"
   $bwsr_dl_ini = "no"
   $bwsr_fav_ini = "no"
   $bwsr_hist_ini = "no"
   $bwsr_password_ini = "no"
   $bwsr_webcache_ini = "Yes"
   $compress_ini = "no"
   $conn_ini = "no"
   $ConnS_ini = "no"
   $dcInfo_ini= "no"
   $dir_ini = "no"
   $DNS_ini = "no"
   $evt_ini = "no"
   $exifmetadata_ini = "no"
   $fassoc_ini = "no"
   $fw_ini = "no"
   $hkcurrp_ini = "No"
   $host_ini = "no"
   $hostn_ini = "no"
   $IPs_ini = "no"
   $JL_ini = "no"
   $JL_target_ini = "no"
   $logon_ini = "no"
   $md_ini = "No"
   $md5_ini = "no"
   $MFT_ini = "no"
   $mntdsk_ini = "no"
   $ntBIOS_ini = "no"
   $NTFS_ini = "no"
   $ntusrrp_ini = "No"
   $pf_ini = "no"
   $AmCache_ini = "no"
   $pf_target_ini = "no"
   $proc_ini = "Yes"
   $ProcexpVTEnabled_ini= "no"
   $rf_ini = "no"
   $rf_target_ini = "no"
   $routes_ini = "no"
   $samrrp_ini = "No"
   $secrrp_ini = "No"
   $sftrrp_ini = "No"
   $sha1_ini = "no"
   $share_ini = "no"
   $shfile_ini = "no"
   $srum_ini = "no"
   $srvs_ini = "Yes"
   $st_ini = "no"
   $sysinf_ini = "Yes"
   $SysIntAdd_ini = "no"
   $sysrrp_ini = "No"
   $usrc_ini = "no"
   $UsrInfo_ini = "no"
   $VolInfo_ini = "no"
   $VS_EvtCpy_ini = "no"
   $VS_JmpLst_ini = "no"
   $VS_PF_ini = "no"
   $VS_RF_ini = "no"
   $VS_SAMREG_ini = "no"
   $VS_SECREG_ini = "no"
   $VS_SOFTREG_ini = "no"
   $VS_SYSREG_ini = "no"
   $VS_USERREG_ini = "no"
   $wmi_bios_ini = "no"
   $wmi_domain_ini = "no"
   $wmi_evt_ini = "no"
   $wmi_hd_ini = "no"
   $wmi_hotfix_ini = "no"
   $wmi_job_ini = "no"
   $wmi_manu_ini = "no"
   $wmi_model_ini = "no"
   $wmi_nic_ini = "no"
   $wmi_proc_ini = "no"
   $wmi_prodkey_ini = "no"
   $wmi_service_ini = "no"
   $wmi_share_ini = "no"
   $wmi_software_ini = "no"
   $wmi_startup_ini = "no"
   $wmi_tz_ini = "no"
   $wmi_usr_ini = "Yes"
   $wmi_warranty_ini = "no"
   $wrkgrp_ini = "no"

EndFunc

Func INI2Command()						;Correlate the INI file into executing the selected functions

   If Not FileExists($RptsDir) Then DirCreate($RptsDir)
   If Not FileExists($EvDir) Then DirCreate($EvDir)

   If $md_ini = "Yes" Then MemDump()

   If $pf_ini = "Yes" Then Prefetch()

   If $AmCache_ini = "Yes" Then AmCache()

   If $rf_ini = "Yes" Then RecentFolder()

   If $JL_ini = "Yes" Then JumpLists()

   If $pf_target_ini = "Yes" Then Prefetch_Target()

   If $rf_target_ini = "Yes" Then RecentFolder_Target()

   If $JL_target_ini = "Yes" Then JumpLists_Target()

   If $sysrrp_ini = "Yes" Then SystemRRip()

   If $sftrrp_ini = "Yes" Then SoftwareRRip()

   If $secrrp_ini = "Yes" Then SecurityRRip()

   If $samrrp_ini = "Yes" Then SAMRRip()

   If $hkcurrp_ini = "Yes" Then HKCURRip()

   If $ntusrrp_ini = "Yes" Then NTUserRRip()

   If $usrc_ini = "Yes" Then UsrclassE()

   If $MFT_ini = "Yes" Then MFTgrab()

   VSC_IniCount()

	  If $r_ini >= 1 Then
		 GetShadowNames()
		 MountVSCs()
	  Else
		 Global $firstMountedVersion = -1
	  EndIf

	  ;ZFZF: If file exist, just copy?! Don't care option?!
	  ;TANADI:The file will only exist if one of the VSC option is selected!
	  If FileExists("C:\VSC_" & $firstMountedVersion) = 1 Then

		 If $VS_PF_ini = "Yes" Then VSC_Prefetch()

		 If $VS_RF_ini = "Yes" Then VSC_RecentFolder()

		 If $VS_JmpLst_ini = "Yes" Then VSC_JumpLists()

		 If $VS_EvtCpy_ini = "Yes" Then VSC_EvtCopy()

		 If $VS_SYSREG_ini = "Yes" Then VSC_RegHiv("SYSTEM")

		 If $VS_SECREG_ini = "Yes" Then VSC_RegHiv("SECURITY")

		 If $VS_SAMREG_ini = "Yes" Then VSC_RegHiv("SAM")

		 If $VS_SOFTREG_ini = "Yes" Then VSC_RegHiv("SOFTWARE")

		 If $VS_USERREG_ini = "Yes" Then VSC_NTUser()

	  Else
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Failed to execute Volume Shadow Copy Functions." & @CRLF)
	  EndIf

	  If $r_ini >= 1 Then
		 VSC_rmVSC()
	  EndIf

   If $SysIntAdd_ini = "Yes" Then SysIntAdd()

   If $IPs_ini = "Yes" Then IPs()

   If $DNS_ini = "Yes" Then DNS()

   If $Arp_ini = "Yes" Then Arp()

   If $ntBIOS_ini = "Yes" Then NetBIOS()

   If $routes_ini = "Yes" Then Routes()

   If $conn_ini = "Yes" Then Connections()

   If $Conns_ini = "Yes" Then ConnectedSessions()

   If $share_ini = "Yes" Then Shares()

   If $shfile_ini = "Yes" Then SharedFiles()

   If $wrkgrp_ini = "Yes" Then Workgroups()

   If $sysinf_ini = "Yes" Then SystemInfo()

   If $proc_ini = "Yes" Then Processes()

   If $srvs_ini = "Yes" Then Services()

   If $acctinfo_ini = "Yes" Then AccountInfo()

   If $autorun_ini = "Yes" Then AutoRun()

   If $AutoRun_Target_ini = "Yes" Then AutoRun_Target()

   If $srum_ini = "Yes" Then Srum()

   If $st_ini = "Yes" Then ScheduledTasks()

   If $fassoc_ini = "Yes" Then FileAssociation()

   If $hostn_ini = "Yes" Then Hostname()

   If $UsrInfo_ini = "Yes" Then UsrInfo()

   If $NTFS_ini = "Yes" Then NTFSInfo()

   If $VolInfo_ini = "Yes" Then VolInfo()

   If $mntdsk_ini = "Yes" Then MountedDisk()

   If $dir_ini = "Yes" Then Directory()

   If $evt_ini = "Yes" Then EvtCopy()

   If $dcInfo_ini = "Yes" Then dcInfo()

   If $wmi_tz_ini = "Yes" Then wmi_tz()

   If $wmi_usr_ini = "Yes" Then wmi_usr()

   If $wmi_model_ini = "Yes" Then wmi_model()

   If $wmi_warranty_ini = "Yes" Then wmi_warranty()

   If $wmi_nic_ini = "Yes" Then wmi_nic()

   If $wmi_manu_ini = "Yes" Then wmi_manu()

   If $wmi_software_ini = "Yes" Then wmi_software()

   If $wmi_evt_ini = "Yes" Then wmi_evt()

   If $wmi_proc_ini = "Yes" Then wmi_proc()

   If $wmi_job_ini = "Yes" Then wmi_job()

   If $wmi_startup_ini = "Yes" Then wmi_startup()

   If $wmi_domain_ini = "Yes" Then wmi_domain()

   If $wmi_service_ini = "Yes" Then wmi_service()

   If $wmi_bios_ini = "Yes" Then wmi_bios()

   If $wmi_hd_ini = "Yes" Then wmi_hd()

   If $wmi_share_ini = "Yes" Then wmi_share()

   If $wmi_hotfix_ini = "Yes" Then wmi_hotfix()

   If $wmi_prodkey_ini = "Yes" Then wmi_prodkey()

   If $bwsr_cache_ini = "Yes" Then bwsr_cache()

   If $bwsr_hist_ini = "Yes" Then bwsr_hist()

   If $bwsr_fav_ini = "Yes" Then bwsr_fav()

   If $bwsr_cookies_ini = "Yes" Then bwsr_cookies()

   If $bwsr_dl_ini = "Yes" Then bwsr_dl()

   If $bwsr_autocomplete_ini = "Yes" Then bwsr_autocomplete()

   If $bwsr_webcache_ini = "Yes" Then bwsr_webcache()

   If $bwsr_password_ini = "Yes" Then bwsr_password()

   If $exifmetadata_ini = "Yes" Then exifmetadata()

   If $fw_ini = "Yes" Then Firewall()

   If $host_ini = "Yes" Then Hosts()

   If $AutorunVTEnabled_ini = "Yes" Then AutorunVTEnabled()

   If $ProcexpVTEnabled_ini = "Yes" Then ProcexpVTEnabled()

   If $md5_ini = "Yes" Then MD5()

   If $sha1_ini = "Yes" Then SHA1()

   If $compress_ini = "Yes" Then Compression()

   CommandROSLOG()

;   MsgBox(0, "Triage:  Incident Response", "Your selected tasks have completed.")

EndFunc

Func VSC_IniCount()						;Count the number of VSC functions selected in the INI
   Global $r_ini = 0

   If $VS_PF_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_RF_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_JmpLst_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_EvtCpy_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_SYSREG_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_SECREG_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_SAMREG_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_SOFTREG_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_USERREG_ini = "Yes" Then $r_ini = $r_ini + 1

EndFunc

;1. Memory Dump
Func MemDump()							;Special thanks to MoonSols for an amazing tool for memory captures
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 1. Memdump" & @CRLF)
   ;MsgBox(0, "DEBUG", "Starting MemDump")

   $windd = "DumpIt.exe" ;The memory dump executable, we are currently using moonsol DumpIt.exe

   ;Moving DumpIt to Evidence Folder
   FileMove(".\Tools\DumpIt.exe",$EvDir)

   ShellExecute($windd, "", $EvDir )

   ;Moving DumpIt to back to Tools folder
   FileMove($EvDir & "DumpIt.exe", ".\Tools")

   ;Waiting for user input. If DumpIt.exe is running, the countdown is stopped.
   Sleep(4500)

   ProcessClose($windd)

   	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command:" & $windd & @CRLF)

   ProcessWaitClose($windd)

EndFunc

;2. Prefetch
Func Prefetch()							;Copy any prefecth data while maintaining metadata
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 2. Prefetch" & @CRLF)
   Local $robocopy = '"' & @ScriptDir & '\Tools\Robocopy.exe"'
   Local $pf1 = $shellex & ' ' & $robocopy & ' "' & @WindowsDir & '\Prefetch" "' & $EvDir & '\Prefetch" *.pf /copyall /ZB /TS /r:2 /w:3 /FP /NP /log:"' & $RptsDir & '\Prefetch_RoboCopy_Log.txt"'

   If Not FileExists($EvDir & "\Prefetch") Then DirCreate($EvDir & "\Prefetch")

   ShellExecuteWait($robocopy, ' "' & @WindowsDir & '\Prefetch" "' & $EvDir & '\Prefetch" *.pf /copyall /ZB /TS /r:2 /w:3 /FP /NP /log:"' & $RptsDir & '\Prefetch_RoboCopy_Log.txt"', $tools, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command:" & $pf1 & @CRLF)
EndFunc

;2b. AmCache
Func AmCache()							;Copy any prefecth data while maintaining metadata
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 2b. AmCache" & @CRLF)
   If Not FileExists($EvDir & '\AmCache') Then DirCreate($EvDir & '\AmCache')
   Local $uDir = "C:\Windows\AppCompat\Programs"

   If FileExists($uDir & "\Amcache.hve") Then
	  Local $webcache = $shellex & ' .\Tools\Hobocopy\HoboCopy.exe "' & $uDir & '" "' & $EvDir & '\AmCache" "Amcache.hve"'
	  RunWait($webcache, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $webcache & @CRLF)
   EndIf

   If FileExists($uDir & "\RecentFileCache.bcf") Then
	  Local $webcache2 = $shellex & ' .\Tools\Hobocopy\HoboCopy.exe "' & $uDir & '" "' & $EvDir & '\AmCache" "RecentFileCache.bcf"'
	  RunWait($webcache2, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $webcache2 & @CRLF)
   EndIf
EndFunc

;3. Recent Folder
Func RecentFolder()						;Send information to the recent folder copy function

   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 3. Recent Folder" & @CRLF)

   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr

	  $profs = FileFindNextFile($usr)

		 If @error then ExitLoop

	  $uDir = $uPath & $profs

	  $uATB = FileGetAttrib($uDir)

	  If StringInStr($uATB, "D") Then _RobocopyRF($uDir, $profs)

   WEnd
EndFunc

Func _RobocopyRF($path, $output)		;Copy Recent folder from all profiles while maintaining metadata

   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($EvDir & '\Recent LNKs\' & $output) Then DirCreate($EvDir & '\Recent LNKs\' & $output)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

	  If $OS = "Users" Then
			$recPATH = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent"'
		 Else
			$recPATH = '"' & $path & '\Recent"'
		 EndIf

   Local $recF1 = $robocopy & ' ' & $recPATH & ' "' & $EvDir & '\Recent LNKs\' & $output & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & 'Recent LNKs\' & $output & ' Recent RoboCopy Log.txt"'
   RunWait($recF1, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command:" & $recF1 & @CRLF)

   ;Uses lnkparser.exe to generate more information regarding LNK files
   Local $lnkparser = ' .\Tools\lnkparser.exe'
   Local $lnk1 = $shellex & $lnkparser & ' -o "' & $EvDir & '\Recent LNKs\' & $output & '" -c -s "' & $recPATH & '"'
   RunWait($lnk1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command:" & $lnk1 & @CRLF)

EndFunc

;4. JumpLists
Func JumpLists()						;Provide info to the Jumplist copy function

   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 4. Jumplists" & @CRLF)

   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If $OS = "Users" Then
	  $uPath = "C:\Users\"
   Else
	  $uPath = "C:\Documents and Settings\"
   EndIf

	  $usr = FileFindFirstFile($uPath & "*.*")

	  While 1

		 $profs = FileFindNextFile($usr)

			If @error then ExitLoop

		 $uDir = $uPath & $profs

		 $uATB = FileGetAttrib($uDir)

		 If StringInStr($uATB, "D") Then _RobocopyJL($udir, $profs)

	  WEnd
EndFunc

Func _ArrayAddColumns(ByRef $aArrayIn, $NumColCount = 1)
    If Not IsArray($aArrayIn) Then
        SetError(1)
        Return -1
    EndIf
    If $NumColCount < 1 Then
        SetError( 2)
        Return -1
    EndIf
    Local $iDimensions = UBound($aArrayIn, $UBOUND_DIMENSIONS)
    If $iDimensions > 2 Then
        SetError(3)
        Return -1
    EndIf
    Local $NewArrayOut[UBound($aArrayIn)][UBound($aArrayIn, $UBOUND_COLUMNS) + $NumColCount]
    For $I = 0 To UBound($aArrayIn) - 1
        If $iDimensions > 1 Then
            For $X = 0 To UBound($aArrayIn, $UBOUND_COLUMNS) - 1
			   $NewArrayOut[$I][$X] = $aArrayIn[$I][$X]
            Next
        Else
			$NewArrayOut[$I][0] = $aArrayIn[$I]
        EndIf
	 Next
    Return $NewArrayOut
 EndFunc

 Func _RobocopyJL($path, $output)		;Copy Jumplist information while maintaining metadata

   Local $robocopy
   Local $robocmd
   Local $autodest
   Local $customdest
   Local $shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'
   Local $autodest = $EvDir & '\Jump Lists\' & $output & '\Automatic'
   Local $customdest = $EvDir & '\Jump Lists\' & $output & '\Custom'

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($autodest) Then DirCreate($autodest)
   If Not FileExists($customdest) Then DirCreate($customdest)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   $autoexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"'
   $customexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"'

   Local $jla1 = $robocopy & " " & $autoexe1 & ' "' & $autodest & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Jump Lists\' & $output & '_JumpList_Auto_RoboCopy_Log.txt"'
   Local $jlc1 = $robocopy & " " & $customexe1 & ' "' & $customdest & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Jump Lists\' & $output & '_JumpList_Custom_RoboCopy.txt"'

   RunWait($jla1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $jla1 & @CRLF)
   RunWait($jlc1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $jlc1 & @CRLF)

EndFunc

;5. Prefetch Target File
Func Prefetch_Target()							;Copy any prefecth data while maintaining metadata
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 5. Prefetch Target" & @CRLF)
   Local $robocopy = '"' & @ScriptDir & '\Tools\Robocopy.exe"'
   Local $winprefetch = ' .\Tools\nirsoft_package\NirSoft\winprefetchview'
   Local $drivelistview = ' .\Tools\nirsoft_package\NirSoft\driveletterview'
   Local $pf2 = $shellex & $winprefetch & ' /scomma "' & $RptsDir & '\Prefetch Info.csv"'
   Local $pf3 = $shellex & $drivelistview & ' /scomma "' & $RptsDir & '\Drive Letter Info.csv"'

   RunWait($pf2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $pf2 & @CRLF)
   RunWait($pf3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $pf3 & @CRLF)

   ;Creates a dictionary containing mapping from Volume Serial Number to corresponding Drive Letter
   Local $intCount = 0, $linecount = 0
   Local $csv, $prefetchfile[1]
   Local $driveDict = ObjCreate("Scripting.Dictionary")
   Local $filename = $RptsDir & '\Drive Letter Info.csv'
   While _WinAPI_FileInUse($filename) = 1
       sleep(10)
   WEnd
   _FileReadToArray($filename, $csv)
   If IsArray($csv) Then
	  For $i = 1 To $csv[0]
		 $temp = StringSplit($csv[$i], ",")
		 Sleep(1)
		 If StringLen($temp[1]) <> 0 And StringLen($temp[13]) <> 0 Then
			$driveLetter = $temp[1]
			$serialNumber = $temp[13]
			$driveDict($serialNumber) = $driveLetter
		 EndIf
	  Next
   EndIf

   ;Gets Target path of each prefetch file and uses robocopy to copy file to evidence directory
   $filename = $RptsDir & '\Prefetch Info.csv'
   While _WinAPI_FileInUse($filename) = 1
       sleep(10)
   WEnd
   _FileReadToArray($filename, $csv)
   Local $prefetchDict = ObjCreate("Scripting.Dictionary")
   If IsArray($csv) Then
	  For $i = 1 To $csv[0]
		 ;_ArrayDisplay(StringSplit($csv[$i], ","), "Test")
		 $temp = StringSplit($csv[$i], ",")
		 If StringLen($temp[7]) <> 0 Then
			If @OSVersion = "WIN_10" Then
			   If StringRegExp($temp[7], '-([^}]*)', $STR_REGEXPMATCH) Then
				  Local $volSerialNumber = StringRegExp($temp[7], '-([^}]*)', $STR_REGEXPARRAYMATCH)[0]
			   EndIf
			   Local $drive = $driveDict(StringUpper($volSerialNumber))
			   $temp[7] = StringRegExpReplace($temp[7], '^\\[^\\]*', $drive)
			EndIf
			If Not $prefetchDict.Exists($temp[7]) Then
			   $prefetchDict($temp[7]) = StringRegExpReplace($temp[1], '\.\w*$', '')
			EndIf
		 EndIf
	  Next
   EndIf

   Local $dictKeys = $prefetchDict.Keys
   If Not FileExists($EvDir & "\Prefetch\Files") Then DirCreate($EvDir & "\Prefetch\Files")
   For $i = 0 To $prefetchDict.Count - 1
	  Local $fullPath = $dictKeys[$i]
	  Local $parentDirectory = StringRegExpReplace($fullPath, '\\[^\\]*$', '')
	  Local $file = StringRegExpReplace($fullPath, '.*\\', '')
	  Local $recF1 = $shellex & ' ' & $robocopy & ' "' & $parentDirectory & '" "' & $EvDir & '\Prefetch\Files" "' & $file & '" /copyall /ZB /TS /r:2 /w:3 /FP /NP /log+:"' & $RptsDir & '\Prefetch_Target_RoboCopy_Log.txt"'
	  ;some files do not allow renaming i.e. cmd
	  ;renaming command might be different with different OS Versions
	  If StringRegExp($file, '\.\w*$', $STR_REGEXPMATCH) Then
		 Local $rename = @ComSpec & ' /c rename "' & $EvDir & '\Prefetch\Files\' & $file & '" "' & $prefetchDict($dictKeys[$i]) & StringRegExp($file, '\.\w*$', $STR_REGEXPARRAYMATCH)[0] & '"'
	  Else
		 Local $rename = @ComSpec & ' /c rename "' & $EvDir & '\Prefetch\Files\' & $file & '" "' & $prefetchDict($dictKeys[$i]) & '"'
	  EndIf
	  ShellExecuteWait($robocopy, ' "' & $parentDirectory & '" "' & $EvDir & '\Prefetch\Files" "' & $file & '" /copyall /ZB /TS /r:2 /w:3 /FP /NP', $tools, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $recF1 & @CRLF)
	  RunWait($rename, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $rename & @CRLF)
   Next
EndFunc

;6. Recent Folder Target
Func RecentFolder_Target()						;Send information to the recent folder copy function
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 6. Recent Folder Target" & @CRLF)
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr

	  $profs = FileFindNextFile($usr)

		 If @error then ExitLoop

	  $uDir = $uPath & $profs

	  $uATB = FileGetAttrib($uDir)

	  If StringInStr($uATB, "D") Then _RobocopyRFTgt($uDir, $profs)

   WEnd
EndFunc

Func _RobocopyRFTgt($path, $output)		;Copy Recent folder from all profiles while maintaining metadata

   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

	  If $OS = "Users" Then
			$recPATH = $path & '\AppData\Roaming\Microsoft\Windows\Recent'
	  Else
			$recPATH = $path & '\Recent'
	  EndIf

   ;Gets Target path of each LNK file and uses robocopy to copy file to evidence directory
   $lnkfiles = FileFindFirstFile($recPATH & '\*.*')
   While $lnkfiles
	  $lnkfile = FileFindNextFile($lnkfiles)
		 If @error then ExitLoop
	  $lnkpath = $recPATH & '\' & $lnkfile
	  $lnkdetails = FileGetShortcut($lnkpath)
		 If Not @error Then
			$path = $lnkdetails[0]
		 EndIf
	  $lnkATB = FileGetAttrib($path)
	  If Not StringInStr($lnkATB, "D") Then _RobocopyRFTgtFiles($path, $output)
   WEnd
EndFunc

Func _RobocopyRFTgtFiles($path, $output)		;Copy Recent folder from all profiles while maintaining metadata
   Local $robocopy
   Local $robocmd

   If Not FileExists($EvDir & '\Recent LNKs\' & $output & '\Files') Then DirCreate($EvDir & '\Recent LNKs\' & $output & '\Files')

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $parentDirectory = StringRegExpReplace($path, '\\[^\\]*$', '')
   Local $file =  '"' & StringRegExpReplace($path, '.*\\', '') & '"'
   Local $recF1 = $shellex & ' ' & $robocopy & ' "' & $parentDirectory & '" "' & $EvDir & '\Recent LNKs\' & $output & '\Files" ' & $file & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /IS'
   ShellExecuteWait($robocopy, ' "' & $parentDirectory & '" "' & $EvDir & '\Recent LNKs\' & $output & '\Files" ' & $file & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /IS /log:"' & $EvDir & 'Recent LNKs\' & $output & ' Recent Target RoboCopy Log.txt"', $tools, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $recF1 & @CRLF)
EndFunc

;7. JumpLists Target
Func JumpLists_Target()						;Provide info to the Jumplist copy function
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 7. JumpLists Target" & @CRLF)
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If $OS = "Users" Then
		 $uPath = "C:\Users\"
	  Else
	   $uPath = "C:\Documents and Settings\"
	EndIf

	  $usr = FileFindFirstFile($uPath & "*.*")

	  While 1

		 $profs = FileFindNextFile($usr)

			If @error then ExitLoop

		 $uDir = "C:\Users\" & $profs

		 $uATB = FileGetAttrib($uDir)

		 If StringInStr($uATB, "D") Then _RobocopyJLTgt($udir, $profs)

	  WEnd
EndFunc

Func _RobocopyJLTgt($path, $output)		;Copy Jumplist information while maintaining metadata
;JumpListsView currently only reads information from AutomaticDestinations
   Local $shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'
   Local $autodest = $EvDir & '\Jump Lists\' & $output & '\Automatic'
   Local $customdest = $EvDir & '\Jump Lists\' & $output & '\Custom'
   Local $jlecmd = ' .\Tools\JLECmd-master\JLECmd-master\JLECmd\bin\Debug\JLECmd'

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($autodest & "\Files") Then DirCreate($autodest & "\Files")
   If Not FileExists($customdest & "\Files") Then DirCreate($customdest & "\Files")

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   $autoexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"'
   $customexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"'

   Local $jla2 = $shellex & $jlecmd & ' -d ' & $autoexe1 &' --csv "' & $EvDir & '\Jump Lists\' & $output & '"'
   Local $jlc2 = $shellex & $jlecmd & ' -d ' & $customexe1 &' --csv "' & $EvDir & '\Jump Lists\' & $output & '"'

   RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4.0\Client","Install")
   If @error <> 0 Then Return
   RunWait($jla2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $jla2 & @CRLF)
   RunWait($jlc2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $jlc2 & @CRLF)

   Local $intCount = 0, $linecount1 = 0
   ;Local $linecount2 = 0
   Local $autocsv, $customcsv, $autofilelist[1], $customfilelist[1]
   $autofiles = FileFindFirstFile($EvDir & '\Jump Lists\' &  $output & '\*_AutomaticDestinations.tsv')
   $customfiles = FileFindFirstFile($EvDir & '\Jump Lists\' & $output & '\*_CustomDestinations.tsv')
   $autofile = FileFindNextFile($autofiles)
   $customfile = FileFindNextFile($customfiles)

   ;Makes sure that JLECmd has finished saving all data into TSV file
   While _WinAPI_FileInUse($EvDir & '\Jump Lists\' & $output & '\' & $autofile) = 1
       sleep(10)
   WEnd
   While _WinAPI_FileInUse($EvDir & '\Jump Lists\' & $output & '\' & $customfile) = 1
       sleep(10)
   WEnd

   ;Initializes variable for CSV Output
   _FileReadToArray($EvDir & '\Jump Lists\' & $output & '\' & $autofile, $autocsv, $FRTA_COUNT, @TAB)
   _FileReadToArray($EvDir & '\Jump Lists\' & $output & '\' & $customfile, $customcsv, $FRTA_COUNT, @TAB)

   If Not UBound($autocsv, $UBOUND_ROWS)=0 Then _RobocopyJLTgtFiles($autocsv, $output, $autofile, $autodest)
   If Not UBound($customcsv, $UBOUND_ROWS)=0 Then _RobocopyJLTgtFiles($customcsv, $output, $customfile, $customdest)
EndFunc

Func _RobocopyJLTgtFiles($csv, $output, $tsvfile, $dest)
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   If UBound($csv, $UBOUND_ROWS)=0 Then Return
   ;Stores row number of item within original array
   Local $jumpDict = ObjCreate("Scripting.Dictionary")
   $csv = _ArrayAddColumns($csv)
   $csv[1][UBound($csv, $UBOUND_COLUMNS)-1]="Robocopy File Name"

   For $i=0 To UBound($csv, $UBOUND_COLUMNS)-1
	  If $csv[1][$i]="LocalPath" Then $col = $i
   Next

   For $i = 2 To $csv[0][0]
	  If $csv[$i][$col] Then
		 If Not $jumpDict.Exists($csv[$i][$col]) Then $jumpDict($csv[$i][$col]) = $i
	  EndIf
   Next

   ;Uses robocopy to copy file out
   Local $dictKeys = $jumpDict.Keys
   For $i = 0 To $jumpDict.Count - 1
	  Local $fullPath = $dictKeys[$i]
	  ;Checks if path points to a file to be copied
	  If StringRegExp($fullPath, '\.\w*$') Then
		 Local $md5 = _Crypt_HashFile($fullPath, $CALG_MD5)
		 Local $parentDirectory = StringRegExpReplace($fullPath, '\\[^\\]*$', '')
		 Local $file = StringRegExpReplace($fullPath, '.*\\', '')
		 Local $auto = $shellex & ' ' & $robocopy & ' "' & $parentDirectory & '" "' & $dest & '\Files" "' & $file & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Jump Lists\' & $output & '_JumpList_Auto_Target_RoboCopy_Log.txt"'
		 Local $custom = $shellex & ' ' & $robocopy & ' "' & $parentDirectory & '" "' & $dest & '\Files" "' & $file & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Jump Lists\' & $output & '_JumpList_Custom_Target_RoboCopy_Log.txt"'
		 Local $newFileName = StringRegExpReplace($file, '\.\w*$', '') & '-' & $md5 & StringRegExp($file, '\.\S*$', $STR_REGEXPARRAYMATCH)[0]
		 Local $rename = @ComSpec & ' /c rename "' & $dest & '\Files\' & $file & '" "' & $newFileName & '"'
		 If StringInStr($tsvfile, "Automatic") Then
			ShellExecuteWait($robocopy, ' "' & $parentDirectory & '" "' & $dest & '\Files" ' & $file & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Jump Lists\' & $output & '_JumpList_Auto_Target_RoboCopy_Log.txt"', $tools, "", @SW_HIDE)
			   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $auto & @CRLF)
		 Else
			ShellExecuteWait($robocopy, ' "' & $parentDirectory & '" "' & $dest & '\Files" ' & $file & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Jump Lists\' & $output & '_JumpList_Custom_Target_RoboCopy_Log.txt"', $tools, "", @SW_HIDE)
			   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $custom & @CRLF)
		 EndIf
		 RunWait($rename, "", @SW_HIDE)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $rename & @CRLF)
		 If FileExists($dest & '\Files\' & $newFileName) Then
			$csv[$jumpDict($fullpath)][UBound($csv, $UBOUND_COLUMNS)-1] = $newFileName
		 EndIf
	  Else
		 ContinueLoop
	  EndIf
   Next
   _FileWriteFromArray($EvDir & '\Jump Lists\' & $output & '\' & $tsvfile, $csv)
EndFunc

;8. System Registry RIP
Func SystemRRip()						;Copy the SYSTEM HIV for analysis
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 8. System Registry RIP" & @CRLF)
   Local $sysrip

   If @OSVersion = "WIN_XP" Then
	  $sysrip = $shellex & ' REG SAVE HKLM\SYSTEM "' & $EvDir & 'SYSTEM_' & @ComputerName & '.hiv"'
   Else
	  $sysrip = $shellex & ' REG SAVE HKLM\SYSTEM "' & $EvDir & 'SYSTEM_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($sysrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $sysrip & @CRLF)
EndFunc

;9. Software Registry RIP
Func SoftwareRRip()						;Copy the SOFTWARE HIV for analysis
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 9. Software Registry RIP" & @CRLF)
   Local $softrip

   If @OSVersion = "WIN_XP" Then
	  $softrip = $shellex & ' REG SAVE HKLM\SOFTWARE "' & $EvDir & 'SOFTWARE_' & @ComputerName & '.hiv"'
   Else
	  $softrip = @ComSpec & ' /c REG SAVE HKLM\SOFTWARE "' & $EvDir & 'SOFTWARE_' & @ComputerName & '.hiv"'
   EndIf

   RunWait($softrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $softrip & @CRLF)
EndFunc

;10. Security Registry RIP
Func SecurityRRip()						;Copy the SECURITY HIV for analysis
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 10. Security Registry RIP" & @CRLF)
   Local $secrip

   If @OSVersion = "WIN_XP" Then
	  $secrip = $shellex & ' REG SAVE HKLM\SECURITY "' & $EvDir & 'SECURITY_' & @ComputerName & '.hiv"'
   Else
	  $secrip = $shellex & ' REG SAVE HKLM\SECURITY "' & $EvDir & 'SECURITY_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($secrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $secrip & @CRLF)
EndFunc

;11. SAM Registry RIP
Func SAMRRip()							;Copy the SAM HIV for analysis
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 11. SAM Registry RIP" & @CRLF)
   Local $samrip

   If @OSVersion = "WIN_XP" Then
	  $samrip = $shellex & ' REG SAVE HKLM\SAM "' & $EvDir & 'SAM_' & @ComputerName & '.hiv"'
   Else
	  $samrip = $shellex & ' REG SAVE HKLM\SAM "' & $EvDir & 'SAM_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($samrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $samrip & @CRLF)
EndFunc

;12. HKCU Registry RIP
Func HKCURRip()							;Copy the HKCU HIV for analysis
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 12. HKCU Registry RIP" & @CRLF)
   Local $hkcurip

   If @OSVersion = "WIN_XP" Then
	  $hkcurip = $shellex & ' REG SAVE HKCU "' & $EvDir & '\HKCU_' & @ComputerName & '.hiv"'
   Else
	  $hkcurip = $shellex & ' REG SAVE HKCU "' & $EvDir & '\HKCU_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($hkcurip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $hkcurip & @CRLF)
EndFunc

;13. NTUser Registry RIP
Func NTUserRRip()						;Copy all NTUSER.dat files from each profile
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 13. NTUser Registry RIP" & @CRLF)
   Local $usrFile = $EvDir & "\USERMapping.txt"
   Local $s_Out = ""
   Local $test_OUT = ""
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $ntuserCount = 1

   $h_Proc = Run(@ComSpec & " /c " & 'REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"', "", @SW_HIDE, 0x08)

   While 1
	  $sTemp = StdoutRead($h_Proc)
	  $s_Out &= $sTemp
	  If @error Then ExitLoop
   WEnd
   $aLines = StringRegExp($s_Out, "(?m:^)HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\(S-1-5-21-\d*-\d*-\d*-\S*)",3)
   ;_ArrayDisplay($aLines, "test")

   If Not @error Then
	  For $i = 0 To UBound($aLines) - 1
		 $s_Val = $aLines[$i]
		 $s_Val = StringStripWS($s_Val, 2)
		 _ArrayDisplay($s_Val, "test")
		 Local $nturip
		 $h_Proc = Run(@ComSpec & " /c " & 'REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\' & $s_Val & '" /v ProfileImagePath', "", @SW_HIDE, 0x08)
		 $s_Out = ""
		 While 1
			$sTemp = StdoutRead($h_Proc)
			$s_Out &= $sTemp
			If @error Then ExitLoop
		 WEnd
		 $aPath = StringRegExp($s_Out, "REG_EXPAND_SZ\s*([\S]*)",1)[0]
		 If FileExists ($aPath & '\NTUSER.DAT') Then
			Local $cmd = $robocopy & ' ' & $aPath & ' "' & $RptsDir & '\Evidence" NTUSER.DAT /r:1 /w:3 /log+:"' & $EvDir & 'NTUSER Log Copy.txt"'
			Local $test = RunWait($cmd, "", @SW_HIDE, 0x08)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cmd & @CRLF)

			$sFileOld = $EvDir & 'NTUSER.DAT'
			$sFileRenamed = $EvDir & @ComputerName &'_USER_' & $ntuserCount & '.dat'
			Local $mov = FileMove($sFileOld, $sFileRenamed)

			If $mov = 0 Then
			    Local $hkcurip
			   If @OSVersion = "WIN_XP" Then
				  $hkcurip = $shellex & ' REG SAVE HKEY_USERS\' & $s_Val & ' "' & $EvDir & '\' & @ComputerName &'_USER_' & $ntuserCount & '.dat"'
			   Else
				  $hkcurip = $shellex & ' REG SAVE HKEY_USERS\' & $s_Val & ' "' & $EvDir & '\' & @ComputerName &'_USER_' & $ntuserCount & '.dat" /y'
			   EndIf
			   RunWait($hkcurip, "", @SW_HIDE)
			EndIf

			FileWriteLine($usrFile, "HKEY_USERS\"&$s_Val&":USER_"&$ntuserCount&@CRLF)
			$ntuserCount = $ntuserCount + 1
		 EndIf
	  Next
   EndIf
EndFunc

;14. UsrClass
Func UsrclassE()  						;Search for profiles and initiate the copy of USRCLASS.dat
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 14. UsrClass.dat" & @CRLF)

   Local $OS, $uPath, $usr, $profs, $uDir, $uPath, $uATB

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   $str=''

   While 1
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $uPath & "\" & $profs
	  $uATB = FileGetAttrib($uDir)
	  If StringInStr($uATB, "D") Then $filename = _Usrclass($profs)
	  $str &= $filename & @CRLF
   WEnd

   ;Tanadi Workaround:
   ;$log = FileReadLine("MFTEntries.log",1) will create alot of numeric files in the root folder
   ;This is to ensure that these output are moved to the Evidence folder instead of the root folder
   FileWrite("MFTEntriesOutputFileList.txt", $str)
   $file = FileOpen("MFTEntriesOutputFileList.txt", 0)
   While 1
	  $line = FileReadLine($file)
		 If @error Then ExitLoop
	  FileMove($line, $EvDir)
   WEnd
   FileDelete("MFTEntriesOutputFileList.txt")
EndFunc

Func _Usrclass($prof)					;Performs the function of copying the USRCLASS.dat
   ;Finds the inode number of USRCLASS.DAT within each users' folder
   Local $usrce = $shellex & ' .\Tools\sleuthkit-win32-3.2.3\bin\ifind.exe -n /users/' & $prof & '/appdata/local/microsoft/windows/usrclass.dat \\.\c: > MFTEntries.log'
   RunWait($usrce, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $usrce & @CRLF)
   $log = FileReadLine("MFTEntries.log",1)

   ;Extracts USRCLASS.DAT data using the inode number
   Local $catusrce = $shellex & ' .\Tools\sleuthkit-win32-3.2.3\bin\icat.exe \\.\c: ' & $log & ' > "' & $EvDir & $prof & '-usrclass.dat"'
   RunWait($catusrce, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $catusrce & @CRLF)
   FileDelete("MFTEntries.log")
   Return $log
EndFunc

;15. Master File Table
Func MFTgrab()							;Use iCat to rip a file from NTFS file system
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 15. Master File Table (MFT)" & @CRLF)
   Local $MFTc = $shellex & ' .\Tools\sleuthkit-win32-3.2.3\bin\icat.exe \\.\c: 0 > "' & $EvDir & '$MFTcopy"'

   RunWait($MFTc, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $MFTc & @CRLF)
EndFunc

;16. Mount VSC
Func VSC_ChkCount()						;Count the number of VSC functions selected within the GUI
   Global $r_chk = 0

   If (GUICtrlRead($VS_PF_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_RF_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_JmpLst_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_EvtCpy_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_SYSREG_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_SECREG_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_SAMREG_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_SOFTREG_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_USERREG_chk) = 1) Then $r_chk = $r_chk + 1

EndFunc
Func VSC_Info()

   Local $vscinfo = @ComSpec & ' /c vssadmin list shadows /for=C: > "' & $RptsDir & '\VSC Information.txt"'
   RunWait($vscinfo, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vscinfo & @CRLF)
EndFunc

; To check for list of VSC
; Command: vssadmin List Shadows
Func GetShadowNames()					;Query WMIC for list of Volume Shadow Copy mount points
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 16. Mount Volume Shadow Copy" & @CRLF)
   Local $objWMIService = ObjGet("winmgmts:\\" & $strComputer & "\root\CIMV2")
   Local $colAdapters = $objWMIService.ExecQuery("SELECT * FROM Win32_ShadowCopy", "WQL", $wbemFlagReturnImmediately + $wbemFlagForwardOnly)

   $n = 1
   $str = ''
   For $objList In $colAdapters
	  $str &= $objList.DeviceObject & @CRLF
   Next

   FileWrite($RptsDir & '\VSCmnts.txt', $str)
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: SELECT * FROM Win32_ShadowCopy" & @CRLF)
EndFunc

Func MountVSCs()						;Mount any Volume Shadow Copies found on the PC
   Local $v = 1
   Local $filename = $RptsDir & '\VSCmnts.txt'
   Global $firstMountedVersion = StringRegExp(FileReadLine($filename, 1), '\d*$', $STR_REGEXPARRAYMATCH)[0]
   Global $VSCList[_FileCountLines($filename)+1]

   Do
	  $mntpt = FileReadLine($filename, $v)
	  If $mntpt = "" Then ExitLoop
	  Local $copyNumber = StringRegExp($mntpt, '\d*$', $STR_REGEXPARRAYMATCH)[0]
	  $VSCList[$v-1] = $copyNumber
	  $mntvsccmd = @ComSpec & ' /c mklink /d "C:\VSC_' & $copyNumber & '"' & ' ' & $mntpt & '\'
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $mntvsccmd & @CRLF)
	  Run($mntvsccmd, "", @SW_HIDE)
	  $v = $v + 1
   Until $v = _FileCountLines($filename) + 1
EndFunc

;17. VSC Prefetch
Func VSC_Prefetch()						;Copy Prefetch data from any Volume Shadow Copies
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 17. VSC Prefetch" & @CRLF)
   Local $robocopy = '"' & @ScriptDir & '\Tools\Robocopy.exe"'
   Local $vscpf1 = ''

   For $i = 0 To UBound($VSCList) - 1
	  Local $v = $VSCList[$i]
	  $vscpf1 = $shellex & ' ' & $robocopy & ' "C:\VSC_' & $v & '\Windows\Prefetch" "' & $EvDir & '\VSC_' & $v & '\Prefetch" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & 'VSC_' & $v & '\VSC_' & $v & ' Prefetch Copy Log.txt"'
	  If FileExists("C:\VSC_" & $v) = 1 Then
		 If Not FileExists($EvDir & "\VSC_" & $v &"\Prefetch") Then DirCreate($EvDir & "\VSC_" & $v &"\Prefetch")
		 ShellExecuteWait($robocopy, ' "C:\VSC_' & $v & '\Windows\Prefetch" "' & $EvDir & '\VSC_' & $v & '\Prefetch" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & 'VSC_' & $v & '\VSC_' & $v & ' Prefetch Copy Log.txt"', $tools)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vscpf1 & @CRLF)
	  EndIf
   Next
EndFunc

;18. VSC Recent Folder
Func VSC_RecentFolder()					;Send information to the recent folder copy function (Volume Shadow Copy version)
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 18. VSC Recent Folder" & @CRLF)
   Local 	$usr
   Local 	$profs
   Local 	$uDir
   Local 	$uATB
   Local 	$uPath
   Local 	$OS
   Local 	$robocopy
   Local 	$robocmd
   Local 	$robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local 	$uPath

   For $i = 0 To UBound($VSCList) - 1
	  Local $vrfc = $VSCList[$i]
	  If FileExists("C:\VSC_" & $vrfc) = 1 Then
	  $uPath = "C:\VSC_" & $vrfc & "\Users\"
		 $usr = FileFindFirstFile($uPath & "*.*")
			While 1
			   $profs = FileFindNextFile($usr)
			   If @error then ExitLoop
			   $uDir = $uPath & "\" & $profs
			   $uATB = FileGetAttrib($uDir)
			   If StringInStr($uATB, "D") Then VSC_RobocopyRF($udir, $profs, $vrfc)
			WEnd
	  Else
		 ExitLoop
	  EndIf
   Next
EndFunc

Func VSC_RobocopyRF($path, $output, $vrfc)		;Copy Recent folder from all profiles while maintaining metadata (Volume Shadow Copy version)

   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($EvDir & 'VSC_' & $vrfc & '\Recent LNKs\' & $output) Then DirCreate($EvDir & 'VSC_' & $vrfc & '\Recent LNKs\' & $output)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If $OS = "Users" Then
	  $recPATH = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent"'
   Else
	  $recPATH = '"' & $path & '\Recent"'
   EndIf

   Local $vscrf1 = $robocopy & " " & $recPATH & ' "' & $EvDir & 'VSC_' & $vrfc & '\Recent LNKs\' & $output & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /SL /log:"' & $EvDir & 'VSC_' & $vrfc & '\Recent LNKs\' & $output & '_RecentFolder_Copy.txt"'

   RunWait($vscrf1, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vscrf1 & @CRLF)
EndFunc

;19. VSC JumpLists
Func VSC_JumpLists()					;Provide info to the Jumplist copy function (Volume Shadow Copy version)
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 19. VSC Jumplist" & @CRLF)
   Local 	$usr
   Local 	$profs
   Local 	$uDir
   Local 	$uATB
   Local 	$uPath
   Local 	$OS
   Local 	$robocopy
   Local 	$robocmd

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   For $i = 0 To UBound($VSCList) - 1
	  Local $vjlc = $VSCList[$i]
	  If FileExists("C:\VSC_" & $vjlc) = 1 Then
		 $uPath = "C:\VSC_" & $vjlc & "\Users\"
		 $usr = FileFindFirstFile($uPath & "*.*")
		 While 1
			$profs = FileFindNextFile($usr)
			   If @error then ExitLoop
			$uDir = "C:\VSC_" & $vjlc& "\Users\" & $profs
			$uATB = FileGetAttrib($uDir)
			If StringInStr($uATB, "D") Then VSC_RobocopyJL($udir, $profs, $vjlc)
		 WEnd
   	  Else
		 ExitLoop
	  EndIf
   Next

EndFunc

Func VSC_RobocopyJL($path, $output, $vjlc)		;Copy Jumplist information while maintaining metadata (Volume Shadow Copy version)

   Local $robocopy
   Local $robocmd
   Local $autodest
   Local $customdest
   Local $shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'
   Local $autodest = $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '\Automatic'
   Local $customdest = $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '\Custom'

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($autodest) Then DirCreate($autodest)
   If Not FileExists($customdest) Then DirCreate($customdest)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   $autoexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"'
   $customexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"'

   Local $vscjla1 = $robocopy & " " & $autoexe1 & ' "' & $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '\Automatic" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '_JumpList_Auto_Copy.txt"'
   Local $vscjlc1 = $robocopy & " " & $customexe1 & ' "' & $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '\Custom" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '_JumpList_Custom_Copy.txt"'

   RunWait($vscjla1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vscjla1 & @CRLF)
   RunWait($vscjlc1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vscjlc1 & @CRLF)

EndFunc

;20. VSC Event Copy
Func VSC_EvtCopy()						;Copy all event logs from local machine (Volume Shadow Copy version)
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 20. VSC Event Copy" & @CRLF)
   Local 	$OS
   Local 	$evtdir
   Local 	$evtext
   Local 	$robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local 	$robo7 = '"' & @ScriptDir & '\Tools\robo7.exe"'
   Local 	$evtext = "evtx"

   For $i = 0 To UBound($VSCList) - 1
	  Local $vevc = $VSCList[$i]
	  If FileExists("C:\VSC_" & $vevc) = 1 Then
		 Local $LogDir = $EvDir & "VSC_" & $vevc & '\Logs'
		 Local $evtdir = '"C:\VSC_' & $vevc & '\Windows\system32\winevt\Logs"'
		 If Not FileExists($LogDir) Then DirCreate($LogDir)
		 Local $VSC_EvtCmd = $robo7 & ' "C:\VSC_' & $vevc & '\Windows\system32\winevt\Logs" "' & $EvDir & "VSC_" & $vevc & '\Logs' & '" /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & "VSC_" & $vevc & '\Event Log Copy.txt"'
		 RunWait($VSC_EvtCmd, "", @SW_HIDE)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Copied ." & $evtext & " files from " & $evtdir & "." & @CRLF)
	  Else
		 ExitLoop
	  EndIf
   Next

EndFunc

;21. VSC Registry Hive
Func VSC_RegHiv($hiv)					;Copy Registry Hive from Volume Shadow Copy
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 21. VSC Registry Hive" & @CRLF)
   Local $robo7 = '"' & @ScriptDir & '\Tools\robo7.exe"'

   For $i = 0 To UBound($VSCList) - 1
	  Local $v = $VSCList[$i]
	  If FileExists("C:\VSC_" & $v) = 1 Then
		 Local $vhivout = $EvDir & "VSC_" & $v & "\Registry"
		 Local $vhivfile = "C:\VSC_" & $v & "\Windows\System32\Config"
		 If Not FileExists($vhivout) Then DirCreate($vhivout)
		 Local $vsc_syshivc = $robo7 & ' "' & $vhivfile & '" "' & $vhivout & '" ' & $hiv & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $vhivout & '\SYSTEM_Log_Copy.txt"'
		 RunWait($vsc_syshivc, "", @SW_HIDE)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vsc_syshivc & @CRLF)
	  Else
		 ExitLoop
	  EndIf
   Next
EndFunc

;22. VSC NTUSER
Func VSC_NTUser()						;Copy NTUSER.dat from Volume Shadow Copy
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 22. VSC NTUSER" & @CRLF)
   Local 	$usr
   Local 	$profs
   Local 	$uDir
   Local 	$uATB
   Local 	$uPath
   Local 	$OS
   Local 	$robocopy
   Local 	$robocmd

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   For $i = 0 To UBound($VSCList) - 1
	  Local $vntc = $VSCList[$i]
	  If FileExists("C:\VSC_" & $vntc) = 1 Then

	  $uPath = "C:\VSC_" & $vntc & "\Users\"

	  $usr = FileFindFirstFile($uPath & "*.*")

	  While 1

		 $profs = FileFindNextFile($usr)

			If @error then ExitLoop

		 $uDir = "C:\VSC_" & $vntc& "\Users\" & $profs

		 $uATB = FileGetAttrib($uDir)

		 If StringInStr($uATB, "D") Then VSC_RobocopyNTU($udir, $profs, $vntc)

	  WEnd
 	  Else
		 ExitLoop
	  EndIf
   Next
EndFunc

Func VSC_RobocopyNTU($path, $output, $vntc)	;Copy function for NTUSER.DAT (Volume Shadow Copy version)

   Local $robocopy
   Local $robocmd
   Local $shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'
   Local $ntudest = $EvDir & "VSC_" & $vntc & '\Registry\' & $output


   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($ntudest) Then DirCreate($ntudest)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   $ntl = '"' & $path & '"'

   Local $vscntu1 = $robocopy & " " & $ntl & ' "' & $EvDir & "VSC_" & $vntc & '\Registry\' & $output & '" NTUSER.DAT /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & "VSC_" & $vntc & '\Registry\' & $output & '\' & $output & '_NTUSER_Copy.txt"'

   RunWait($vscntu1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vscntu1 & @CRLF)

EndFunc

;23. Unmount VSC
Func VSC_rmVSC()						;Remove the mounted VSC directories
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 23. Unmount VSC" & @CRLF)
   For $i = 0 To UBound($VSCList) - 1
	  Local $v = $VSCList[$i]
	  Local $vscdir = "C:\VSC_" & $v
	  Local $dirchk = FileExists($vscdir)

	  If $dirchk = 1 Then
		 DirRemove($vscdir)
		 ConsoleWrite($v)
	  Else
		 ExitLoop
	  EndIf
   Next
   FileDelete("VSCmnts.txt")
EndFunc

;24. Sysinternals Reg Key
Func SysIntAdd()						;Add registry key to accept Sysinternals
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 24. SysInternals Registry Key" & @CRLF)
   Local $RegAdd1 = $shellex & ' REG ADD HKCU\Software\Sysinternals\NTFSInfo /v EulaAccepted /t REG_DWORD /d 1 /f'

   RunWait($RegAdd1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $RegAdd1 & @CRLF)
EndFunc

;25. IP
Func IPs()								;Gather network address for the computer
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 25. IP" & @CRLF)
   Local $ip1 = $shellex & ' ipconfig /all > "' & $RptsDir & '\IP Info.txt"'
   Local $ip2 = $shellex & ' netsh int ip show config >> "' & $RptsDir & '\IP Info.txt"'

   RunWait($ip1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $ip1 & @CRLF)
   RunWait($ip2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $ip2 & @CRLF)
EndFunc

;26. DNS
Func DNS()								;Gather DNS information
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 26. DNS" & @CRLF)
   Local $dns1 = $shellex & ' ipconfig /displaydns > "' & $RptsDir & '\DNS Info.txt"'
   Local $dns2 = $shellex & ' nslookup host server >> "' & $RptsDir & '\DNS Info.txt"'

   RunWait($dns1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $dns1 & @CRLF)
   RunWait($dns2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $dns2 & @CRLF)
EndFunc

;27. ARP
Func Arp()								;Gather information regarding ARP
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 27. ARP" & @CRLF)
   Local $arp1 = $shellex & ' arp -a > "' & $RptsDir & '\ARP Info.txt"'

   RunWait($arp1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $arp1 & @CRLF)
EndFunc

;28. NETBIOS
Func NetBIOS()							;Get NetBIOS information
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 28. NETBIOS" & @CRLF)
   Local $nbt1 = @ComSpec & ' /c nbtstat -A 127.0.0.1 > "' & $RptsDir & '\NBTstat.txt"'
   Local $nbt2 = @ComSpec & ' /c nbtstat -a ' & $compName & ' >> "' & $RptsDir & '\NBTstat.txt"'

   RunWait($nbt1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $nbt1 & @CRLF)

   RunWait($nbt2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $nbt2 & @CRLF)
EndFunc

;29. Routes
Func Routes()							;Gather list of active routes
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 29. Routes" & @CRLF)
   Local $route1 = $shellex & ' route PRINT > "' & $RptsDir & '\Routes.txt"'
   Local $route2 = $shellex & ' netstat -r >> "' & $RptsDir & '\Routes.txt"'
   RunWait($route1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $route1 & @CRLF)
   RunWait($route2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $route2 & @CRLF)
EndFunc

;30. Connections
Func Connections()						;Discover any network connections on the PC
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 30. Connections" & @CRLF)
   Local $Conn1 = $shellex & ' netstat -nao > "' & $RptsDir & '\Network Connections.txt"'
   Local $Conn2 = $shellex & ' netstat -naob >> "' & $RptsDir & '\Network Connections.txt"'

   RunWait($Conn1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $Conn1 & @CRLF)
   RunWait($Conn2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $Conn2 & @CRLF)
EndFunc

;31. Connected Sessions
Func ConnectedSessions()				;Gather information on any connected sessions
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 31. Connected Sessions" & @CRLF)
   Local $ConnSes = $shellex & ' net Session > "' & $RptsDir & '\Sessions.txt"'

   RunWait($ConnSes, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $ConnSes & @CRLF)
EndFunc

;32. Shares
Func Shares()							;Gather information on any shared folders
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 32. Shares" & @CRLF)
   Local $share1 = $shellex & ' net share > "' & $RptsDir & '\LocalShares.txt"'

   RunWait($share1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $share1 & @CRLF)
EndFunc

;33. Shared Files
Func SharedFiles()						;Gather information on any shared files
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 33. Shared Files" & @CRLF)
   Local $sfile1 = $shellex & ' net file > "' & $RptsDir & '\Open Shared Files.txt"'

   RunWait($sfile1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $sfile1 & @CRLF)
EndFunc

;34. Workgroups
Func Workgroups()						;Gather possible information on PC Workgroups
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 34. Workgroups" & @CRLF)
   Local $sVar = RegRead("HKLM\System\CurrentControlSet\Services\Tcpip\Parameters", "Domain")
   Local $wkgrp1 = $shellex & ' net view ' & $sVar & ' > "' & $RptsDir & '\Workgroup PC Information.txt"'

   RunWait($wkgrp1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wkgrp1 & @CRLF)
EndFunc

;35. SystemInfo
Func SystemInfo()						;Gather valuable information regarding type of PC
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 35. SystemInfo" & @CRLF)
   Local $sysinfo1 = $shellex & ' .\Tools\SysinternalsSuite\PsInfo -accepteula -s -d > "' & $RptsDir & '\System Info.txt"'
   Local $sysinfo2 = $shellex & ' systeminfo >> "' & $RptsDir & '\System Info.txt"'
   Local $sysinfo3 = $shellex & ' set >> "' & $RptsDir & '\System Variables.txt"'

   RunWait($sysinfo1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $sysinfo1 & @CRLF)
   RunWait($sysinfo2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $sysinfo2 & @CRLF)
   RunWait($sysinfo3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $sysinfo3 & @CRLF)
EndFunc

;36. Processes
Func Processes()						;Gather running process information
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 36. Processes" & @CRLF)
   Local $proc1 = $shellex & ' tasklist /svc > "' & $RptsDir & '\Processes.txt"'
   Local $proc2 = $shellex & ' tasklist /m > "' & $RptsDir & '\Processes.txt"'
   Local $proc3 = $shellex & ' .\Tools\SysinternalsSuite\pslist -accepteula >> "' & $RptsDir & '\Processes.txt"'
   Local $proc4 = $shellex & ' .\Tools\SysinternalsSuite\pslist -t -accepteula >> "' & $RptsDir & '\Processes.txt"'

   RunWait($proc1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $proc1 & @CRLF)
   RunWait($proc2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $proc2 & @CRLF)
   RunWait($proc3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $proc3 & @CRLF)
   RunWait($proc4, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $proc3 & @CRLF)
EndFunc

;37. Services
Func Services()							;Pertinent services information
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 37. Services" & @CRLF)
   Local $serv1 = $shellex & ' .\Tools\SysinternalsSuite\psservice -accepteula > "' & $RptsDir & '\Services.txt"'
   Local $serv2 = $shellex & ' sc queryex >> "' & $RptsDir & '\Services.txt"'
   Local $serv3 = $shellex & ' net start >> "' & $RptsDir & '\Services.txt"'

   RunWait($serv1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $serv1 & @CRLF)
   RunWait($serv2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $serv2 & @CRLF)
   RunWait($serv3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $serv3 & @CRLF)
EndFunc

;38. Account Information
Func AccountInfo()						;Gather information pertaining to the user accounts
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 38. Account Information" & @CRLF)
   Local $acctinfo1 = $shellex & ' net accounts > "' & $RptsDir & '\Account Details.txt"'

   RunWait($acctinfo1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $acctinfo1 & @CRLF)
EndFunc

;39. AutoRun
Func AutoRun()							;Information regarding startup
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 39. AutoRun" & @CRLF)
   ;NOTE: -a = All, -c = csv output
   Local $autorun = $shellex & ' .\Tools\SysinternalsSuite\autorunsc.exe -accepteula -c > "' & $RptsDir & '\AutoRun Info.csv"'

   RunWait($autorun, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autorun & @CRLF)
EndFunc

;40. AutoRun Target
Func AutoRun_Target()					;Copy autorun target files
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 40. AutoRun Target" & @CRLF)
   Local $intCount = 0, $linecount = 0
   Local $csv, $prefetchfile[1]
   Local $driveDict = ObjCreate("Scripting.Dictionary")
   Local $filename = $RptsDir & '\AutoRun Info.csv'
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   If Not FileExists($EvDir & "\Autorun") Then DirCreate($EvDir & "\Autorun")
   While _WinAPI_FileInUse($filename) = 1
       sleep(10)
   WEnd
   _FileReadToArray($filename, $csv)
   If IsArray($csv) Then
	  For $i = 1 To $csv[0]
		 $temp = StringSplit($csv[$i], ",")
		 Sleep(1)
		 If StringLen($temp[9]) <> 0 Then
			Local $fullPath = StringReplace($temp[9],'"', "")
			Local $parentDirectory = StringRegExpReplace($fullPath, '\\[^\\]*$', '')
			Local $file = StringRegExpReplace($fullPath, '.*\\', '')
			Local $autorun = $robocopy & ' "' & $parentDirectory & '" "' & $EvDir & '\Autorun" "' & $file & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:"' & $RptsDir & '\AutoRun_Target_RoboCopy_Log.txt"'
			RunWait($autorun, @ScriptDir & '\Tools', @SW_HIDE)
			   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autorun & @CRLF)
		 EndIf
	  Next
   EndIf
EndFunc

;41. SRUM
Func Srum()						;Gather information pertaining to the user accounts
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 41. SRUM" & @CRLF)
   ;Local $srumdump = @ScriptDir & '\Tools\srum-dump'
   ;Local $srum1 = $shellex & ' "cd /d ' & $srumdump & ' && srum_dump.exe -i "' & $EvDir & '\SRUDB.dat' & '" -o "' & $EvDir & '\SRUM_DUMP_Output_Report.xls"'
   Local $robocopy = '"' & @ScriptDir & '\Tools\Robocopy.exe"'
   Local $pf1 = @ComSpec & ' /c ' & $robocopy & ' "' & @WindowsDir & '\System32\sru" "' & $RptsDir & '\Evidence" SRUDB.dat /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\SRU Copy Log.txt"'

   ShellExecuteWait($robocopy, '"' & @WindowsDir & '\System32\sru" "' & $RptsDir & '\Evidence" "SRUDB.dat" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\Evidence\SRU Copy Log.txt"', $tools, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $pf1 & @CRLF)
   ;SRUDB file to be processed by Magneto
   ;RunWait($srum1, "")
	  ;FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $srum1 & @CRLF)
EndFunc

;42. Schedule Tasks
Func ScheduledTasks()					;List any scheduled tasks
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 42. Scheduled Tasks" & @CRLF)
   If @OSVersion = "WIN_XP" Then
	  Local $schedtask1 = $shellex & ' at > "' & $RptsDir & '\Scheduled Tasks.txt"'
   Else
	  Local $schedtask1 = $shellex & ' schtasks > "' & $RptsDir & '\Scheduled Tasks.txt"'
   EndIf

   RunWait($schedtask1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $schedtask1 & @CRLF)
EndFunc

;43. File Association
Func FileAssociation()					;Get information on file associations
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 43. File Association" & @CRLF)
   Local $fa1 = $shellex & ' .\Tools\SysinternalsSuite\handle -a -accepteula c > "' & $RptsDir & '\Handles.txt"'

   RunWait($fa1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $fa1 & @CRLF)
EndFunc

;44. Hostname
Func Hostname()							;Gather information on the hostname
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 44. Hostname" & @CRLF)
   Local $hostn1 = $shellex & ' whoami > "' & $RptsDir & '\Hostname.txt"'
   Local $hostn2 = $shellex & ' hostname >> "' & $RptsDir & '\Hostname.txt"'

   RunWait($hostn1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $hostn1 & @CRLF)
   RunWait($hostn2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $hostn2 & @CRLF)
EndFunc

;45. User Info
Func UsrInfo()							;Gather list of user accounts
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 45. User Info" & @CRLF)
   Local $usrinfo = $shellex & ' net user > "' & $RptsDir & '\User Account Information.txt"'
   RunWait($usrinfo, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $usrinfo & @CRLF)
EndFunc

;46. NTFS Information
Func NTFSInfo()							;Gather information regarding NTFS
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 46. NTFSInfo" & @CRLF)
   Local $ntfs1 = $shellex & ' .\Tools\SysinternalsSuite\ntfsinfo c > "' & $RptsDir & '\NTFS Info.txt"'
   Local $ntfs2 = $shellex & ' fsutil fsinfo ntfsinfo C: >> "' & $RptsDir & '\NTFS Info.txt"'

   RunWait($ntfs1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $ntfs1 & @CRLF)
   RunWait($ntfs2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $ntfs2 & @CRLF)
EndFunc

;47. Volume Information
Func VolInfo()							;Gather volume information
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 47. Volume Info" & @CRLF)
   Local $vol1 = $shellex & ' fsutil fsinfo volumeinfo C: >> "' & $RptsDir & '\Volume Info.txt"'

   RunWait($vol1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vol1 & @CRLF)
EndFunc

;48. Mounted Disk
Func MountedDisk()						;Mounted Disk Information
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 48. Mounted Disk" & @CRLF)
   Local $md1 = $shellex & ' .\Tools\SysinternalsSuite\diskext -accepteula > "' & $RptsDir & '\Disk Mounts.txt"'

   RunWait($md1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $md1 & @CRLF)
EndFunc

;49. Directory Listing
Func Directory()						;Get list of directory structure
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 49. Directory Info" & @CRLF)
   Local $dir1 = $shellex & ' tree c:\ /f /a > "' & $RptsDir & '\Directory Info.txt"'

   RunWait($dir1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $dir1 & @CRLF)
EndFunc

;50. Event Logs
Func EvtCopy()							;Copy all event logs from local machine
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 50. Event Copy" & @CRLF)
   Local $OS
   Local $evtdir
   Local $evtext
   Local $LogDir = $EvDir & 'Logs'
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $robo7 = '"' & @ScriptDir & '\Tools\robo7.exe"'

   Local $evtc1 = $shellex & ' .\Tools\SysinternalsSuite\psloglist.exe -accepteula Application > "' & $RptsDir & '\Application Log.csv"'
   Local $evtc2 = $shellex & ' .\Tools\SysinternalsSuite\psloglist.exe -accepteula System > "' & $RptsDir & '\System Log.csv"'
   Local $evtc3 = $shellex & ' .\Tools\SysinternalsSuite\psloglist.exe -accepteula Security > "' & $RptsDir & '\Security Log.csv"'

   RunWait($evtc1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $evtc1 & @CRLF)

   RunWait($evtc2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $evtc2 & @CRLF)

   RunWait($evtc3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $evtc3 & @CRLF)

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Docs" Then $evtdir = '"C:\Windows\system32\config"'
   If $OS = "Users" Then $evtdir = '"C:\Windows\system32\winevt\Logs"'

   If $OS = "Docs" Then $evtext = "evt"
   If $OS = "Users" Then $evtext = "evtx"

   If Not FileExists($LogDir) Then DirCreate($LogDir)

   If $OS = "Docs" Then $EvtCmd = $robocopy & " " & $evtdir & ' "' & $LogDir & '" *.' & $evtext & ' /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\Event Log Copy.txt"'
   If $OS = "Users" Then $EvtCmd = $robo7 & " " & $evtdir & ' "' & $LogDir & '" /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\Event Log Copy.txt"'

   RunWait($EvtCmd, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Copied ." & $evtext & " files from " & $evtdir & "." & @CRLF)
EndFunc

;51. DC Info
Func dcInfo()
   ;Get Domain Controller Information
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 51. DC Information" & @CRLF)
   Local $nltest = @ComSpec & ' /c nltest /dclist: > "' & $RptsDir & '\nltest.txt"'
   RunWait($nltest, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $nltest & @CRLF)
EndFunc

;52. WMI Timezone
Func wmi_tz()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 52. WMI Timezone" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-Timezone.csv"' & ' timezone list brief /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;53. WMI User
Func wmi_usr()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 53. WMI User" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-UserAccountList.csv"' & ' useraccount list /format:csv'
   Local $wmi2 = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-UserAccountAll.csv"' & ' useraccount get /ALL /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
   RunWait($wmi2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi2 & @CRLF)
EndFunc

;54. WMI Model
Func wmi_model()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 54. WMI Model" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-Model.csv"' & ' csproduct get name /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;55. WMI Warranty
Func wmi_warranty()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 55. WMI Warranty" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-SerialNumber.csv"' & ' bios get serialnumber /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;56. WMI NIC
Func wmi_nic()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 56. WMI NIC" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-NIC.csv"' & ' nicconfig get description,IPAddress,MACaddress /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;57. WMI Manufacturer
Func wmi_manu()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 57. WMI Manufacturer" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-Manufacturer.csv"' & ' computersystem get manufacturer /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;58. WMI Software
Func wmi_software()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 58. WMI Software" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-Software.csv"' & ' product list /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;59. WMI Events
Func wmi_evt()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 59. WMI Events" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-EventLogName.csv"' & ' nteventlog get name /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;60. WMI Processes
Func wmi_proc()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 60. WMI Processes" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-ProcessStatus.csv"' & ' process list status /format:csv'
   Local $wmi2 = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-ProcessMemory.csv"' & ' process list memory /format:csv'
   Local $wmi3 = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-ProcessGet.csv"' & ' process get caption,executablepath,commandline /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
   RunWait($wmi2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi2 & @CRLF)
   RunWait($wmi3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi3 & @CRLF)

      ;Outputs Process and Loaded DLLs
   Local $objWMIProcess = ObjGet("winmgmts:\\localhost\root\cimv2")
   Local $objWMIService = ObjGet("winmgmts:\\localhost\root\cimv2")
   Local $colAdapters = $objWMIService.ExecQuery("Select * from Win32_PerfFormattedData_PerfProc_FullImage_Costly","WQL", $wbemFlagReturnImmediately + $wbemFlagForwardOnly)
   $str = ''
   For $objList In $colAdapters
	  $str &= $objList.Name & "/"
	  $processName = StringSplit($objList.Name, '/')[1] & ".exe"
	  $query = "Select * from Win32_Process Where Name='" & $processName & "'"
	  Local $pids = $objWMIProcess.ExecQuery($query,"WQL", $wbemFlagReturnImmediately + $wbemFlagForwardOnly)
	  For $pid in $pids
		 $str &= $pid.ProcessID
	  Next
	  $str &= @CRLF
   Next
   FileWrite($RptsDir & '\ProcessDLLs.txt', $str)
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: Select * from Win32_PerfFormattedData_PerfProc_FullImage_Costly; Select * from Win32_Process" & @CRLF)
EndFunc

;61. WMI Jobs
Func wmi_job()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 61. WMI Jobs" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-JobList.csv"' & ' job list brief /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;62. WMI Startup
Func wmi_startup()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 62. WMI Startup" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-StartupBrief.csv"' & ' startup list brief /format:csv'
   Local $wmi2 = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-StartupFull.csv"' & ' startup list full /format:csv'
   Local $wmi3 = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-StartupGet.csv"' & ' startup get caption,command /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
   RunWait($wmi2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi2 & @CRLF)
   RunWait($wmi3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi3 & @CRLF)
EndFunc

;63. WMI Domain
Func wmi_domain()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 63. WMI Domain" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-Domain.csv"' & ' ntdomain /format:csv'
   Local $wmi2 = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-DomainBrief.csv"' & ' ntdomain list brief /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
   RunWait($wmi2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi2 & @CRLF)
EndFunc

;64. WMI Services
Func wmi_service()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 64. WMI Services" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-Service.csv"' & ' service list config /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;65. WMI BIOS
Func wmi_bios()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 65. WMI BIOS" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-Bios.csv"' & ' bios /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;66. WMI HD
Func wmi_hd()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 66. WMI HD" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-Harddrive.csv"' & ' logicaldisk where drivetype=3 get name, freespace, systemname, filesystem, size, volumeserialnumber /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;67. WMI Share
Func wmi_share()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 67. WMI Share" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-ShareDriveInfo.csv"' & ' share get /ALL /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;68. WMI Hotfix
Func wmi_hotfix()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 68. WMI Hotfix" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-HotFix.csv"' & ' qfe get Hotfixid /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;69. WMI Product Key
Func wmi_prodkey()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 69. WMI Product Key" & @CRLF)
   Local $wmi = @ComSpec & ' /c wmic /output:"' & $RptsDir & '\wmi-ProductKey.csv"' & ' path SoftwareLicensingService get OA3xOriginalProductKey /format:csv'

   RunWait($wmi, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $wmi & @CRLF)
EndFunc

;70. Browser Cache
Func bwsr_cache()						;Send information to the recent folder copy function
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 70. Browser Cache" & @CRLF)
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $uPath & $profs
	  $uATB = FileGetAttrib($uDir)
	  If Not FileExists($BrowserDir & $profs) Then DirCreate($BrowserDir & $profs)
	  If StringInStr($uATB, "D") Then
		 If Not FileExists($BrowserDir & $profs & '\Mozilla') Then DirCreate($BrowserDir & $profs & '\Mozilla')
		 If Not FileExists($BrowserDir & $profs & '\Mozilla\Cache_Files') Then DirCreate($BrowserDir & $profs & '\Mozilla\Cache_Files')
		 mozilla_cache($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\IE') Then DirCreate($BrowserDir & $profs & '\IE')
		 If Not FileExists($BrowserDir & $profs & '\IE\Cache_Files') Then DirCreate($BrowserDir & $profs & '\IE\Cache_Files')
		 ie_cache($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\Chrome') Then DirCreate($BrowserDir & $profs & '\Chrome')
		 If Not FileExists($BrowserDir & $profs & '\Chrome\Cache_Files') Then DirCreate($BrowserDir & $profs & '\Chrome\Cache_Files')
		 chrome_cache($uDir, $profs)
	  EndIf
   WEnd
EndFunc

Func mozilla_cache($uDir, $profs)
   Local $OS
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Local\Mozilla\Firefox\Profiles\"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"

   ;Finds for .default mozilla profile
   $bwsrprofiles = FileFindFirstFile($uDir & "*.*")
   $bwsrprofile = FileFindNextFile($bwsrprofiles)
   $uDir = $uDir & $bwsrprofile & "\"

   ;Finds for cache folder
   $cachefolders = FileFindFirstFile($uDir & "cache*")
   $cachefolder = FileFindNextFile($cachefolders)
   $uDir = $uDir & $cachefolder

   Local $mozillacache = ' .\Tools\nirsoft_package\NirSoft\mozillacacheview'
   Local $cache1a = $shellex & $mozillacache & ' -folder "' & $uDir & '" /scomma "' & $BrowserDir & $profs & '\Mozilla\Mozilla Cache.csv"'
   Local $cache1b = $shellex & $mozillacache & ' -folder "' & $uDir & '" /copycache "" "" /CopyFilesFolder "' & $BrowserDir & $profs & '\Mozilla\Cache_Files" /Use      SiteDirStructure 0'
   RunWait($cache1a, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1a & @CRLF)
   RunWait($cache1b, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1b & @CRLF)
EndFunc

Func ie_cache($uDir, $profs)
   Local $OS
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Local\Microsoft\Windows\WebCache"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Local Settings\Temporary Internet Files"

   Local $iecache = ' .\Tools\nirsoft_package\NirSoft\iecacheview'
   Local $cache1a = $shellex & $iecache & ' -folder "' & $uDir & '" /scomma "' & $BrowserDir & $profs & '\IE\IE Cache.csv"'
   Local $cache1b = $shellex & $iecache & ' -folder "' & $uDir & '" /copycache "" "" /CopyFilesFolder "' & $BrowserDir & $profs & '\IE\Cache_Files" /UseWebSiteDirStructure 0'
   RunWait($cache1a, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1a & @CRLF)
   RunWait($cache1b, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1b & @CRLF)
EndFunc

Func chrome_cache($uDir, $profs)
   Local $OS
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\Default\Cache"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Google\Chrome\User Data\Default\Cache"

   Local $chromecache = ' .\Tools\nirsoft_package\NirSoft\chromecacheview'
   Local $cache1a = $shellex & $chromecache & ' -folder "' & $uDir & '" /scomma "' & $BrowserDir & '\' & $profs & '\Chrome\Chrome Cache.csv"'
   Local $cache1b = $shellex & $chromecache & ' -folder "' & $uDir & '" /copycache "" "" /CopyFilesFolder "' & $BrowserDir & $profs & '\Chrome\Cache_Files" /UseWebSiteDirStructure 0'
   RunWait($cache1a, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1a & @CRLF)
   RunWait($cache1b, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1b & @CRLF)
EndFunc

;71. Browser History
Func bwsr_hist()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 71. Browser History" & @CRLF)
   Local $browserHistory = ' .\Tools\nirsoft_package\NirSoft\browsinghistoryview'
   Local $hist = $shellex & $browserHistory & ' /HistorySource 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome1 /LoadSafari 1 /scomma "' & $BrowserDir & '\Browser History.csv"'

   RunWait($hist, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $hist & @CRLF)
EndFunc

;72. Browser Favourites
Func bwsr_fav()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 72. Browser Favourites" & @CRLF)
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   ;Nirsoft faview does not allow users to specify bookmarks folder from CLI
   ;Local $browserFav = ' .\Tools\nirsoft_package\NirSoft\faview'
   ;Local $fav = $shellex & $browserFav & ' /scomma "' & $BrowserDir & '\Browser Bookmarks-IE.csv" /browser 1'
   ;Local $fav2 = $shellex & $browserFav & ' /scomma "' & $BrowserDir & '\Browser Bookmarks-Mozilla.csv" /browser 2'

   ;RunWait($fav, "", @SW_HIDE)
	  ;FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $fav & @CRLF)
   ;RunWait($fav2, "", @SW_HIDE)
	  ;FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $fav2 & @CRLF)

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $uPath & $profs
	  $uATB = FileGetAttrib($uDir)
	  If Not FileExists($BrowserDir & $profs) Then DirCreate($BrowserDir & $profs)
	  If StringInStr($uATB, "D") Then
		 If Not FileExists($BrowserDir & $profs & '\Mozilla') Then DirCreate($BrowserDir & $profs & '\Mozilla')
		 mozilla_fav($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\IE') Then DirCreate($BrowserDir & $profs & '\IE')
		 ie_fav($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\Chrome') Then DirCreate($BrowserDir & $profs & '\Chrome')
		 chrome_fav($uDir, $profs)
	  EndIf
   WEnd
EndFunc

Func mozilla_fav($uDir, $profs)
   Local $OS
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"
   If $OS = "Users" Then $uDir = $uDir & "\AppData\Roaming\Mozilla\Firefox\Profiles\"

   ;Finds for .default mozilla profile
   $bwsrprofiles = FileFindFirstFile($uDir & "*.*")
   $bwsrprofile = FileFindNextFile($bwsrprofiles)
   $uDir = $uDir & $bwsrprofile

   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $bookmarks = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\Mozilla" "places.sqlite" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\Mozilla\MozillaBookmarks_RoboCopy_Log.txt"'
   RunWait($bookmarks, @ScriptDir & '\Tools', @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $bookmarks & @CRLF)
EndFunc

Func ie_fav($uDir, $profs)
   If FileExists($uDir & "\Favorites") Then
	  $uDir = $uDir & "\Favorites"
	  Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
	  Local $bookmarks = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\IE\Bookmarks" /copyall /S /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\IE\IEBookmarks_RoboCopy_Log.txt"'
	  If Not FileExists($BrowserDir & $profs & '\IE\Bookmarks') Then DirCreate($BrowserDir & $profs& '\IE\Bookmarks')
	  RunWait($bookmarks, @ScriptDir & '\Tools', @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $bookmarks & @CRLF)
   EndIf
EndFunc

Func chrome_fav($uDir, $profs)
   Local $OS
   Local $chromeProfs
   Local $rootDir
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Google\Chrome\User Data\"
   $rootDir = $uDir

   If FileExists($uDir & "\Default") Then
	  $uDir = $uDir & "\Default"
	  $chromeProfs = "Default"
	  chrome_fav_robocopy($uDir, $profs, $chromeProfs)

	  $chromeProfiles = FileFindFirstFile($rootDir & "Profile *")
	  While $chromeProfiles
		 $chromeProfile = FileFindNextFile($chromeProfiles)
			If @error then ExitLoop
		 $uDir = $rootDir & '\' & $chromeProfile
		 $chromeProfs = $chromeProfile
		 $uATB = FileGetAttrib($uDir)
		 chrome_fav_robocopy($uDir, $profs, $chromeProfs)
	  WEnd
   EndIf
EndFunc

Func chrome_fav_robocopy($uDir, $profs, $chromeProfs)
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $bookmarks = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '" "Bookmarks.bak" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '\ChromeBookmarks_RoboCopy_Log.txt"'
   If Not FileExists($BrowserDir & $profs & '\Chrome\' & $chromeProfs) Then DirCreate($BrowserDir & $profs & '\Chrome\' & $chromeProfs)
   RunWait($bookmarks, @ScriptDir & '\Tools', @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $bookmarks & @CRLF)
EndFunc

;73. Browser Cookies
Func bwsr_cookies()						;Send information to the recent folder copy function
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 73. Browser Cookies" & @CRLF)
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $uPath & $profs
	  $uATB = FileGetAttrib($uDir)
	  If Not FileExists($BrowserDir & $profs) Then DirCreate($BrowserDir & $profs)
	  If StringInStr($uATB, "D") Then
		 If Not FileExists($BrowserDir & $profs & '\Mozilla') Then DirCreate($BrowserDir & $profs & '\Mozilla')
		 mozilla_cookies($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\IE') Then DirCreate($BrowserDir & $profs & '\IE')
		 ie_cookies($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\Chrome') Then DirCreate($BrowserDir & $profs & '\Chrome')
		 chrome_cookies($uDir, $profs)
	  EndIf
   WEnd
EndFunc

Func mozilla_cookies($uDir, $profs)
   Local $OS
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Roaming\Mozilla\Firefox\Profiles\"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"

   ;Finds for .default mozilla profile
   $bwsrprofiles = FileFindFirstFile($uDir & "*.*")
   $bwsrprofile = FileFindNextFile($bwsrprofiles)
   $uDir = $uDir & $bwsrprofile & "\cookies.sqlite"

   Local $mozillacookies = ' .\Tools\nirsoft_package\NirSoft\mzcv'
   Local $cookies = $shellex & $mozillacookies & ' /stab "' & $BrowserDir & '\' & $profs & '\Mozilla\Mozilla Cookies.tsv" -cookiesfile "' & $uDir & '"'
   RunWait($cookies, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cookies & @CRLF)
EndFunc

Func ie_cookies($uDir, $profs)
   If FileExists($uDir & "\Cookies") Then
	  $uDir = $uDir & "\Cookies"
   ElseIf FileExists($uDir & "\AppData\Roaming\Microsoft\Windows\Cookies") Then
	  $uDir = $uDir & "\AppData\Roaming\Microsoft\Windows\Cookies"
   ElseIf FileExists($uDir & "\AppData\Local\Microsoft\Windows\INetCookies") Then
	  $uDir = $uDir & "\AppData\Local\Microsoft\Windows\INetCookies"
   Else
	  Return
   EndIf

   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $cookies = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\IE\IE Cookies" /copyall /S /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\IE\IECookies_RoboCopy_Log.txt"'
   RunWait($cookies, @ScriptDir & '\Tools', @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cookies & @CRLF)
EndFunc

Func chrome_cookies($uDir, $profs)
   Local $OS
   Local $chromeProfs
   Local $rootDir
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Google\Chrome\User Data\"
   $rootDir = $uDir

   If FileExists($uDir & "\Default") Then
	  $uDir = $uDir & "\Default"
	  $chromeProfs = "Default"
	  chrome_cookies_robocopy($uDir, $profs, $chromeProfs)

	  $chromeProfiles = FileFindFirstFile($rootDir & "Profile *")
	  While $chromeProfiles
		 $chromeProfile = FileFindNextFile($chromeProfiles)
			If @error then ExitLoop
		 $uDir = $rootDir & '\' & $chromeProfile
		 $chromeProfs = $chromeProfile
		 $uATB = FileGetAttrib($uDir)
		 chrome_cookies_robocopy($uDir, $profs, $chromeProfs)
	  WEnd
   EndIf
EndFunc

Func chrome_cookies_robocopy($uDir, $profs, $chromeProfs)
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $cookies = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '" "Cookies" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '\ChromeCookies_RoboCopy_Log.txt"'
   If Not FileExists($BrowserDir & $profs & '\Chrome\' & $chromeProfs) Then DirCreate($BrowserDir & $profs & '\Chrome\' & $chromeProfs)
   RunWait($cookies, @ScriptDir & '\Tools', @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cookies & @CRLF)
EndFunc

;74. Browser Downloads
Func bwsr_dl()						;Send information to the recent folder copy function
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 74. Browser Downloads" & @CRLF)
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $uPath & $profs
	  $uATB = FileGetAttrib($uDir)
	  If Not FileExists($BrowserDir & $profs) Then DirCreate($BrowserDir & $profs)
	  If StringInStr($uATB, "D") Then
		 If Not FileExists($BrowserDir & $profs & '\Mozilla') Then DirCreate($BrowserDir & $profs & '\Mozilla')
		 mozilla_download($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\IE') Then DirCreate($BrowserDir & $profs & '\IE')
		 ;ie_cookies($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\Chrome') Then DirCreate($BrowserDir & $profs & '\Chrome')
		 chrome_download($uDir, $profs)
	  EndIf
   WEnd
EndFunc

Func mozilla_download($uDir, $profs)
   Local $OS
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Roaming\Mozilla\Firefox\Profiles\"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"

   ;Finds for .default mozilla profile
   $bwsrprofiles = FileFindFirstFile($uDir & "*.*")
   $bwsrprofile = FileFindNextFile($bwsrprofiles)
   $uDir = $uDir & $bwsrprofile

   Local $mozilladownload = ' .\Tools\nirsoft_package\NirSoft\firefoxdownloadsview'
   Local $downloads = $shellex & $mozilladownload & ' /profile "' & $uDir & '" /scomma "' & $BrowserDir & '\' & $profs & '\Mozilla\Mozilla Downloads.csv"'
   RunWait($downloads, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $downloads & @CRLF)
EndFunc

Func chrome_download($uDir, $profs)
   Local $OS
   Local $chromeProfs
   Local $rootDir
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Google\Chrome\User Data\"
   $rootDir = $uDir

   If FileExists($uDir & "\Default") Then
	  $uDir = $uDir & "\Default"
	  $chromeProfs = "Default"
	  chrome_download_robocopy($uDir, $profs, $chromeProfs)

	  $chromeProfiles = FileFindFirstFile($rootDir & "Profile *")
	  While $chromeProfiles
		 $chromeProfile = FileFindNextFile($chromeProfiles)
			If @error then ExitLoop
		 $uDir = $rootDir & '\' & $chromeProfile
		 $chromeProfs = $chromeProfile
		 $uATB = FileGetAttrib($uDir)
		 chrome_download_robocopy($uDir, $profs, $chromeProfs)
	  WEnd
   EndIf
EndFunc

Func chrome_download_robocopy($uDir, $profs, $chromeProfs)
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $download = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '" "History" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '\ChromeHistory_RoboCopy_Log.txt"'
   If Not FileExists($BrowserDir & $profs & '\Chrome\' & $chromeProfs) Then DirCreate($BrowserDir & $profs & '\Chrome\' & $chromeProfs)
   RunWait($download, @ScriptDir & '\Tools', @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $download & @CRLF)
EndFunc

;75. Browser Autocomplete
Func bwsr_autocomplete()						;Send information to the recent folder copy function
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 75. Browser Autocomplete" & @CRLF)
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $uPath & $profs
	  $uATB = FileGetAttrib($uDir)
	  If Not FileExists($BrowserDir & $profs) Then DirCreate($BrowserDir & $profs)
	  If StringInStr($uATB, "D") Then
		 If Not FileExists($BrowserDir & $profs & '\Mozilla') Then DirCreate($BrowserDir & $profs & '\Mozilla')
		 mozilla_autocomplete($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\IE') Then DirCreate($BrowserDir & $profs & '\IE')
		 ;ie_cookies($uDir, $profs)

		 If Not FileExists($BrowserDir & $profs & '\Chrome') Then DirCreate($BrowserDir & $profs & '\Chrome')
		 chrome_autocomplete($uDir, $profs)
	  EndIf
   WEnd
EndFunc

Func mozilla_autocomplete($uDir, $profs)
   Local $OS
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Roaming\Mozilla\Firefox\Profiles\"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"

   ;Finds for .default mozilla profile
   $bwsrprofiles = FileFindFirstFile($uDir & "*.*")
   $bwsrprofile = FileFindNextFile($bwsrprofiles)
   $uDir = $uDir & $bwsrprofile

   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $autocomplete = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\Mozilla" "formhistory.sqlite" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\Mozilla\MozillaAutocomplete_RoboCopy_Log.txt"'
   RunWait($autocomplete, @ScriptDir & '\Tools', @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autocomplete & @CRLF)
EndFunc

Func chrome_autocomplete($uDir, $profs)
   Local $OS
   Local $chromeProfs
   Local $rootDir
   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\"
   If $OS = "Docs" Then $uDir = $uDir & "\Application Data\Google\Chrome\User Data\"
   $rootDir = $uDir

   If FileExists($uDir & "\Default") Then
	  $uDir = $uDir & "\Default"
	  $chromeProfs = "Default"
	  chrome_autocomplete_robocopy($uDir, $profs, $chromeProfs)

	  $chromeProfiles = FileFindFirstFile($rootDir & "Profile *")
	  While $chromeProfiles
		 $chromeProfile = FileFindNextFile($chromeProfiles)
			If @error then ExitLoop
		 $uDir = $rootDir & '\' & $chromeProfile
		 $chromeProfs = $chromeProfile
		 $uATB = FileGetAttrib($uDir)
		 chrome_autocomplete_robocopy($uDir, $profs, $chromeProfs)
	  WEnd
   EndIf
EndFunc

Func chrome_autocomplete_robocopy($uDir, $profs, $chromeProfs)
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $autocomplete1 = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '" "Web Data" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '\ChromeAutocomplete_WebData_RoboCopy_Log.txt"'
   Local $autocomplete2 = $robocopy & ' "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '" "Network Action Predictor" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $BrowserDir & '\' & $profs & '\Chrome\' & $chromeProfs & '\ChromeAutocomplete_NetworkActionPredictor_RoboCopy_Log.txt"'
   If Not FileExists($BrowserDir & $profs & '\Chrome\' & $chromeProfs) Then DirCreate($BrowserDir & $profs & '\Chrome\' & $chromeProfs)
   RunWait($autocomplete1, @ScriptDir & '\Tools', @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autocomplete1 & @CRLF)
   RunWait($autocomplete2, @ScriptDir & '\Tools', @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autocomplete2 & @CRLF)
EndFunc

;76. Browser Webcache
Func bwsr_webcache()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 76. Browser Webcache" & @CRLF)
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   If @OSVersion = "WIN_81" Then $OS = "Users"
   If @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $uPath & $profs
	  $uATB = FileGetAttrib($uDir)
	  If StringInStr($uATB, "D") Then
		 If Not FileExists($BrowserDir & $profs & '\IE') Then DirCreate($BrowserDir & $profs & '\IE')
		 If FileExists($uDir & "\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat") Then bwsr_webcache_hobocopy($uDir & "\AppData\Local\Microsoft\Windows\WebCache", $profs)
	  EndIf
   WEnd
EndFunc

Func bwsr_webcache_hobocopy($uDir, $profs)
   Local $OS
   Local $chromeProfs
   Local $rootDir

   Local $webcache = $shellex & ' .\Tools\Hobocopy\HoboCopy.exe "' & $uDir & '" "' & $BrowserDir & '\' & $profs & '\IE" "WebCacheV01.dat"'
   Run($webcache, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $webcache & @CRLF)
EndFunc

;77. Browser Password
Func bwsr_password()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 77. Browser Password" & @CRLF)
   Local $browserPassword = ' .\Tools\nirsoft_package\NirSoft\WebBrowserPassView'
   Local $pass = $shellex & $browserPassword & ' /LoadPasswordsIE 1 /LoadPasswordsFirefox 1 /LoadPasswordsChrome 1 /LoadPasswordsSafari 1 /LoadPasswordsOpera 1 /scomma "' & $BrowserDir & '\Web Passwords.csv"'

   RunWait($pass, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $pass & @CRLF)
EndFunc

;78. Exiftool Metadata
Func exifmetadata()
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 78. Exiftool Metadata" & @CRLF)
   Local $metadata = @ComSpec & ' /c .\Tools\exiftool-10.31\exiftool -r C:\ > "' & $RptsDir & '\exifmetadata.txt"'

   RunWait($metadata, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $metadata & @CRLF)
EndFunc

;79. Firewall
Func Firewall()							;Get the firewall information
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 79. Firewall" & @CRLF)
   Local $fw1 = $shellex & ' netsh firewall show state > "' & $RptsDir & '\Firewall Config.txt"'
   Local $fw2 = $shellex & ' netsh advfirewall show allprofiles >> "' & $RptsDir & '\Firewall Config.txt"'

   RunWait($fw1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $fw1 & @CRLF)
   RunWait($fw2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $fw2 & @CRLF)
EndFunc

;80. Hosts
Func Hosts()							;Gather the HOST file
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 80. Hosts" & @CRLF)
   Local $host1 = $shellex & ' type %systemroot%\System32\Drivers\etc\hosts > "' & $RptsDir & '\Hosts Info.txt"'

   RunWait($host1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $host1 & @CRLF)
EndFunc

;81. Autorun VirusTotal
Func AutorunVTEnabled()							;Running autorunsc with VT checking, TAKES A LONG TIME TO RUN!
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 81. Autorun VT Enabled" & @CRLF)
   ;Autorun default

   ;NOTE: -a = All, -c = csv output
   Local $autorun = $shellex & ' .\Tools\SysinternalsSuite\autorunsc.exe -accepteula -a * -vt -m -c > "' & $RptsDir & '\AutoRun Info VT.csv"'

   RunWait($autorun, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autorun & @CRLF)
EndFunc

;82. Process Explorer VirusTotal
Func ProcexpVTEnabled()							;Running autorunsc with VT checking, TAKES A LONG TIME TO RUN!
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 82. Process Explorer VT Enabled" & @CRLF)
   Local $autorun = $shellex & ' .\Tools\SysinternalsSuite\procexp.exe /e'

   Run($autorun, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autorun & @CRLF)
EndFunc

;83. MD5
Func MD5()								;Special thanks to Jesse Kornblum for his amazing hashing tools
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 83. MD5" & @CRLF)
   Local $md51 = $shellex & ' .\Tools\md5deep -rbtk "' & $HashDir & '" >> "' & $RptsDir & '\MD5 Hashes.txt"'
   Local $md52 = $shellex & ' .\Tools\md5deep64 -rbtk "' & $HashDir & '" >> "' & $RptsDir & '\MD5 Hashes.txt"'

   If @OSArch = "X86" Then
	  $arch = "32"
   Else
	  $arch = "64"
   EndIf

   If $arch = "32" Then
	  RunWait($md51, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $md51 & @CRLF)
   EndIf

   If $arch = "64" Then
	  RunWait($md52, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $md52 & @CRLF)
   EndIf
EndFunc

;84. SHA1
Func SHA1()								;Special thanks to Jesse Kornblum for his amazing hashing tools
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 84. SHA1" & @CRLF)
   Local $sha11 = $shellex & ' .\Tools\sha1deep -rbtk "' & $HashDir & '" >> "' & $RptsDir & '\SHA1 Hashes.txt"'
   Local $sha12 = $shellex & ' .\Tools\sha1deep64 -rbtk "' & $HashDir & '" >> "' & $RptsDir & '\SHA1 Hashes.txt"'

   If @OSArch = "X86" Then
	  $arch = "32"
   Else
	  $arch = "64"
   EndIf

   If $arch = "32" Then
	  RunWait($sha11, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $sha11 & @CRLF)
   EndIf

   If $arch = "64" Then
	  RunWait($sha12, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $sha12 & @CRLF)
   EndIf
EndFunc

;85. Compression
Func Compression()						;Special thanks to the 7-Zip team such a great tool\
   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Currently Executing: 85. Compression" & @CRLF)
   ShellExecuteWait(".\Tools\7za.exe" , 'a -mx9 -r "' & $RptsDir & '" *.txt *.hiv *.raw *.lnk *.dat *.pf *.evt *.evtx *.automaticDestinations-ms *.customDestinations-ms *.csv *.dmp', $tools, "", @SW_HIDE)
EndFunc

Func CommandROSLOG()					;Copy the log data from ReactOS command prompt

   Local $ROSlog = "C:\Commands.log"

   If FileExists($ROSlog) = 1 Then
	  FileMove($ROSlog, $RptsDir)
   EndIf

EndFunc