#Include <GUIConstantsEx.au3>
#Include <WindowsConstants.au3>
#Include <StaticConstants.au3>
#Include <Date.au3>
#Include <File.au3>
#Include <array.au3>
#include <Crypt.au3>
#include <WinAPIFiles.au3>
#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <FileConstants.au3>
;DEBUGGING TIPS: Note that if you run as administrator, the LINE indicated in the error message is inaccurate. Revert to user mode for debugging accuracy.
;DEBUGGING TIP2: If there are no output for VSC functions, select Compile Script (x64) and then run the .exe file as administrator

Global 	$tStamp = @YEAR & @MON & @MDAY & @HOUR & @MIN & @SEC

;Tools Directory
Global 	$tools = '"' &@ScriptDir & '\Tools\'

;Note that in the Tools directory contain cmd.exe from Windows XP
;ZFZF: To update this with a sanitized version

;Using our own cammand prompt instead of the system
Global	$shell = '"' & @ScriptDir & '\Tools\cmd.exe"'
Global 	$shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'

;Logo Image
Global  $image = "zf.jpg"

;ZFZF: How is this used?
Global 	$RecentPath = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Recent")

;Log file
Global 	$ini_file
Global 	$fcnt

;Parameters for WMI Execute Query
Global	$wbemFlagReturnImmediately	= 0x10
Global	$wbemFlagForwardOnly		= 0x20				;DO NOT CHANGE
Global	$strComputer = "."
Global	$compName = @ComputerName

$ini_file = "Triage.ini"

If IsAdmin() = 0 Then
	;MsgBox(64, "Insufficient Privilege Detected", 'Please restart with "RunAs /user:[admin] ' & @ScriptDir & '\TriageIR.exe" or Right-Click "Run As Administrator".')
	;Exit
EndIf

INI_Check($ini_file)

If $GUI_ini = "Yes" Then
   TriageGUI()
EndIf

If $GUI_ini = "No" Then
   INI2Command()
EndIf

Func TriageGUI()						;Creates a graphical user interface for Triage

   Local 	$filemenu, $fileitem1, $fileitem2
   Local 	$iniread, $inidsp
   Local 	$msg, $run, $os
   Global 	$inifile, $tr_tab
   Global 	$Sys_chk, $Proc_chk, $Serv_chk, $FileAssoc_chk, $STsk_chk, $srum_chk, $UsrInfo_chk
   Global 	$Host_chk, $AutoRun_chk, $AutoRun_Target_chk, $AcctInfo_chk, $IPs_chk, $CONN_chk
   Global 	$Routes_chk, $ARP_chk, $DNS_chk, $NBT_chk, $nShare_chk
   Global 	$nFiles_chk, $Sessions_chk, $WrkgrpPC_chk
   Global 	$SYSTEM_chk, $SECURITY_chk, $SAM_chk, $SOFTWARE_chk, $HKCU_chk, $HKU_chk, $UsrC_chk
   Global 	$NTFSInfo_chk, $VolInfo_chk, $DiskMnt_chk, $Tree_chk
   Global 	$MemDmp_chk, $JmpLst_chk, $EvtCpy_chk
   Global 	$PF_chk, $RF_chk, $sysint_chk
   Global 	$PF_Target_chk, $RF_Target_chk, $JmpLst_Target_chk
   Global 	$md5_chk, $sha1_chk, $compress_chk
   Global	$VS_info_chk, $VS_PF_chk, $VS_RF_chk, $VS_JmpLst_chk, $VS_EvtCpy_chk, $VS_SYSREG_chk, $VS_SECREG_chk, $VS_SAMREG_chk, $VS_SOFTREG_chk, $VS_USERREG_chk
   Global	$MFTg_chk

   ;ZF added
   Global	$AutorunVTEnabled_chk
   Global	$bwsr_cache_chk, $bwsr_hist_chk, $bwsr_fav_chk, $bwsr_cookies_chk, $bwsr_dl_chk, $bwsr_autocomplete_chk, $bwsr_webcache_chk, $bwsr_password_chk

   GUICreate("Triage:  KPMG Incident Response", 810, 350)

	  $font = "Arial"

	  GUISetFont(10,400, "",$font)

	  $filemenu = GUICtrlCreateMenu("File")

	  $fileitem1 = GUICtrlCreateMenuItem("Select INI File", $filemenu)

	  GUICtrlCreateMenuItem("", $filemenu, 2) ;empty line

	  $fileitem2 = GUICtrlCreateMenuItem("Exit", $filemenu)

	  $inidsp = StringTrimLeft($ini_file, StringInStr($ini_file, "\", 0, -1))

	  $iniread = GUICtrlCreateLabel("Reading from " & $inidsp & " configuration.", 106, 300, 354, 20, BitOR($SS_SIMPLE, $SS_SUNKEN))

	  $tr_tab = GUICtrlCreateTab(3, 60, 805, 225)

	  ;ZF added

	  GUICtrlCreateTabItem("System Information")

		 ;$AutoRun_chk = GUICtrlCreateCheckbox("AutoRun Information", 10, 90)
			GUICtrlSetTip($AutoRun_chk, "Gather information about system start-up.  Often a source of persistence for intrusions.")
		 ;$AutoRun_Target_chk = GUICtrlCreateCheckbox("Collect AutoRun Target Files", 10, 110)
			GUICtrlSetTip($AutoRun_Target_chk, "Gather all Autorun Target files on the system.")
		 $srum_chk = GUICtrlCreateCheckbox("System Resource Utilization Manager (SRUM) Information", 10, 90)
			GUICtrlSetTip($srum_chk, "Collect SRUM.dat from computer and outputs XLSX file.")

	  GUICtrlCreateTabItem("Registry")

		 $SYSTEM_chk = GUICtrlCreateCheckbox("Save SYSTEM registry hive", 10, 90)
			GUICtrlSetTip($SYSTEM_chk, "Collect a copy of the SYSTEM Registry hive.")
		 $SECURITY_chk = GUICtrlCreateCheckbox("Save SECURITY registry hive", 10, 110)
			GUICtrlSetTip($SECURITY_chk, "Collect a copy of the SECURITY Registry hive.")
		 $SAM_chk = GUICtrlCreateCheckbox("Save SAM registry hive", 10, 130)
			GUICtrlSetTip($SAM_chk, "Collect a copy of the System Account Managment registry hive.")
		 $SOFTWARE_chk = GUICtrlCreateCheckbox("Save SOFTWARE registry hive", 10,150)
			GUICtrlSetTip($SOFTWARE_chk, "Collect a copy of the SOFTWARE registry hive.")
		 $HKCU_chk = GUICtrlCreateCheckbox("Save the Current User registry hive", 10, 170)
			GUICtrlSetTip($HKCU_chk, "Collect the NTUSER.DAT registry hive for just the currently logged in user.")
		 $HKU_chk = GUICtrlCreateCheckbox("Save all user registry hives", 10, 190)
			GUICtrlSetTip($HKU_chk, "Collect the NTUSER.DAT registry hive for all users on the system.")

	  GUICtrlCreateTabItem("Disk Information")

		 $NTFSInfo_chk = GUICtrlCreateCheckbox("NTFS Information", 10, 90)
			GUICtrlSetTip($NTFSInfo_chk, "Gather disk information if formatted with New Technology File System.")
		 $Tree_chk = GUICtrlCreateCheckbox("Directory Information", 10, 110)
			GUICtrlSetTip($Tree_chk, "Print a listing of files on they system and the directory structure.")
		 $VolInfo_chk = GUICtrlCreateCheckbox("Volume Information", 10, 130)
			GUICtrlSetTip($VolInfo_chk, "Get information about the C Drive volume with Sleuth Kit.")

	  GUICtrlCreateTabItem("Evidence Collection")

		 $PF_chk = GUICtrlCreateCheckbox("Collect Prefetch Files", 10, 90)
			GUICtrlSetTip($PF_chk, "Gather all prefetch files on the system to determine file execution.")
		 $PF_Target_chk = GUICtrlCreateCheckbox("Collect Target Prefetch Files", 10, 110)
			GUICtrlSetTip($PF_Target_chk, "Gather all target files of Prefetch.")
		 $RF_chk = GUICtrlCreateCheckbox("Collect Recent Folder Files", 10, 130)
			GUICtrlSetTip($RF_chk, "Gather the link files that have been recently used, for each user.")
		 $RF_Target_chk = GUICtrlCreateCheckbox("Collect Target Recent Folder Files", 10, 150)
			GUICtrlSetTip($RF_Target_chk, "Gather the target files of link files.")
		 $JmpLst_chk = GUICtrlCreateCheckbox("Collect Jump List Files", 10, 170)
			GUICtrlSetTip($JmpLst_chk, "Gather both Automatic and Custom destination jump lists to gain insight into recent files used, for each user.")
		 $JmpLst_Target_chk = GUICtrlCreateCheckbox("Collect Target Jump List Files", 10, 190)
			GUICtrlSetTip($JmpLst_Target_chk, "Gather target files of Automatic and Custom destination jump lists.")
		 $EvtCpy_chk = GUICtrlCreateCheckbox("Collect Event Logs from System.", 10, 210)
			GUICtrlSetTip($EvtCpy_chk, "Copy any event logs on the system.")
		 $UsrC_chk = GUICtrlCreateCheckbox("Collect Profile USRCLASS.dat Files", 10, 230)
			GUICtrlSetTip($UsrC_chk, "Copy the USERCLASS portion of registry for analysis of Windows Shell.")
		 $MFTg_chk = GUICtrlCreateCheckbox("Collect a copy of the MFT", 10, 250)
			GUICtrlSetTip($MFTg_chk, "Collect a copy of the Master File Table for analysis.")

	  GUICtrlCreateTabItem("Browser")

		 $bwsr_cache_chk = GUICtrlCreateCheckbox("Cache Collection", 10, 90)
			GUICtrlSetTip($bwsr_cache_chk, "Collects IE, Mozilla and Chrome cache for later analysis.")
		 $bwsr_hist_chk = GUICtrlCreateCheckbox("History Collection", 10, 110)
			GUICtrlSetTip($bwsr_hist_chk, "Collects IE, Mozilla and Chrome History for later analysis.")
		 $bwsr_fav_chk = GUICtrlCreateCheckbox("Favourites/Bookmarks Collection", 10, 130)
			GUICtrlSetTip($bwsr_fav_chk, "Collects IE and Mozilla Favourites/Bookmarks for later analysis.")
		 $bwsr_cookies_chk = GUICtrlCreateCheckbox("Cookies Collection", 10, 150)
			GUICtrlSetTip($bwsr_cookies_chk, "Collects IE, Mozilla and Chrome Cookies for later analysis.")
		 $bwsr_dl_chk = GUICtrlCreateCheckbox("Download History", 10, 170)
			GUICtrlSetTip($bwsr_dl_chk, "Collects IE, Mozilla and Chrome Cookies download history for later analysis.")
		 $bwsr_autocomplete_chk = GUICtrlCreateCheckbox("AutoComplete Collection", 10, 190)
			GUICtrlSetTip($bwsr_autocomplete_chk, "Collects IE, Mozilla and Chrome Cookies autocomplete history for later analysis.")
		 $bwsr_webcache_chk = GUICtrlCreateCheckbox("Export IE WebCache", 10, 210)
			GUICtrlSetTip($bwsr_webcache_chk, "Exports IE WebCacheV01.dat or IEWebCacheV24.dat.")

	  ;GUICtrlCreateTabItem("Volume Shadow Copies (VSCs)")

		 ;$VS_info_chk = GUICtrlCreateCheckbox("Collect Volume Shadow Copy Information", 10, 60)
			;GUICtrlSetTip($VS_PF_chk, "Outputs Volume Shadow Copy Information to text file.")
		 ;$VS_PF_chk = GUICtrlCreateCheckbox("Collect Prefetch Files from VSCs", 10, 80)
			;GUICtrlSetTip($VS_PF_chk, "Gather Prefetch files through Volume Shadow Copies for historical file execution analysis.")
		 ;$VS_RF_chk = GUICtrlCreateCheckbox("Collect Recent Folder Files from VSCs", 10, 100)
			;GUICtrlSetTip($VS_RF_chk, "Gather links for recent folder for each user in Volume Shadow Copies.")
		 ;$VS_JmpLst_chk = GUICtrlCreateCheckbox("Collect JumpLists from VSCs", 10, 120)
			;GUICtrlSetTip($VS_JmpLst_chk, "Gather Jump List information for each user from Volume Shadow Copies.")
		 ;$VS_EvtCpy_chk = GUICtrlCreateCheckbox("Collect EventLogs from VSCs", 10, 140)
			;GUICtrlSetTip($VS_EvtCpy_chk, "Collect Event Logs occuring through history with Volume Shadow Copies.")
		 ;$VS_SYSREG_chk = GUICtrlCreateCheckbox("Collect SYSTEM hive from VSCs", 10, 160)
			;GUICtrlSetTip($VS_SYSREG_chk, "Collect the SYSTEM registry hive through history with Volume Shadow Copies.")
		 ;$VS_SECREG_chk = GUICtrlCreateCheckbox("Collect SECURITY hive from VSCs", 10, 180)
			;GUICtrlSetTip($VS_SECREG_chk, "Collect the SECURITY registry hive through history with Volume Shadow Copies.")
		 ;$VS_SAMREG_chk = GUICtrlCreateCheckbox("Collect SAM hive from VSCs", 10, 200)
			;GUICtrlSetTip($VS_SAMREG_chk, "Collect the System Account Management registry hive through history with Volume Shadow Copies.")
		 ;$VS_SOFTREG_chk = GUICtrlCreateCheckbox("Collect SOFTWARE hive from VSCs", 10, 220)
			;GUICtrlSetTip($VS_SOFTREG_chk, "Collect the SOFTWARE registry hive through history with Volume Shadow Copies.")
		 ;$VS_USERREG_chk = GUICtrlCreateCheckbox("Collect USER hives from VSCs", 400, 60)
			;GUICtrlSetTip($VS_USERREG_chk, "Collect the NTUSER.dat registry hive through history with Volume Shadow Copies.")

	  GUICtrlCreateTabItem("Options")

		 $md5_chk = GUICtrlCreateCheckbox("Hash all collected files with MD5.", 10,90)
			GUICtrlSetTip($md5_chk, "Use MD5DEEP to hash all gathered evidence items.")
		 $sha1_chk = GUICtrlCreateCheckbox("Hash all collected files with SHA1.", 10, 110)
			GUICtrlSetTip($sha1_chk, "Use SHA1DEEP to hash all gathered evidence items.")
		 $compress_chk = GUICtrlCreateCheckbox("Compress all of collected files and information in an archive.", 10, 130)
			GUICtrlSetTip($compress_chk, "Use 7-zip to compress all collected evidence into one zipped archive.")
		 $sysint_chk = GUICtrlCreateCheckbox("Add Registry Entry for SysInternals Suite.", 10, 150)
			GUICtrlSetTip($sysint_chk, "Add registry entry to eliminate any risk of EULA stopping Sysinternals from running properly.")

	  GUICtrlCreateTabItem("KPMG Customized Scripts")
		 $AutorunVTEnabled_chk = GUICtrlCreateCheckbox("Autorun with VT", 10, 90)
			GUICtrlSetTip($AutorunVTEnabled_chk, "Run Sysinternals autorunsc with Virustotal verification and driver signing")

	  GUICtrlCreateTabItem("") ; end tabitem definition

	  GUICtrlCreateLabel("Evidence Name:", 6, 8, 130)
	  $evName = GUICtrlCreateInput("", 140, 5, 400, 24)

	  GUICtrlCreateLabel("Select Mounted E01:", 6, 33, 130)
	  $Find = GUICtrlCreateInput("", 140, 33, 400, 24)
	  $Browse = GUICtrlCreateButton("Browse", 555, 33, 115, 25)

	  $all = GUICtrlCreateButton("Select All", 480, 290, 80, 30)

	  $none = GUICtrlCreateButton("Select None", 570, 290, 80, 30)

	  $run = GUICtrlCreateButton("Run", 755, 290, 50, 30)

	  $iniimage = GUICtrlCreatePic($image, 3, 285, 95 ,40)

	  _Ini2GUI()

	  GUISetState(@SW_SHOW)

	  While 1

		 $msg = GUIGetMsg()

		 If $msg = $fileitem1 Then
			$ini_file = FileOpenDialog("Choose an INI file:", "C:\", "INI Files (*.ini)")
			INI_Check($ini_file)
			_Ini2GUI()
			GUICtrlSetState($iniread, $GUI_HIDE)
			$inidsp = StringTrimLeft($ini_file, StringInStr($ini_file, "\", 0, -1))
			$iniread = GUICtrlCreateLabel("Reading from " & $inidsp & " configuration.", 106, 262, 354, 20, BitOR($SS_SIMPLE, $SS_SUNKEN))
			GUICtrlSetState($iniread, $GUI_SHOW)
		 EndIf

		 If $msg = $all Then SelectAll()

		 If $msg = $none Then SelectNone()

		 If $msg = $fileitem2 Then ExitLoop

		 If $msg = $GUI_EVENT_CLOSE Then ExitLoop

		 If $msg = $Browse Then GUICtrlSetData($Find, Browse())

		 If $msg = $run Then
			If GUICtrlRead($Find) <> "" And GUICtrlRead($evName) <> "" Then
			   Global $evidenceName = GUICtrlRead($evName)
			   Global $evidencePath = GUICtrlRead($Find)
			   ;Reports Directory
			   Global $RptsDir = @ScriptDir & "\" & $tStamp & " - " & $evidenceName & " Incident"

			   ;Evidence Directory
			   Global $EvDir = $RptsDir & "\Evidence\"

			   ;Browser Directory
			   Global $BrowserDir = $RptsDir & "\Browser\"

			   ;Logs Directory
			   Global $LogsDir = $RptsDir & "\Logs\"

			   Global $HashDir = $RptsDir & "\Evidence"
			   Global $JmpLst = $EvDir & "Jump Lists"
			   Global $Log = $RptsDir & "\Incident Log.txt"
			   ;create directories to store evidence and results
			   If Not FileExists($RptsDir) Then DirCreate($RptsDir)
			   If Not FileExists($EvDir) Then DirCreate($EvDir)
			   If Not FileExists($BrowserDir) Then DirCreate($BrowserDir)
			   If Not FileExists($LogsDir) Then DirCreate($LogsDir)

			   ;create directories to store Tools. This should already exist with Sysinternals inside
			   If Not FileExists(@ScriptDir & "\Tools\") Then
				  Do
					 DirCreate(@ScriptDir & "\Tools\")
				  Until FileExists(@ScriptDir & "\Tools\")
			   EndIf

			   If FileExists(@ScriptDir & '\Tools\SysinternalsSuite\') = 0 Then
				  $sysintchk = MsgBox(0, "Missing Tools", "Missing the Sysinternals Toolset.")
				  ExitLoop
			   EndIf

				  ;Create Triage Process bar
				  $progGUI = GUICreate("Triage Progress", 250, 70, -1, -1, -1, BitOR($WS_EX_TOPMOST, $WS_EX_OVERLAPPEDWINDOW))

				  $progress = GUICtrlCreateProgress(10, 25, 230, 25)

				  ProgChkCount()

				  If (GUICtrlRead($MemDmp_chk) = 1) Then
					 $fcnt = 1
					 GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
				  Else
					 $fcnt = 0
					 GUICtrlSetData($progress, 0)
				  EndIf

				  GUISetState(@SW_SHOW, $progGUI)

			   If (GUICtrlRead($PF_chk) = 1) Then
				  Prefetch()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
				  EndIf

			   If (GUICtrlRead($RF_chk) = 1) Then
				  RecentFolder()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
				  EndIf

			   If (GUICtrlRead($JmpLst_chk) = 1) Then
				  JumpLists()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($PF_Target_chk) = 1) Then
				  Prefetch_Target()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($RF_Target_chk) = 1) Then
				  RecentFolder_Target()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($JmpLst_Target_chk) = 1) Then
				  JumpLists_Target()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($SYSTEM_chk) = 1) Then
				  SystemRRip()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($SOFTWARE_chk) = 1) Then
				  SoftwareRRip()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($HKCU_chk) = 1) Then
				  HKCURRip()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($HKU_chk) = 1) Then
				  NTUserRRip()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($UsrC_chk) = 1) Then
				  UsrclassE()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($SECURITY_chk) = 1) Then
				  SecurityRRip()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($SAM_chk) = 1) Then
				  SAMRRip()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($MFTg_chk) = 1) Then
				  MFTgrab()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   ;ZF Added
			   If (GUICtrlRead($AutorunVTEnabled_chk) = 1) Then
				  ;Function to call
				  AutorunVTEnabled()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_info_chk) = 1) Then
				  VSC_Info()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   VSC_ChkCount()

			   If $r_chk >= 1 Then
				  GetShadowNames()
				  Sleep(6000)
				  MountVSCs()
				  Sleep(6000)

				  ;Checks if VSCs were previously mounted everytime program is run
				  If FileExists("C:\VSC_" & $firstMountedVersion) = 1 Then

					 If (GUICtrlRead($VS_PF_chk) = 1) Then
						VSC_Prefetch()
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

					 If (GUICtrlRead($VS_RF_chk) = 1) Then
						VSC_RecentFolder()
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

					 If (GUICtrlRead($VS_JmpLst_chk) = 1) Then
						VSC_JumpLists()
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

					 If (GUICtrlRead($VS_EvtCpy_chk) = 1) Then
						VSC_EvtCopy()
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

					 If (GUICtrlRead($VS_SYSREG_chk) = 1) Then
						VSC_RegHiv("SYSTEM")
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

					 If (GUICtrlRead($VS_SECREG_chk) = 1) Then
						VSC_RegHiv("SECURITY")
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

					 If (GUICtrlRead($VS_SAMREG_chk) = 1) Then
						VSC_RegHiv("SAM")
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

					 If (GUICtrlRead($VS_SOFTREG_chk) = 1) Then
						VSC_RegHiv("SOFTWARE")
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

					 If (GUICtrlRead($VS_USERREG_chk) = 1) Then
						VSC_NTUser()
						$fcnt = $fcnt + 1
						GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
					 EndIf

				  Else
					 MsgBox(11, "VSC", "Problem with Volume Shadow Mounts")
					 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Failed to execute Volume Shadow Copy Functions." & @CRLF)
				  EndIf
			   EndIf

			   If $r_chk >= 1 Then
				  VSC_rmVSC()
			   EndIf

			   If (GUICtrlRead($sysint_chk) = 1) Then
				  SysIntAdd()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($AutoRun_chk) = 1) Then
				  AutoRun()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($AutoRun_Target_chk) = 1) Then
				  AutoRun_Target()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($srum_chk) = 1) Then
				  Srum()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf


			   If (GUICtrlRead($NTFSInfo_chk) = 1) Then
				  NTFSInfo()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VolInfo_chk) = 1) Then
				  VolInfo()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($Tree_chk) = 1) Then
				  Directory()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($EvtCpy_chk) = 1) Then
				  EvtCopy()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($md5_chk) = 1) Then
				  MD5()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($sha1_chk) = 1) Then
				  SHA1()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($compress_chk) = 1) Then
				  Compression()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($bwsr_cache_chk) = 1) Then
				  bwsr_cache()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($bwsr_hist_chk) = 1) Then
				  bwsr_hist()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($bwsr_fav_chk) = 1) Then
				  bwsr_fav()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($bwsr_cookies_chk) = 1) Then
				  bwsr_cookies()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($bwsr_dl_chk) = 1) Then
				  bwsr_dl()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($bwsr_autocomplete_chk) = 1) Then
				  bwsr_autocomplete()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($bwsr_webcache_chk) = 1) Then
				  bwsr_webcache()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   GUIDelete($progGUI)

			   CommandROSLOG()

			   MsgBox(0, "Triage:  Incident Response", "Your selected tasks have completed.")
			Else
			   MsgBox(0, "Error", "Please make sure all fields are filled!")
			EndIf
		 EndIf
	  WEnd

   GUIDelete()

EndFunc

Func INI_Check($ini_file)				;Check the INI file included in triage for functions and whether or not to run them

   Global 	$GUI_ini
   Global 	$md_ini, $tm_ini
   Global 	$sysrrp_ini, $sftrrp_ini, $hkcurrp_ini, $secrrp_ini, $samrrp_ini, $ntusrrp_ini, $usrc_ini
   Global	$VS_info_ini, $VS_PF_ini, $VS_RF_ini, $VS_JmpLst_ini, $VS_EvtCpy_ini, $VS_SYSREG_ini, $VS_SECREG_ini, $VS_SAMREG_ini, $VS_SOFTREG_ini, $VS_USERREG_ini
   Global 	$SysIntAdd_ini
   Global 	$MFT_ini
   Global 	$IPs_ini, $DNS_ini, $Arp_ini, $ConnS_ini, $routes_ini, $ntBIOS_ini, $conn_ini
   Global 	$share_ini, $shfile_ini, $fw_ini, $host_ini, $wrkgrp_ini
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
   Global	$bwsr_cache_ini, $bwsr_hist_ini, $bwsr_fav_ini, $bwsr_cookies_ini, $bwsr_dl_ini, $bwsr_autocomplete_ini, $bwsr_webcache_ini, $bwsr_password_ini

   $GUI_ini = IniRead($ini_file, "GUI", "GUI", "Yes")
   $md_ini = IniRead($ini_file, "Function", "MemDump", "Yes")
   $tm_ini = IniRead($ini_file, "Function", "TestMem", "Yes")
   $sysrrp_ini = IniRead($ini_file, "Function", "SystemRRip", "Yes")
   $sftrrp_ini = IniRead($ini_file, "Function", "SoftwareRRip", "Yes")
   $hkcurrp_ini = IniRead($ini_file, "Function", "HKCURRip", "Yes")
   $secrrp_ini = IniRead($ini_file, "Function", "SecurityRRip", "Yes")
   $samrrp_ini = IniRead($ini_file, "Function", "SAMRRip", "Yes")
   $ntusrrp_ini = IniRead($ini_file, "Function", "NTUserRRip", "Yes")
   $usrc_ini = IniRead($ini_file, "Function", "Userclass", "Yes")

   $MFT_ini = IniRead($ini_file, "Function", "MFTcopy", "Yes")
   $VS_info_ini = IniRead($ini_file, "Function", "VSinfo", "No")
   $VS_PF_ini = IniRead($ini_file, "Function", "VSprefetch", "No")
   $VS_RF_ini = IniRead($ini_file, "Function", "VSrecent", "No")
   $VS_JmpLst_ini = IniRead($ini_file, "Function", "VSjumplist", "No")
   $VS_EvtCpy_ini = IniRead($ini_file, "Function", "VSevents", "No")
   $VS_SYSREG_ini = IniRead($ini_file, "Function", "VSsystemreg", "No")
   $VS_SECREG_ini = IniRead($ini_file, "Function", "VSsecurityreg", "No")
   $VS_SAMREG_ini = IniRead($ini_file, "Function", "VSsamreg", "No")
   $VS_SOFTREG_ini = IniRead($ini_file, "Function", "VSsoftware", "No")
   $VS_USERREG_ini = IniRead($ini_file, "Function", "VSuserreg", "No")
   $SysIntAdd_ini = IniRead($ini_file, "Function", "SysIntAdd", "Yes")
   $pf_ini = IniRead($ini_file, "Function", "Prefetch", "Yes")
   $rf_ini = IniRead($ini_file, "Function", "RecentFolder", "Yes")
   $JL_ini = IniRead($ini_file, "Function", "JumpLists", "Yes")
   $pf_target_ini = IniRead($ini_file, "Function", "PrefetchTarget", "Yes")
   $rf_target_ini = IniRead($ini_file, "Function", "RecentFolderTarget", "Yes")
   $JL_target_ini = IniRead($ini_file, "Function", "JumpListsTarget", "Yes")
   $evt_ini = IniRead($ini_file, "Function", "EvtCopy", "Yes")
   $srum_ini = IniRead($ini_file, "Function", "SRUM", "Yes")
   $autorun_ini = IniRead($ini_file, "Function", "AutoRun", "Yes")
   $AutoRun_Target_ini = IniRead($ini_file, "Function", "AutoRunTarget", "Yes")
   $st_ini = IniRead($ini_file, "Function", "ScheduledTasks", "Yes")
   $logon_ini = IniRead($ini_file, "Function", "LoggedOn", "Yes")
   $NTFS_ini = IniRead($ini_file, "Function", "NTFSInfo", "Yes")
   $VolInfo_ini = IniRead($ini_file, "Function", "VolumeInfo", "Yes")
   $dir_ini = IniRead($ini_file, "Function", "Directory", "Yes")
   $md5_ini = IniRead($ini_file, "Function", "MD5", "Yes")
   $sha1_ini = IniRead($ini_file, "Function", "SHA1", "Yes")
   $compress_ini = IniRead($ini_file, "Function", "Compression", "No")

   ;ZF added
   $AutorunVTEnabled_ini= IniRead($ini_file, "Function", "AutorunVTEnabled", "No")
   $bwsr_cache_ini = IniRead($ini_file, "Function", "browserCache", "Yes")
   $bwsr_hist_ini = IniRead($ini_file, "Function", "browserHistory", "Yes")
   $bwsr_fav_ini = IniRead($ini_file, "Function", "browserFav", "Yes")
   $bwsr_cookies_ini = IniRead($ini_file, "Function", "browserCookies", "Yes")
   $bwsr_dl_ini = IniRead($ini_file, "Function", "browserDownload", "Yes")
   $bwsr_autocomplete_ini = IniRead($ini_file, "Function", "browserAutocomplete", "Yes")
   $bwsr_webcache_ini = IniRead($ini_file, "Function", "browserWebcache", "Yes")
   $bwsr_password_ini = IniRead($ini_file, "Function", "browserPassword", "Yes")
EndFunc

Func _Ini2GUI()							;Correlate the INI into checking the boxes of the GUI to execute the specific functions

   If $sysinf_ini = "Yes" Then
	  GUICtrlSetState($Sys_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Sys_chk, $GUI_UNCHECKED)
   EndIf

   If $st_ini = "Yes" Then
	  GUICtrlSetState($STsk_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($STsk_chk, $GUI_UNCHECKED)
   EndIf

   If $autorun_ini = "Yes" Then
	  GUICtrlSetState($AutoRun_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($AutoRun_chk, $GUI_UNCHECKED)
   EndIf

   If $AutoRun_Target_ini = "Yes" Then
	  GUICtrlSetState($AutoRun_Target_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($AutoRun_Target_chk, $GUI_UNCHECKED)
   EndIf

   If $srum_ini = "Yes" Then
	  GUICtrlSetState($srum_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($srum_chk, $GUI_UNCHECKED)
   EndIf

   If $sysrrp_ini = "Yes" Then
	  GUICtrlSetState($SYSTEM_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($SYSTEM_chk, $GUI_UNCHECKED)
   EndIf

   If $secrrp_ini = "Yes" Then
	  GUICtrlSetState($SECURITY_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($SECURITY_chk, $GUI_UNCHECKED)
   EndIf

   If $samrrp_ini = "Yes" Then
	  GUICtrlSetState($SAM_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($SAM_chk, $GUI_UNCHECKED)
   EndIf

   If $sftrrp_ini = "Yes" Then
	  GUICtrlSetState($SOFTWARE_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($SOFTWARE_chk, $GUI_UNCHECKED)
   EndIf

   If $hkcurrp_ini = "Yes" Then
	  GUICtrlSetState($HKCU_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($HKCU_chk, $GUI_UNCHECKED)
   EndIf

   If $ntusrrp_ini = "Yes" Then
	  GUICtrlSetState($HKU_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($HKU_chk, $GUI_UNCHECKED)
   EndIf

   If $NTFS_ini = "Yes" Then
	  GUICtrlSetState($NTFSInfo_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($NTFSInfo_chk, $GUI_UNCHECKED)
   EndIf

   If $usrc_ini = "Yes" Then
	  GUICtrlSetState($UsrC_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($UsrC_chk, $GUI_UNCHECKED)
   EndIf

   If $dir_ini = "Yes" Then
	  GUICtrlSetState($Tree_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Tree_chk, $GUI_UNCHECKED)
   EndIf

   If $JL_ini = "Yes" Then
	  GUICtrlSetState($JmpLst_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($JmpLst_chk, $GUI_UNCHECKED)
   EndIf

   If $evt_ini = "Yes" Then
	  GUICtrlSetState($EvtCpy_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($EvtCpy_chk, $GUI_UNCHECKED)
   EndIf

   If $md5_ini = "Yes" Then
	  GUICtrlSetState($md5_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($md5_chk, $GUI_UNCHECKED)
   EndIf

   If $sha1_ini = "Yes" Then
	  GUICtrlSetState($sha1_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($sha1_chk, $GUI_UNCHECKED)
   EndIf

   If $compress_ini = "Yes" Then
	  GUICtrlSetState($compress_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($compress_chk, $GUI_UNCHECKED)
   EndIf

   If $pf_ini = "Yes" Then
	  GUICtrlSetState($PF_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($PF_chk, $GUI_UNCHECKED)
   EndIf

   If $rf_ini = "Yes" Then
	  GUICtrlSetState($RF_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($RF_chk, $GUI_UNCHECKED)
   EndIf

   If $pf_target_ini = "Yes" Then
	  GUICtrlSetState($PF_Target_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($PF_Target_chk, $GUI_UNCHECKED)
   EndIf

   If $rf_target_ini = "Yes" Then
	  GUICtrlSetState($RF_Target_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($RF_Target_chk, $GUI_UNCHECKED)
   EndIf

   If $JL_target_ini = "Yes" Then
	  GUICtrlSetState($JmpLst_Target_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($JmpLst_Target_chk, $GUI_UNCHECKED)
   EndIf

   If $SysIntAdd_ini = "Yes" Then
	  GUICtrlSetState($sysint_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($sysint_chk, $GUI_UNCHECKED)
   EndIf

   If $MFT_ini = "Yes" Then
	  GUICtrlSetState($MFTg_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($MFTg_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_info_ini = "Yes" Then
	  GUICtrlSetState($VS_info_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_info_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_PF_ini = "Yes" Then
	  GUICtrlSetState($VS_PF_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_PF_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_RF_ini = "Yes" Then
	  GUICtrlSetState($VS_RF_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_RF_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_JmpLst_ini = "Yes" Then
	  GUICtrlSetState($VS_JmpLst_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_JmpLst_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_EvtCpy_ini = "Yes" Then
	  GUICtrlSetState($VS_EvtCpy_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_EvtCpy_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_SYSREG_ini = "Yes" Then
	  GUICtrlSetState($VS_SYSREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_SYSREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_SECREG_ini = "Yes" Then
	  GUICtrlSetState($VS_SECREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_SECREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_SAMREG_ini = "Yes" Then
	  GUICtrlSetState($VS_SAMREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_SAMREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_SOFTREG_ini = "Yes" Then
	  GUICtrlSetState($VS_SOFTREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_SOFTREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_USERREG_ini = "Yes" Then
	  GUICtrlSetState($VS_USERREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_USERREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VolInfo_ini = "Yes" Then
	  GUICtrlSetState($VolInfo_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VolInfo_chk, $GUI_UNCHECKED)
   EndIf

   If $AutorunVTEnabled_ini = "Yes" Then
	  GUICtrlSetState($AutorunVTEnabled_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($AutorunVTEnabled_chk, $GUI_UNCHECKED)
   EndIf

   If $bwsr_cache_ini = "Yes" Then
	  GUICtrlSetState($bwsr_cache_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($bwsr_cache_chk, $GUI_UNCHECKED)
   EndIf

   If $bwsr_hist_ini = "Yes" Then
	  GUICtrlSetState($bwsr_hist_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($bwsr_hist_chk, $GUI_UNCHECKED)
   EndIf

   If $bwsr_fav_ini = "Yes" Then
	  GUICtrlSetState($bwsr_fav_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($bwsr_fav_chk, $GUI_UNCHECKED)
   EndIf

   If $bwsr_cookies_ini = "Yes" Then
	  GUICtrlSetState($bwsr_cookies_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($bwsr_cookies_chk, $GUI_UNCHECKED)
   EndIf

   If $bwsr_dl_ini = "Yes" Then
	  GUICtrlSetState($bwsr_dl_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($bwsr_dl_chk, $GUI_UNCHECKED)
   EndIf

   If $bwsr_autocomplete_ini = "Yes" Then
	  GUICtrlSetState($bwsr_autocomplete_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($bwsr_autocomplete_chk, $GUI_UNCHECKED)
   EndIf

   If $bwsr_webcache_ini = "Yes" Then
	  GUICtrlSetState($bwsr_webcache_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($bwsr_webcache_chk, $GUI_UNCHECKED)
   EndIf

   If $bwsr_password_ini = "Yes" Then
	  GUICtrlSetState($bwsr_password_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($bwsr_password_chk, $GUI_UNCHECKED)
   EndIf

EndFunc

Func INI2Command()						;Correlate the INI file into executing the selected functions

   If Not FileExists($RptsDir) Then DirCreate($RptsDir)
   If Not FileExists($EvDir) Then DirCreate($EvDir)

   If $pf_ini = "Yes" Then Prefetch()

   If $rf_ini = "Yes" Then RecentFolder()

   If $JL_ini = "Yes" Then JumpLists()

   If $pf_target_ini = "Yes" Then Prefetch_Target()

   If $rf_target_ini = "Yes" Then RecentFolder_Target()

   If $JL_target_ini = "Yes" Then JumpLists_Target()

   If $sysrrp_ini = "Yes" Then SystemRRip()

   If $sftrrp_ini = "Yes" Then SoftwareRRip()

   If $hkcurrp_ini = "Yes" Then HKCURRip()

   If $ntusrrp_ini = "Yes" Then NTUserRRip()

   If $usrc_ini = "Yes" Then UsrclassE()

   If $MFT_ini = "Yes" Then MFTgrab()

   If $secrrp_ini = "Yes" Then SecurityRRip()

   If $samrrp_ini = "Yes" Then SAMRRip()

   VSC_IniCount()

	  If $r_ini >= 1 Then
		 GetShadowNames()
		 MountVSCs()
	  EndIf

	  ;ZFZF: If file exist, just copy?! Don't care option?!
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

   If $autorun_ini = "Yes" Then AutoRun()

   If $AutoRun_Target_ini = "Yes" Then AutoRun_Target()

   If $srum_ini = "Yes" Then Srum()

   If $NTFS_ini = "Yes" Then NTFSInfo()

   If $VolInfo_ini = "Yes" Then VolInfo()

   If $dir_ini = "Yes" Then Directory()

   If $evt_ini = "Yes" Then EvtCopy()

   If $md5_ini = "Yes" Then MD5()

   If $sha1_ini = "Yes" Then SHA1()

   If $compress_ini = "Yes" Then Compression()

   If $AutorunVTEnabled_ini = "Yes" Then AutorunVTEnabled()

   If $bwsr_cache_ini = "Yes" Then bwsr_cache()

   If $bwsr_hist_ini = "Yes" Then bwsr_hist()

   If $bwsr_fav_ini = "Yes" Then bwsr_fav()

   If $bwsr_cookies_ini = "Yes" Then bwsr_cookies()

   If $bwsr_dl_ini = "Yes" Then bwsr_dl()

   If $bwsr_autocomplete_ini = "Yes" Then bwsr_autocomplete()

   If $bwsr_webcache_ini = "Yes" Then bwsr_webcache()

   CommandROSLOG()

;   MsgBox(0, "Triage:  Incident Response", "Your selected tasks have completed.")

EndFunc

Func Browse()
    ; Create a constant variable in Local scope of the message to display in FileOpenDialog.
    Local Const $Message = "Select Mounted Evidence File"

    ; Display an open dialog to select a list of file(s).
    Local $Browse = FileSelectFolder($Message, "")
    If @error Then
        ; Display the error message.

        ; Change the working directory (@WorkingDir) back to the location of the script directory as FileOpenDialog sets it to the last accessed folder.
        FileChangeDir(@ScriptDir)
    Else
        ; Change the working directory (@WorkingDir) back to the location of the script directory as FileOpenDialog sets it to the last accessed folder.
        FileChangeDir(@ScriptDir)

        ; Replace instances of "|" with @CRLF in the string returned by FileOpenDialog.
        $Browse = StringReplace($Browse, "|", @CRLF)

    return $browse  ; <----------------------------------------
    ;MsgBox(0, "", $Browse)

    EndIf

EndFunc   ;==>Browse

Func Srum()						;Gather information pertaining to the user accounts
   ;Local $srumdump = @ScriptDir & '\Tools\srum-dump'
   ;Local $srum1 = $shellex & ' "cd /d ' & $srumdump & ' && srum_dump.exe -i "' & $EvDir & '\SRUDB.dat' & '" -o "' & $EvDir & '\SRUM_DUMP_Output_Report.xls"'
   Local $robocopy = '"' & @ScriptDir & '\Tools\Robocopy.exe"'
   Local $pf1 = @ComSpec & ' /c ' & $robocopy & ' "' & $evidencePath & '\Windows\System32\sru" "' & $RptsDir & '\Evidence" SRUDB.dat /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\SRU Copy Log.txt"'

   ShellExecuteWait($robocopy, '"' & $evidencePath & '\Windows\System32\sru" "' & $RptsDir & '\Evidence" "SRUDB.dat" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\Evidence\SRU Copy Log.txt"', $tools, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $pf1 & @CRLF)
   ;SRUDB file to be processed by Magneto
   ;RunWait($srum1, "")
	  ;FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $srum1 & @CRLF)
EndFunc

Func AutoRun()							;Information regarding startup
   ;NOTE: -a = All, -c = csv output
   Local $autorun = $shellex & ' .\Tools\SysinternalsSuite\autorunsc.exe -accepteula -c -z > "' & $RptsDir & '\AutoRun Info.csv"'

   RunWait($autorun, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autorun & @CRLF)
EndFunc

Func AutoRun_Target()					;Copy autorun target files
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
			$parentDirectory = StringRegExpReplace($parentDirectory, '^[^\\]*', $evidencePath)
			MsgBox(0, "test", $parentDirectory)
			Local $file = StringRegExpReplace($fullPath, '.*\\', '')
			Local $autorun = $robocopy & ' "' & $parentDirectory & '" "' & $EvDir & '\Autorun" "' & $file & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:"' & $RptsDir & '\AutoRun_Target_RoboCopy_Log.txt"'
			RunWait($autorun, @ScriptDir & '\Tools', @SW_HIDE)
			   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autorun & @CRLF)
		 EndIf
	  Next
   EndIf
EndFunc

Func Prefetch()							;Copy any prefecth data while maintaining metadata
   Local $robocopy = '"' & @ScriptDir & '\Tools\Robocopy.exe"'
   Local $pf1 = $shellex & ' ' & $robocopy & ' "' & $evidencePath & '\Windows\Prefetch" "' & $EvDir & '\Prefetch" *.pf /copyall /ZB /TS /r:2 /w:3 /FP /NP /log:"' & $RptsDir & '\Prefetch_RoboCopy_Log.txt"'

   If Not FileExists($EvDir & "\Prefetch") Then DirCreate($EvDir & "\Prefetch")

   ShellExecuteWait($robocopy, ' "' & $evidencePath & '\Windows\Prefetch" "' & $EvDir & '\Prefetch" *.pf /copyall /ZB /TS /r:2 /w:3 /FP /NP /log:"' & $RptsDir & '\Prefetch_RoboCopy_Log.txt"', $tools, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $pf1 & @CRLF)
   EndFunc

Func Prefetch_Target()							;Copy any prefecth data while maintaining metadata
   Local $robocopy = '"' & @ScriptDir & '\Tools\Robocopy.exe"'
   Local $winprefetch = ' .\Tools\nirsoft_package\NirSoft\winprefetchview'
   Local $pf2 = $shellex & $winprefetch & ' /folder "' & $RptsDir & '\Evidence\Prefetch" /scomma "' & $RptsDir & '\Prefetch Info.csv"'
   RunWait($pf2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $pf2 & @CRLF)

   ;Gets Target path of each prefetch file and uses robocopy to copy file to evidence directory
   Local $intCount = 0, $linecount = 0
   Local $csv, $prefetchfile[1]
   Local $filename = $RptsDir & "\Prefetch Info.csv"
   Sleep(30)

   While _WinAPI_FileInUse($filename) = 1
	  Sleep(10)
   WEnd

   _FileReadToArray($filename, $csv)
   Local $prefetchDict = ObjCreate("Scripting.Dictionary")
   If IsArray($csv) Then
	  For $i = 1 To $csv[0]
		 ;_ArrayDisplay(StringSplit($csv[$i], ","), "Test")
		 $temp = StringSplit($csv[$i], ",")
		 If StringLen($temp[7]) <> 0 Then
			;If @OSVersion = "WIN_10" Then
			   ;If StringRegExp($temp[7], '-([^}]*)', $STR_REGEXPMATCH) Then
				  ;Local $volSerialNumber = StringRegExp($temp[7], '-([^}]*)', $STR_REGEXPARRAYMATCH)[0]
			   ;EndIf
			   ;Local $drive = $driveDict(StringUpper($volSerialNumber))
			   ;$temp[7] = StringRegExpReplace($temp[7], '^\\[^\\]*', $drive)
			;EndIf
			If StringLeft($temp[7], 1) = "\" Then $temp[7] = StringRegExpReplace($temp[7], '\\DEVICE\\HARDDISK[^\\]*', $evidencePath)
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
	  $parentDirectory = StringRegExpReplace($parentDirectory, '^[^\\]*', $evidencePath)
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

Func RecentFolder()						;Send information to the recent folder copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
   EndIf

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

   If Not FileExists($EvDir & '\Recent LNKs\' & $output) Then DirCreate($EvDir & '\Recent LNKs\' & $output)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If Not FileExists($evidencePath & "\Users") Then
	  $recPATH = '"' & $path & '\Recent"'
   Else
	  $recPATH = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent"'
   EndIf

   Local $recF1 = $robocopy & ' ' & $recPATH & ' "' & $EvDir & '\Recent LNKs\' & $output & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & 'Recent LNKs\' & $output & ' Recent RoboCopy Log.txt"'
   RunWait($recF1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $recF1 & @CRLF)

   ;Uses lnkparser.exe to generate more information regarding LNK files
   Local $lnkparser = ' .\Tools\lnkparser.exe'
   Local $lnk1 = $shellex & $lnkparser & ' -o "' & $EvDir & '\Recent LNKs\' & $output & '" -c -s "' & $recPATH & '"'
   RunWait($lnk1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $lnk1 & @CRLF)

EndFunc

Func RecentFolder_Target()						;Send information to the recent folder copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
   EndIf

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

   If Not FileExists($evidencePath & "\Users") Then
	  $recPATH = $path & '\Recent'
   Else
	  $recPATH = $path & '\AppData\Roaming\Microsoft\Windows\Recent'
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
   $parentDirectory = StringRegExpReplace($parentDirectory, '^[^\\]*', $evidencePath)
   Local $file =  '"' & StringRegExpReplace($path, '.*\\', '') & '"'
   Local $recF1 = $shellex & ' ' & $robocopy & ' "' & $parentDirectory & '" "' & $EvDir & '\Recent LNKs\' & $output & '\Files" ' & $file & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /IS'
   ShellExecuteWait($robocopy, ' "' & $parentDirectory & '" "' & $EvDir & '\Recent LNKs\' & $output & '\Files" ' & $file & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /IS /log:"' & $EvDir & 'Recent LNKs\' & $output & ' Recent Target RoboCopy Log.txt"', $tools, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $recF1 & @CRLF)
EndFunc

Func JumpLists()						;Provide info to the Jumplist copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
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

Func JumpLists_Target()						;Provide info to the Jumplist copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
   EndIf

   $usr = FileFindFirstFile($uPath & "*.*")

   While 1
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $evidencePath & "\Users\" & $profs
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
		 $parentDirectory = StringRegExpReplace($parentDirectory, '^[^\\]*', $evidencePath)
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

Func NTFSInfo()							;Gather information regarding NTFS
   Local $ntfs1 = $shellex & ' .\Tools\SysinternalsSuite\ntfsinfo ' & $evidencePath & ' > "' & $RptsDir & '\NTFS Info.txt"'

   RunWait($ntfs1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $ntfs1 & @CRLF)
   EndFunc

Func VolInfo()							;Gather volume information
   Local $vol1 = $shellex & ' fsutil fsinfo volumeinfo ' & $evidencePath & ' >> "' & $RptsDir & '\Volume Info.txt"'

   RunWait($vol1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vol1 & @CRLF)
EndFunc

Func Directory()						;Get list of directory structure
   Local $dir1 = $shellex & ' tree ' & $evidencePath & '\ /f /a > "' & $RptsDir & '\Directory Info.txt"'

   RunWait($dir1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $dir1 & @CRLF)
EndFunc

Func SystemRRip()						;Copy the SYSTEM HIV for analysis
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $sysrip = $robocopy & ' "' & $evidencePath & 'Windows\System32\config" "' & $RptsDir & '\Evidence" SYSTEM /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $LogsDir & 'SYSTEM_RoboCopy.txt"'
   Local $rename = @ComSpec & ' /c rename "' & $RptsDir & '\Evidence\SYSTEM' & '" "SYSTEM_' & $evidenceName & '.hiv"'

   RunWait($sysrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $sysrip & @CRLF)
   RunWait($rename, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $rename & @CRLF)
EndFunc

Func SecurityRRip()						;Copy the SECURITY HIV for analysis
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $secrip = $robocopy & ' "' & $evidencePath & 'Windows\System32\config" "' & $RptsDir & '\Evidence" SECURITY /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $LogsDir & 'SECURITY_RoboCopy.txt"'
   Local $rename = @ComSpec & ' /c rename "' & $RptsDir & '\Evidence\SECURITY' & '" "SECURITY_' & $evidenceName & '.hiv"'

   RunWait($secrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $secrip & @CRLF)
   RunWait($rename, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $rename & @CRLF)
EndFunc

Func SAMRRip()							;Copy the SAM HIV for analysis
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $samrip = $robocopy & ' "' & $evidencePath & 'Windows\System32\config" "' & $RptsDir & '\Evidence" SAM /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $LogsDir & 'SAM_RoboCopy.txt"'
   Local $rename = @ComSpec & ' /c rename "' & $RptsDir & '\Evidence\SAM' & '" "SAM_' & $evidenceName & '.hiv"'

   RunWait($samrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $samrip & @CRLF)
   RunWait($rename, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $rename & @CRLF)
EndFunc

Func SoftwareRRip()						;Copy the SOFTWARE HIV for analysis
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $softrip = $robocopy & ' "' & $evidencePath & 'Windows\System32\config" "' & $RptsDir & '\Evidence" SOFTWARE /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $LogsDir & 'SOFTWARE_RoboCopy.txt"'
   Local $rename = @ComSpec & ' /c rename "' & $RptsDir & '\Evidence\SOFTWARE' & '" "SOFTWARE_' & $evidenceName & '.hiv"'

   RunWait($softrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $softrip & @CRLF)
   RunWait($rename, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $rename & @CRLF)
EndFunc

Func HKCURRip()							;Copy the HKCU HIV for analysis
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $hkcurip = $robocopy & ' "' & $evidencePath & 'Windows\System32\config" "' & $RptsDir & '\Evidence" DEFAULT /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $LogsDir & 'CURRENTUSER_RoboCopy.txt"'
   Local $rename = @ComSpec & ' /c rename "' & $RptsDir & '\Evidence\DEFAULT' & '" "HKCU_' & $evidenceName & '.hiv"'

   RunWait($hkcurip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $hkcurip & @CRLF)
   RunWait($rename, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $rename & @CRLF)
EndFunc

Func NTUserRRip()						;Copy all NTUSER.dat files from each profile
   Local $usrFile = $EvDir & "\USERMapping.txt"
   Local $s_Out = ""
   Local $test_OUT = ""
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $ntuserCount = 1

   $loadReg = RunWait(@ComSpec & " /c " & 'REG LOAD HKLM\TempHive "' & $EvDir & 'SOFTWARE_' & $evidenceName & '.hiv"')
   ;While 1
	  ;$sTemp = StdoutRead($loadReg)
	  ;If StringInStr($sTemp, "The operation completed successfully") Then ExitLoop
   ;WEnd
   Sleep(30)
   $h_Proc = Run(@ComSpec & " /c " & 'REG QUERY "HKEY_LOCAL_MACHINE\TempHive\Microsoft\Windows NT\CurrentVersion\ProfileList"', "", @SW_HIDE, 0x02)

   While 1
	  $sTemp = StdoutRead($h_Proc)
	  $s_Out &= $sTemp
	  If @error Then ExitLoop
   WEnd
   ;MsgBox(0, "test", $s_Out)
   $aLines = StringRegExp($s_Out, "(?m:^)HKEY_LOCAL_MACHINE\\TempHive\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\(S-1-5-21-\d*-\d*-\d*-\S*)",3)
   ;_ArrayDisplay($aLines, "test")

   If Not @error Then
	  For $i = 0 To UBound($aLines) - 1
		 $s_Val = $aLines[$i]
		 $s_Val = StringStripWS($s_Val, 2)
		 Local $nturip
		 $h_Proc = Run(@ComSpec & " /c " & 'REG QUERY "HKEY_LOCAL_MACHINE\TempHive\Microsoft\Windows NT\CurrentVersion\ProfileList\' & $s_Val & '" /v ProfileImagePath', "", @SW_MAXIMIZE, 0x02)
		 $s_Out = ""
		 While 1
			$sTemp = StdoutRead($h_Proc)
			$s_Out &= $sTemp
			If @error Then ExitLoop
		 WEnd
		 $aPath = StringRegExp($s_Out, "REG_EXPAND_SZ\s*([\S]*)",1)[0]
		 $aPath = StringRegExpReplace($aPath, '^[^\\]*', $evidencePath)
		 If FileExists ($aPath & '\NTUSER.DAT') Then
			Local $cmd = $robocopy & ' ' & $aPath & ' "' & $RptsDir & '\Evidence" NTUSER.DAT /r:1 /w:3 /log+:"' & $LogsDir & 'NTUSER Log Copy.txt"'
			Local $test = RunWait($cmd, "", @SW_HIDE, 0x08)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cmd & @CRLF)

			$sFileOld = $EvDir & 'NTUSER.DAT'
			$sFileRenamed = $EvDir & $evidenceName &'_USER_' & $ntuserCount & '.dat'
			Local $mov = FileMove($sFileOld, $sFileRenamed)

			;If $mov = 0 Thenol0
			    ;Local $hkcurip
			   ;If @OSVersion = "WIN_XP" Then
				  ;$hkcurip = $shellex & ' REG SAVE HKEY_USERS\' & $s_Val & ' "' & $EvDir & '\' & @ComputerName &'_USER_' & $ntuserCount & '.dat"'
			   ;Else
				  ;$hkcurip = $shellex & ' REG SAVE HKEY_USERS\' & $s_Val & ' "' & $EvDir & '\' & @ComputerName &'_USER_' & $ntuserCount & '.dat" /y'
			   ;EndIf
			   ;RunWait($hkcurip, "", @SW_HIDE)
			;EndIf

			FileWriteLine($usrFile, "HKEY_USERS\"&$s_Val&":USER_"&$ntuserCount&@CRLF)
			$ntuserCount = $ntuserCount + 1
		 EndIf
	  Next
   EndIf
   $unloadReg = Run(@ComSpec & " /c " & 'REG UNLOAD HKLM\TempHive')
EndFunc

Func MD5()								;Special thanks to Jesse Kornblum for his amazing hashing tools
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

Func SHA1()								;Special thanks to Jesse Kornblum for his amazing hashing tools
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

Func Compression()						;Special thanks to the 7-Zip team such a great tool
   ShellExecuteWait(".\Tools\7za.exe" , 'a -mx9 -r "' & $RptsDir & '" *.txt *.hiv *.raw *.lnk *.dat *.pf *.evt *.evtx *.automaticDestinations-ms *.customDestinations-ms *.csv *.dmp', $tools, "", @SW_HIDE)
EndFunc

Func SysIntAdd()						;Add registry key to accept Sysinternals
   Local $RegAdd1 = $shellex & ' REG ADD HKCU\Software\Sysinternals\NTFSInfo /v EulaAccepted /t REG_DWORD /d 1 /f'

   RunWait($RegAdd1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $RegAdd1 & @CRLF)
EndFunc

Func EvtCopy()							;Copy all event logs from local machine
   Local $OS
   Local $evtdir
   Local $evtext
   Local $LogDir = $EvDir & 'Logs'
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $robo7 = '"' & @ScriptDir & '\Tools\robo7.exe"'

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

   If Not FileExists($evidencePath & "\Users") Then
	  $evtdir = '"' & $evidencePath & '\Windows\system32\config"'
	  $evtext = "evt"
	  $EvtCmd = $robocopy & " " & $evtdir & ' "' & $LogDir & '" *.' & $evtext & ' /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\Event Log Copy.txt"'
   Else
	  $evtdir = '"' & $evidencePath & '\Windows\system32\winevt\Logs"'
	  $evtext = "evtx"
	  $EvtCmd = $robo7 & " " & $evtdir & ' "' & $LogDir & '" /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\Event Log Copy.txt"'
   EndIf

   If Not FileExists($LogDir) Then DirCreate($LogDir)

   RunWait($EvtCmd, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Copied ." & $evtext & " files from " & $evtdir & "." & @CRLF)
EndFunc

Func UsrclassE()  						;Search for profiles and initiate the copy of USRCLASS.dat

   Local $OS, $uPath, $usr, $profs, $uDir, $uPath, $uATB

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
   EndIf

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
   Local $usrce = $shellex & ' .\Tools\sleuthkit-win32-3.2.3\bin\ifind.exe -n /users/' & $prof & '/appdata/local/microsoft/windows/usrclass.dat \\.\' & StringReplace($evidencePath, "\","") & ' > MFTEntries.log'
   RunWait($usrce, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $usrce & @CRLF)
   $log = FileReadLine("MFTEntries.log",1)

   ;Extracts USRCLASS.DAT data using the inode number
   Local $catusrce = $shellex & ' .\Tools\sleuthkit-win32-3.2.3\bin\icat.exe \\.\' & StringReplace($evidencePath, "\", "") & ' ' & $log & ' > "' & $EvDir & $prof & '-usrclass.dat"'
   RunWait($catusrce, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $catusrce & @CRLF)
   FileDelete("MFTEntries.log")
   Return $log
EndFunc

Func MFTgrab()							;Use iCat to rip a file from NTFS file system
   Local $MFTc = $shellex & ' .\Tools\sleuthkit-win32-3.2.3\bin\icat.exe \\.\' & StringReplace($evidencePath, "\", "") & ' 0 > "' & $EvDir & '$MFTcopy"'

   RunWait($MFTc, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $MFTc & @CRLF)
EndFunc

Func VSC_Info()
   Local $drive = StringReplace($evidencePath, "\", "", -1)
   MsgBox(0, "test", $drive)
   Local $vscinfo = @ComSpec & ' /c vssadmin list shadows /for=C: > "' & $RptsDir & '\VSC Information.txt"'
   RunWait($vscinfo, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $vscinfo & @CRLF)
EndFunc

; To check for list of VSC
; Command: vssadmin List Shadows
Func GetShadowNames()					;Query WMIC for list of Volume Shadow Copy mount points

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

Func VSC_Prefetch()						;Copy Prefetch data from any Volume Shadow Copies
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

Func VSC_RecentFolder()					;Send information to the recent folder copy function (Volume Shadow Copy version)
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

Func VSC_JumpLists()					;Provide info to the Jumplist copy function (Volume Shadow Copy version)
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

Func VSC_EvtCopy()						;Copy all event logs from local machine (Volume Shadow Copy version)
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

Func VSC_RegHiv($hiv)					;Copy Registry Hive from Volume Shadow Copy
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

Func VSC_NTUser()						;Copy NTUSER.dat from Volume Shadow Copy
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

Func VSC_rmVSC()						;Remove the mounted VSC directories

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


Func AutorunVTEnabled()							;Running autorunsc with VT checking, TAKES A LONG TIME TO RUN!
   ;Autorun default

   ;NOTE: -a = All, -c = csv output
   Local $autorun = $shellex & ' .\Tools\SysinternalsSuite\autorunsc.exe -accepteula -a * -vt -m -c > "' & $RptsDir & '\AutoRun Info VT.csv"'

   RunWait($autorun, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $autorun & @CRLF)
EndFunc

Func exifmetadata()
   Local $metadata = @ComSpec & ' /c .\Tools\exiftool-10.31\exiftool -r ' & $evidencePath & ' > "' & $RptsDir & '\exifmetadata.txt"'

   RunWait($metadata, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $metadata & @CRLF)
EndFunc

Func bwsr_cache()						;Send information to the recent folder copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
   EndIf

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
   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"
   Else
	  $uDir = $uDir & "\AppData\Local\Mozilla\Firefox\Profiles\"
   EndIf

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
   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Local Settings\Temporary Internet Files"
   Else
	  $uDir = $uDir & "\AppData\Local\Microsoft\Windows\WebCache"
   EndIf

   Local $iecache = ' .\Tools\nirsoft_package\NirSoft\iecacheview'
   Local $cache1a = $shellex & $iecache & ' -folder "' & $uDir & '" /scomma "' & $BrowserDir & $profs & '\IE\IE Cache.csv"'
   Local $cache1b = $shellex & $iecache & ' -folder "' & $uDir & '" /copycache "" "" /CopyFilesFolder "' & $BrowserDir & $profs & '\IE\Cache_Files" /UseWebSiteDirStructure 0'
   RunWait($cache1a, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1a & @CRLF)
   RunWait($cache1b, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1b & @CRLF)
EndFunc

Func chrome_cache($uDir, $profs)
   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Google\Chrome\User Data\Default\Cache"
   Else
	  $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\Default\Cache"
   EndIf

   Local $chromecache = ' .\Tools\nirsoft_package\NirSoft\chromecacheview'
   Local $cache1a = $shellex & $chromecache & ' -folder "' & $uDir & '" /scomma "' & $BrowserDir & '\' & $profs & '\Chrome\Chrome Cache.csv"'
   Local $cache1b = $shellex & $chromecache & ' -folder "' & $uDir & '" /copycache "" "" /CopyFilesFolder "' & $BrowserDir & $profs & '\Chrome\Cache_Files" /UseWebSiteDirStructure 0'
   RunWait($cache1a, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1a & @CRLF)
   RunWait($cache1b, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $cache1b & @CRLF)
EndFunc

Func bwsr_cookies()						;Send information to the recent folder copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
   EndIf

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
   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"
   Else
	  $uDir = $uDir & "\AppData\Roaming\Mozilla\Firefox\Profiles\"
   EndIf

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
   Local $chromeProfs
   Local $rootDir

   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Google\Chrome\User Data\"
   Else
	  $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\"
   EndIf

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

Func bwsr_dl()						;Send information to the recent folder copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
   EndIf

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
   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"
   Else
	  $uDir = $uDir & "\AppData\Roaming\Mozilla\Firefox\Profiles\"
   EndIf

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
   Local $chromeProfs
   Local $rootDir

   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Google\Chrome\User Data\"
   Else
	  $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\"
   EndIf
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

Func bwsr_autocomplete()						;Send information to the recent folder copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings\"
   Else
	  $uPath = $evidencePath & "\Users\"
   EndIf

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
   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"
   Else
	  $uDir = $uDir & "\AppData\Roaming\Mozilla\Firefox\Profiles\"
   EndIf

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
   Local $chromeProfs
   Local $rootDir

   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Google\Chrome\User Data\"
   Else
	  $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\"
   EndIf
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

Func bwsr_hist()
   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = $evidencePath & "\Documents and Settings"
   Else
	  $uPath = $evidencePath & "\Users"
   EndIf
   Local $browserHistory = ' .\Tools\nirsoft_package\NirSoft\browsinghistoryview'
   Local $hist = $shellex & $browserHistory & ' /HistorySource 3 /HistorySourceFolder "' & $uPath & '" /LoadIE 1 /LoadFirefox 1 /LoadChrome1 /LoadSafari 1 /scomma "' & $BrowserDir & '\Browser History.csv"'

   RunWait($hist, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&"  "&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&"  >  "&"Executed command: " & $hist & @CRLF)
EndFunc

Func bwsr_fav()
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

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = "C:\Documents and Settings\"
   Else
	  $uPath = "C:\Users\"
   EndIf

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
   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Mozilla\Firefox\Profiles\"
   Else
	  $uDir = $uDir & "\AppData\Roaming\Mozilla\Firefox\Profiles\"
   EndIf

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
   Local $chromeProfs
   Local $rootDir

   If Not FileExists($evidencePath & "\Users") Then
	  $uDir = $uDir & "\Application Data\Google\Chrome\User Data\"
   Else
	  $uDir = $uDir & "\AppData\Local\Google\Chrome\User Data\"
   EndIf
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

Func bwsr_webcache()
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath

   If Not FileExists($evidencePath & "\Users") Then
	  $uPath = "C:\Documents and Settings\"
   Else
	  $uPath = "C:\Users\"
   EndIf

   $usr = FileFindFirstFile($uPath & "*.*")
   While $usr
	  $profs = FileFindNextFile($usr)
		 If @error then ExitLoop
	  $uDir = $uPath & $profs
	  $uATB = FileGetAttrib($uDir)
	  If Not FileExists($BrowserDir & $profs) Then DirCreate($BrowserDir & $profs)
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

Func ProgChkCount()						;Count number of functions executing for GUI Progress Bar

   Global $p_chkc

   If (GUICtrlRead($MemDmp_chk) = 1) Then
	  $p_chkc = 1
   Else
	  $p_chkc = 0
   EndIf

   If (GUICtrlRead($PF_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($RF_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($JmpLst_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($PF_Target_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($RF_Target_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($JmpLst_Target_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($SYSTEM_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($SOFTWARE_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($HKCU_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($HKU_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($UsrC_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($SECURITY_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($SAM_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($MFTg_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_info_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_PF_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_RF_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_JmpLst_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_EvtCpy_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_SYSREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_SECREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_SAMREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_SOFTREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_USERREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($sysint_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Sys_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Proc_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Serv_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($AcctInfo_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($srum_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($AutoRun_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($AutoRun_Target_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($STsk_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($FileAssoc_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Host_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($NTFSInfo_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VolInfo_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($DiskMnt_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Tree_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($EvtCpy_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($md5_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($sha1_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($compress_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($AutorunVTEnabled_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($bwsr_cache_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($bwsr_password_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($bwsr_hist_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($bwsr_fav_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($bwsr_dl_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($bwsr_autocomplete_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($bwsr_webcache_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($bwsr_cookies_chk) = 1) Then $p_chkc = $p_chkc + 1
EndFunc

Func SelectAll()						;Function to select all functions within a GUI

   GUICtrlSetState($MemDmp_chk, $GUI_CHECKED)
   GUICtrlSetState($PF_chk, $GUI_CHECKED)
   GUICtrlSetState($RF_chk, $GUI_CHECKED)
   GUICtrlSetState($JmpLst_chk, $GUI_CHECKED)
   GUICtrlSetState($PF_Target_chk, $GUI_CHECKED)
   GUICtrlSetState($RF_Target_chk, $GUI_CHECKED)
   GUICtrlSetState($JmpLst_Target_chk, $GUI_CHECKED)
   GUICtrlSetState($SYSTEM_chk, $GUI_CHECKED)
   GUICtrlSetState($SOFTWARE_chk, $GUI_CHECKED)
   GUICtrlSetState($HKCU_chk, $GUI_CHECKED)
   GUICtrlSetState($HKU_chk, $GUI_CHECKED)
   GUICtrlSetState($UsrC_chk, $GUI_CHECKED)
   GUICtrlSetState($SECURITY_chk, $GUI_CHECKED)
   GUICtrlSetState($SAM_chk, $GUI_CHECKED)
   GUICtrlSetState($MFTg_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_info_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_PF_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_RF_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_JmpLst_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_EvtCpy_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_SYSREG_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_SECREG_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_SAMREG_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_SOFTREG_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_USERREG_chk, $GUI_CHECKED)
   GUICtrlSetState($sysint_chk, $GUI_CHECKED)
   GUICtrlSetState($Sys_chk, $GUI_CHECKED)
   GUICtrlSetState($srum_chk, $GUI_CHECKED)
   GUICtrlSetState($Proc_chk, $GUI_CHECKED)
   GUICtrlSetState($Serv_chk, $GUI_CHECKED)
   GUICtrlSetState($AcctInfo_chk, $GUI_CHECKED)
   GUICtrlSetState($AutoRun_chk, $GUI_CHECKED)
   GUICtrlSetState($AutoRun_Target_chk, $GUI_CHECKED)
   GUICtrlSetState($STsk_chk, $GUI_CHECKED)
   GUICtrlSetState($FileAssoc_chk, $GUI_CHECKED)
   GUICtrlSetState($Host_chk, $GUI_CHECKED)
   GUICtrlSetState($NTFSInfo_chk, $GUI_CHECKED)
   GUICtrlSetState($VolInfo_chk, $GUI_CHECKED)
   GUICtrlSetState($DiskMnt_chk, $GUI_CHECKED)
   GUICtrlSetState($Tree_chk, $GUI_CHECKED)
   GUICtrlSetState($EvtCpy_chk, $GUI_CHECKED)
   GUICtrlSetState($md5_chk, $GUI_CHECKED)
   GUICtrlSetState($sha1_chk, $GUI_CHECKED)
   GUICtrlSetState($compress_chk, $GUI_CHECKED)
   ;ZF added
   GUICtrlSetState($AutorunVTEnabled_chk, $GUI_CHECKED)
   GUICtrlSetState($bwsr_cache_chk, $GUI_CHECKED)
   GUICtrlSetState($bwsr_password_chk, $GUI_CHECKED)
   GUICtrlSetState($bwsr_hist_chk, $GUI_CHECKED)
   GUICtrlSetState($bwsr_fav_chk, $GUI_CHECKED)
   GUICtrlSetState($bwsr_dl_chk, $GUI_CHECKED)
   GUICtrlSetState($bwsr_cookies_chk, $GUI_CHECKED)
   GUICtrlSetState($bwsr_webcache_chk, $GUI_CHECKED)
   GUICtrlSetState($bwsr_autocomplete_chk, $GUI_CHECKED)
EndFunc

Func SelectNone()						;Function to deselect all functions within the GUI
   GUICtrlSetState($PF_chk, $GUI_UNCHECKED)
   GUICtrlSetState($RF_chk, $GUI_UNCHECKED)
   GUICtrlSetState($JmpLst_chk, $GUI_UNCHECKED)
   GUICtrlSetState($PF_Target_chk, $GUI_UNCHECKED)
   GUICtrlSetState($RF_Target_chk, $GUI_UNCHECKED)
   GUICtrlSetState($JmpLst_Target_chk, $GUI_UNCHECKED)
   GUICtrlSetState($SYSTEM_chk, $GUI_UNCHECKED)
   GUICtrlSetState($SOFTWARE_chk, $GUI_UNCHECKED)
   GUICtrlSetState($HKCU_chk, $GUI_UNCHECKED)
   GUICtrlSetState($HKU_chk, $GUI_UNCHECKED)
   GUICtrlSetState($UsrC_chk, $GUI_UNCHECKED)
   GUICtrlSetState($SECURITY_chk, $GUI_UNCHECKED)
   GUICtrlSetState($SAM_chk, $GUI_UNCHECKED)
   GUICtrlSetState($MFTg_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_info_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_PF_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_RF_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_JmpLst_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_EvtCpy_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_SYSREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_SECREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_SAMREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_SOFTREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_USERREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($sysint_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Sys_chk, $GUI_UNCHECKED)
   GUICtrlSetState($srum_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Proc_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Serv_chk, $GUI_UNCHECKED)
   GUICtrlSetState($AcctInfo_chk, $GUI_UNCHECKED)
   GUICtrlSetState($AutoRun_chk, $GUI_UNCHECKED)
   GUICtrlSetState($AutoRun_Target_chk, $GUI_UNCHECKED)
   GUICtrlSetState($STsk_chk, $GUI_UNCHECKED)
   GUICtrlSetState($FileAssoc_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Host_chk, $GUI_UNCHECKED)
   GUICtrlSetState($NTFSInfo_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VolInfo_chk, $GUI_UNCHECKED)
   GUICtrlSetState($DiskMnt_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Tree_chk, $GUI_UNCHECKED)
   GUICtrlSetState($EvtCpy_chk, $GUI_UNCHECKED)
   GUICtrlSetState($md5_chk, $GUI_UNCHECKED)
   GUICtrlSetState($sha1_chk, $GUI_UNCHECKED)
   GUICtrlSetState($compress_chk, $GUI_UNCHECKED)
   ;ZF added
   GUICtrlSetState($AutorunVTEnabled_chk, $GUI_UNCHECKED)
   GUICtrlSetState($bwsr_cache_chk, $GUI_UNCHECKED)
   GUICtrlSetState($bwsr_password_chk, $GUI_UNCHECKED)
   GUICtrlSetState($bwsr_hist_chk, $GUI_UNCHECKED)
   GUICtrlSetState($bwsr_fav_chk, $GUI_UNCHECKED)
   GUICtrlSetState($bwsr_dl_chk, $GUI_UNCHECKED)
   GUICtrlSetState($bwsr_cookies_chk, $GUI_UNCHECKED)
   GUICtrlSetState($bwsr_webcache_chk, $GUI_UNCHECKED)
   GUICtrlSetState($bwsr_autocomplete_chk, $GUI_UNCHECKED)
EndFunc

Func CommandROSLOG()					;Copy the log data from ReactOS command prompt

   Local $ROSlog = "C:\Commands.log"

   If FileExists($ROSlog) = 1 Then
	  FileMove($ROSlog, $RptsDir)
   EndIf

   EndFunc
