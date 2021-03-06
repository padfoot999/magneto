#$hive points to System hive, $hive2 points to HKU hive;
package usbParser;
use strict;
use Data::Dumper;
use Excel::Writer::XLSX;
use DateTime;
use Time::Piece;
use Regexp::Common qw(time);

#perl2exe_include Data/Dumper;

my %config = (hive          => "System",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20141111);

sub getConfig{return %config}

sub getShortDescr {
	return "Get USBStor key info";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub printDetails {
	my $worksheet = shift;
	my $row = shift;
	my $datetime = shift;
	my $source_type = shift;
	my $type = shift;
	my $reg_key = shift;
	my $usb = shift;
	my $datetime_parsed;
	$datetime =~ s/ UTC//g;
	::rptMsg($datetime);
	if ($datetime !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
		my @date = $datetime =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
		$datetime_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
	} else {
		my @parse = $datetime =~ m/(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(.*)/;
		$datetime = $parse[0].$parse[1];
		$datetime_parsed = Time::Piece->strptime($datetime, '%a %b  %d %H:%M:%S %Y');
	}
	$worksheet->write($row, 0, $datetime_parsed->strftime("%Y-%m-%d"));
	$worksheet->write($row, 1, $datetime_parsed->strftime("%H:%M:%S"));
	$worksheet->write($row, 2, "M...");
	$worksheet->write($row, 3, "REG");
	$worksheet->write($row, 4, $source_type);
	$worksheet->write($row, 5, $type);
	my $description;
	$description .= "DEVICE:".$usb->{'DeviceClassID'} if $usb->{'DeviceClassID'} ne "";
	$description .= " SERIAL NUMBER:".$usb->{'SerialNumber'} if $usb->{'SerialNumber'} ne "";
	$description .= " FRIENDLY NAME:".$usb->{'FriendlyName'} if $usb->{'FriendlyName'} ne "";
	$description .= " VOLUME GUID:".$usb->{'VolumeGUID'} if $usb->{'VolumeGUID'} ne "";
	$description .= " DRIVE LETTER:".$usb->{'DriveLetter'} if $usb->{'DriveLetter'} ne "";
	$worksheet->write($row, 6, $description);
	$worksheet->write($row, 7, "[".$reg_key."] ".$description);
	$row++;
	return $row;
}

sub pluginmain {
	#Serial Number => Volume GUID
	my $class = shift;
	my $user = shift;
	my $software = $user;
  	my $output = $user;
  	$output =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$1/g;
	$software =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$1SOFTWARE_$2.hiv/g;
	#$software =~ s/(HKU)[^\\]*$/SOFTWARE/g;
	my $system = $software;
	$system =~ s/(.*)SOFTWARE([^\\]*$)/$1SYSTEM$2/g;
	#$system =~ s/(SOFTWARE)[^\\]*$/SYSTEM/g;

	my $reg = Parse::Win32Registry->new($system);
	my $root_key = $reg->get_root_key;
	my $key_path = "MountedDevices";
	my %mountedDevices;
	my %deviceClassID;
	if (my $key = $root_key->get_subkey($key_path)) {
		my @data = $key->get_list_of_values();
		foreach my $d (@data) {
			my $guid = $d->get_name();
			my $data = $d->get_data();
			$data =~ s/\x00//g;
			if (index($data, "USBSTOR") == -1) {next;}
			my @dataArray = split /#/, $data;
			my @guidArray = split /Volume/, $guid;
			if (exists $guidArray[1]) {
				$mountedDevices{$dataArray[-2]} = $guidArray[-1];
				$deviceClassID{$dataArray[-2]} = $dataArray[1];
			}
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}

	#User Serial => User Name
	my %userDictionary;
	$reg = Parse::Win32Registry->new($software);
	$root_key = $reg->get_root_key;
	$key_path = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
	if (my $key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		foreach my $s (@subkeys) {
			my $profilePath;
			eval {
				$profilePath = $s->get_value("ProfileImagePath")->get_data();
			};
			my @dataArray = split /\\/, $profilePath;
			if ($dataArray[1] eq "Users") {
				$userDictionary{$s->get_name()} = $dataArray[2];
			}
		}
	}

	#USER_? to User Serial Number
	my %userMapping;
	my $filename = $system;
	$filename =~ s/(.*)SYSTEM[^\\]*$/$1USERMapping.txt/g;
	open(my $userFile, "<", $filename);
	while ( my $line = <$userFile> ) {
		my $who;
		my $rest;
		my $temp;
	    ($who, $rest) = split /:\s*/, $line, 2;
	    ($temp, $who) = split /\\/, $who, 2;
	    $userMapping{$rest} = $who;
	}

	#Volume GUID => User Name
	my %ownerDictionary;
	my %lastSeenDictionary;
	my @userNumbers = keys %userMapping;
	foreach my $userNumber (@userNumbers) {
		#S20-15-21....
		my $userId = $userMapping{$userNumber};
		my $currentNumber = $userNumber;
		chomp $currentNumber;
		$user =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$1$2_$currentNumber.dat/g;
		$reg = Parse::Win32Registry->new($user);
		$root_key = $reg->get_root_key;
		$key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";
		if (my $key = $root_key->get_subkey($key_path)) {
			my @subkeys = $key->get_list_of_subkeys();
			if (scalar(@subkeys) > 0) {
				foreach my $s (@subkeys) {
					if (exists $ownerDictionary{$s->get_name()}) {
						$ownerDictionary{$s->get_name()} .= ", ".$userDictionary{$userId}." on ".gmtime($s->get_timestamp())." UTC";
						if ($s->get_timestamp() > $lastSeenDictionary{$s->get_name()}) {
							$lastSeenDictionary{$s->get_name()} = $s->get_timestamp();
						}
					} else {
						$ownerDictionary{$s->get_name()} = $userDictionary{$userId}." on ".gmtime($s->get_timestamp())." UTC";
						$lastSeenDictionary{$s->get_name()} = $s->get_timestamp();
					}
				}
			}
		}
	}

	##Map to Drive Letter
	my %driveDictionary;
	$reg = Parse::Win32Registry->new($software);
	$root_key = $reg->get_root_key;
	$key_path = "Microsoft\\Windows Portable Devices\\Devices";
	if (my $key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				my $serialNo = $s->get_name();
				#my @dataArray = split /#/, $serialNo;
				#$serialNo = $dataArray[4];
				$driveDictionary{$serialNo} = $s->get_value("FriendlyName")->get_data();
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}

# Code for System file, getting CurrentControlSet
	my @usbDictionary;
	my $current;
	my $ccs;
	$reg = Parse::Win32Registry->new($system);
	$root_key = $reg->get_root_key;
	$key_path = 'Select';
	if (my $key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		$ccs = "ControlSet00".$current;
	}
	else {
		::rptMsg($key_path." not found.");
		return;
	}

  	my %diskDevice;
  	$key_path = $ccs."\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
	if (my $key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
		        my $serialNo = $s->get_name();
		        $diskDevice{$serialNo} = gmtime($s->get_timestamp())." UTC";
		     }
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}

  	::rptMsg($ccs);
	$key_path = $ccs."\\Enum\\USBStor";
	if (my $key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my @sk = $s->get_list_of_subkeys();
				if (scalar(@sk) > 0) {
					foreach my $k (@sk) {
						my $usbValues = {};
						$usbValues->{'DeviceClassID'} = $s->get_name();
						$usbValues->{'SerialNumber'} = $k->get_name();
						my $friendly;
						eval {
							$friendly = $k->get_value("FriendlyName")->get_data();
						};
						$usbValues->{'FriendlyName'} = $friendly;
						my $volguid = $mountedDevices{$k->get_name()};
						$usbValues->{'VolumeGUID'} = $volguid;
						my $serialnum = $k->get_name();

						for (grep /\b\Q$serialnum\E\b/i, keys %diskDevice)
						{
						    $usbValues->{'RebootConnected'} = $diskDevice{$_};
						}

						if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064")) {
							$usbValues->{'FirstInstallDate'} = gmtime($k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064")->get_timestamp())." UTC";
							if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066")) {
								$usbValues->{'LastConnectedDate'} = gmtime($k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066")->get_timestamp())." UTC";
								if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067")) {
									$usbValues->{'LastRemovedDate'} = gmtime($k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067")->get_timestamp())." UTC";
								}}}
						else {
							if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\00000064\\00000000")) {
								my $t = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\00000064\\00000000")->get_value("Data")->get_data();
								my ($t0,$t1) = unpack("VV",$t);
								$usbValues->{'FirstInstallDate'} = gmtime(::getTime($t0,$t1))." UTC";
								if (exists $lastSeenDictionary{$volguid}) {
									$usbValues->{'LastConnectedDate'} = gmtime($lastSeenDictionary{$volguid})." UTC";
								} else {
									$usbValues->{'LastConnectedDate'} = "";
								}
								$usbValues->{'LastRemovedDate'} = "";
							}
							else {
								$usbValues->{'FirstInstallDate'} = "";
								$usbValues->{'LastConnectedDate'} = "";
								$usbValues->{'LastRemovedDate'} = "";
							}
						}
						for (grep /\b\Q$serialnum\E\b/i, keys %driveDictionary)
						{
						    $usbValues->{'DriveLetter'} = $driveDictionary{$_};
						}
						$usbValues->{'AssociatedUser'} = $ownerDictionary{$volguid};
						push @usbDictionary, $usbValues;
						#print Dumper(%usbValues);
# Attempt to retrieve InstallDate/FirstInstallDate from Properties subkeys
# http://studioshorts.com/blog/2012/10/windows-8-device-property-ids-device-enumeration-pnpobject/
					}
				}
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
	#Checks if all serial numbers of devives found are included in dictionary
	foreach my $serialnum (keys %mountedDevices) {
		my $find = 0;
		for my $usb (@usbDictionary) {
			if($usb->{'SerialNumber'} == $serialnum) { $find = 1; }
		}
		if($find == 0) {
			my $usbValues = {};
			my $volguid = $mountedDevices{$serialnum};
			$usbValues->{'VolumeGUID'} = $volguid;
			$usbValues->{'AssociatedUser'} = $ownerDictionary{$volguid};
			for (grep /\b\Q$serialnum\E\b/i, keys %diskDevice)
			{
			    $usbValues->{'RebootConnected'} = $diskDevice{$_};
			}
			for (grep /\b\Q$serialnum\E\b/i, keys %driveDictionary)
			{
			    $usbValues->{'DriveLetter'} = $driveDictionary{$_};
			}
			$usbValues->{'DeviceClassID'} = $deviceClassID{$serialnum};
			$usbValues->{'SerialNumber'} = $serialnum;
			$usbValues->{'FriendlyName'} = "";
			$usbValues->{'FirstInstallDate'} = "";
			$usbValues->{'LastConnectedDate'} = "";
			$usbValues->{'LastRemovedDate'} = "";
			push @usbDictionary, $usbValues;
		}
	}
	my $workbook = Excel::Writer::XLSX->new($output.'USBParser.xlsx');
	my $worksheet = $workbook->add_worksheet();
	$worksheet->write(0,0,"Device Class ID");
	$worksheet->write(0,1,"Serial Number");
	$worksheet->write(0,2,"Friendly Name");
	$worksheet->write(0,3,"Volume GUID");
	$worksheet->write(0,4,"First Connected Since Reboot");
	$worksheet->write(0,5,"First Install Date");
	$worksheet->write(0,6,"Last Connected Date");
	$worksheet->write(0,7,"Last Removed Date");
	$worksheet->write(0,8,"Drive Letter & Volume Name");
	$worksheet->write(0,9,"Associated User");
	my $row = 1;
	for my $usb (@usbDictionary) {
		$worksheet->write($row,0,$usb->{'DeviceClassID'});
		$worksheet->write($row,1,$usb->{'SerialNumber'});
		$worksheet->write($row,2,$usb->{'FriendlyName'});
		$worksheet->write($row,3,$usb->{'VolumeGUID'});
		$worksheet->write($row,4,$usb->{'RebootConnected'});
		$worksheet->write($row,5,$usb->{'FirstInstallDate'});
		$worksheet->write($row,6,$usb->{'LastConnectedDate'});
		$worksheet->write($row,7,$usb->{'LastRemovedDate'});
		$worksheet->write($row,8,$usb->{'DriveLetter'});
		$worksheet->write($row,9,$usb->{'AssociatedUser'});
		$row++;
	}
	$workbook->close();

	my $workbook2 = Excel::Writer::XLSX->new($output.'Timeline-USB.xlsx');
	my $worksheet2 = $workbook2->add_worksheet();
	my $row2 = 0;
	for my $usb (@usbDictionary) {
		if ($usb->{'RebootConnected'} ne "") {
			my $source_type = "Registry: DeviceClasses";
			my $type = "USB First Connected Since Reboot";
			my $reg_key = "HKEY_LOCAL_MACHINE\\System\\".$ccs."\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
			$row2 = printDetails($worksheet2, $row2, $usb->{'RebootConnected'}, $source_type, $type, $reg_key, $usb);
		}
		if ($usb->{'FirstInstallDate'} ne "") {
			my $source_type = "Registry: USBStor";
			my $type = "USB First Install Date";
			my $reg_key = "HKEY_LOCAL_MACHINE\\System\\".$ccs."\\Enum\\USBStor\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064";
			$row2 = printDetails($worksheet2, $row2, $usb->{'FirstInstallDate'}, $source_type, $type, $reg_key, $usb);
		}
		if ($usb->{'LastConnectedDate'} ne "") {
			my $source_type = "Registry: USBStor";
			my $type = "USB Last Connected Date";
			my $reg_key = "HKEY_LOCAL_MACHINE\\System\\".$ccs."\\Enum\\USBStor\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065";
			$row2 = printDetails($worksheet2, $row2, $usb->{'LastConnectedDate'}, $source_type, $type, $reg_key, $usb);
		}
		if ($usb->{'LastRemovedDate'} ne "") {
			my $source_type = "Registry: USBStor";
			my $type = "USB Last Removed Date";
			my $reg_key = "HKEY_LOCAL_MACHINE\\System\\".$ccs."\\Enum\\USBStor\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066";
			$row2 = printDetails($worksheet2, $row2, $usb->{'LastRemovedDate'}, $source_type, $type, $reg_key, $usb);
		}
		if ($usb->{'AssociatedUser'} ne "") {
			my @users = split(/,/, $usb->{'AssociatedUser'});
			for my $user (@users) {
				my $source_type = "Registry: MountPoints2";
				my $type = "USB Associated User";
				my @owner = $user =~ m/(.*) on/;
				my $reg_key = "HKEY_USERS\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";
				my @date = $user =~ m/ on (.*)/;
				my $datetime = $date[0];
				$datetime =~ s/ UTC//g;
				my $datetime_parsed;
				if ($datetime !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
					my @date = $datetime =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
					$datetime_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
				} else {
					my @parse = $datetime =~ m/(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(.*)/;
					$datetime = $parse[0].$parse[1];
					$datetime_parsed = Time::Piece->strptime($datetime, '%a %b  %d %H:%M:%S %Y');
				}
				$worksheet2->write($row2, 0, $datetime_parsed->strftime("%Y-%m-%d"));
				$worksheet2->write($row2, 1, $datetime_parsed->strftime("%H:%M:%S"));
				$worksheet2->write($row2, 2, "M...");
				$worksheet2->write($row2, 3, "REG");
				$worksheet2->write($row2, 4, $source_type);
				$worksheet2->write($row2, 5, $type);
				my $description;
				$description .= "USER:".$owner[0];
				$description .= " DEVICE:".$usb->{'DeviceClassID'} if $usb->{'DeviceClassID'} ne "";
				$description .= " SERIAL NUMBER:".$usb->{'SerialNumber'} if $usb->{'SerialNumber'} ne "";
				$description .= " FRIENDLY NAME:".$usb->{'FriendlyName'} if $usb->{'FriendlyName'} ne "";
				$description .= " VOLUME GUID:".$usb->{'VolumeGUID'} if $usb->{'VolumeGUID'} ne "";
				$description .= " DRIVE LETTER:".$usb->{'DriveLetter'} if $usb->{'DriveLetter'} ne "";
				$worksheet2->write($row2, 6, $description);
				$worksheet2->write($row2, 7, "[".$reg_key."] ".$description);
				$row2++;
			}
		}
	}
	$workbook2->close();
}
1;
