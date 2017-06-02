#$hive points to System hive, $hive2 points to HKU hive;
package usbParser;
use strict;
use Data::Dumper;
use Excel::Writer::XLSX;

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

sub pluginmain {
	#Serial Number => Volume GUID
	my $class = shift;
	my $user = shift;
	my $software = $user;
  	my $output = $user;
  	$output =~ s/(.*\\)([^_\\]*)_([^\\]*).dat$/$1/g;
	$software =~ s/(.*\\)([^_\\]*)_([^\\]*).dat$/$1SOFTWARE_$2.hiv/g;
	#$software =~ s/(HKU)[^\\]*$/SOFTWARE/g;
	my $system = $software;
	$system =~ s/(.*)SOFTWARE([^\\]*$)/$1SYSTEM$2/g;
	#$system =~ s/(SOFTWARE)[^\\]*$/SYSTEM/g;

	my $reg = Parse::Win32Registry->new($system);
	my $root_key = $reg->get_root_key;
	my $key_path = "MountedDevices";
	my %mountedDevices;
	if (my $key = $root_key->get_subkey($key_path)) {
		my @data = $key->get_list_of_values();
		foreach my $d (@data) {
			my $guid = $d->get_name();
			my $data = $d->get_data();
			$data =~ s/\x00//g;
			if (index($data, "USBSTOR") == -1) {next;}
			my @dataArray = split /#/, $data;
			$guid =~ /({[^\\]*$)/;
			$mountedDevices{$dataArray[2]} = $1;
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
	my @userNumbers = keys %userMapping;
	foreach my $userNumber (@userNumbers) {
		#S20-15-21....
		my $userId = $userMapping{$userNumber};
		my $currentNumber = $userNumber;
		chomp $currentNumber;
		$user =~ s/(.*\\)([^_\\]*)_([^\\]*).dat/$1$2_$currentNumber.dat/g;
		$reg = Parse::Win32Registry->new($user);
		$root_key = $reg->get_root_key;
		$key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";
		if (my $key = $root_key->get_subkey($key_path)) {
			my @subkeys = $key->get_list_of_subkeys();
			if (scalar(@subkeys) > 0) {
				foreach my $s (@subkeys) {
					if (exists $ownerDictionary{$s->get_name()}) {
						$ownerDictionary{$s->get_name()} .= ", ".$userDictionary{$userId};
					} else {
						$ownerDictionary{$s->get_name()} = $userDictionary{$userId};
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

						if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064")) {
							$usbValues->{'FirstConnectedDate'} = gmtime($k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064")->get_timestamp())." UTC";
							if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065")) {
								$usbValues->{'LastConnectedDate'} = gmtime($k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0065")->get_timestamp())." UTC";
								if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067")) {
									$usbValues->{'LastRemovedDate'} = gmtime($k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067")->get_timestamp())." UTC";
								}}}
						else {
							if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\00000064\\00000000")) {
								my $t = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\00000064\\00000000")->get_value("Data")->get_data();
								my ($t0,$t1) = unpack("VV",$t);
								$usbValues->{'FirstConnectedDate'} = gmtime(::getTime($t0,$t1))." UTC";
								if (my $key = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\00000065\\00000000")) {
									$t = $k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\00000065\\00000000")->get_value("Data")->get_data();
									($t0,$t1) = unpack("VV",$t);
									$usbValues->{'LastConnectedDate'} = gmtime(::getTime($t0,$t1))." UTC";
								}
								$usbValues->{'LastRemovedDate'} = "KEY NOT FOUND";
							}
							else {
								$usbValues->{'FirstConnectedDate'} = "KEY NOT FOUND";
								$usbValues->{'LastConnectedDate'} = "KEY NOT FOUND";
								$usbValues->{'LastRemovedDate'} = "KEY NOT FOUND";
							}
						}
						my $serialnum = $k->get_name();
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
	my $workbook = Excel::Writer::XLSX->new($output.'USBParser.xlsx');
	my $worksheet = $workbook->add_worksheet();
	$worksheet->write(0,0,"Device Class ID");
	$worksheet->write(0,1,"Serial Number");
	$worksheet->write(0,2,"Friendly Name");
	$worksheet->write(0,3,"Volume GUID");
	$worksheet->write(0,4,"First Connected Date");
	$worksheet->write(0,5,"Last Connected Date");
	$worksheet->write(0,6,"Last Removed Date");
	$worksheet->write(0,7,"Drive Letter & Volume Name");
	$worksheet->write(0,8,"Associated User");
	my $row = 1;
	for my $usb (@usbDictionary) {
		$worksheet->write($row,0,$usb->{'DeviceClassID'});
		$worksheet->write($row,1,$usb->{'SerialNumber'});
		$worksheet->write($row,2,$usb->{'FriendlyName'});
		$worksheet->write($row,3,$usb->{'VolumeGUID'});
		$worksheet->write($row,4,$usb->{'FirstConnectedDate'});
		$worksheet->write($row,5,$usb->{'LastConnectedDate'});
		$worksheet->write($row,6,$usb->{'LastRemovedDate'});
		$worksheet->write($row,7,$usb->{'DriveLetter'});
		$worksheet->write($row,8,$usb->{'AssociatedUser'});
		$row++;
	}
}
1;
