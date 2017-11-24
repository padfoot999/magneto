#-----------------------------------------------------------
# comdlg32.pl
# Plugin for Registry Ripper
#
# Change history
#   20121005 - updated to address shell item type 0x3A
#   20121005 - updated to parse shell item ID lists
#   20100409 - updated to include Vista and above
#   20100402 - updated IAW Chad Tilbury's post to SANS
#              Forensic Blog
#   20080324 - created
#
# References
#   Win2000 - http://support.microsoft.com/kb/319958
#   XP - http://support.microsoft.com/kb/322948/EN-US/
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package fileOpeningParser;
use strict;
use Excel::Writer::XLSX;
use Time::Local;
use Encode;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20121008);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of user's ComDlg32 key";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $user = shift;
	my $software = $user;
	my $output = $user;
	$output =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$1/g;
	$software =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$1SOFTWARE_$2.hiv/g;
	my $system = $software;
	$system =~ s/(.*)SOFTWARE([^\\]*$)/$1SYSTEM$2/g;
	my $reg = Parse::Win32Registry->new($user);
	my $root_key = $reg->get_root_key;

	my $workbook = Excel::Writer::XLSX->new($output.'FileOpeningParser.xlsx');
	my $worksheet = $workbook->add_worksheet();
	$worksheet->write(0,0,"1");
	$worksheet->write(0,1,"2");
	$worksheet->write(0,2,"3");
	$worksheet->write(0,3,"4");
	$worksheet->write(0,4,"5");
	$worksheet->write(0,5,"6");
	$worksheet->write(0,6,"7");
	$worksheet->write(0,7,"8");
	$worksheet->write(0,8,"9");
	$worksheet->write(0,9,"10");
	$worksheet->write(0,10,"11");
	$worksheet->write(0,11,"12");
	$worksheet->write(0,12,"13");
	$worksheet->write(0,13,"14");
	$worksheet->write(0,14,"15");
	$worksheet->write(0,15,"16");
	$worksheet->write(0,16,"17");

	# $worksheet->write(0,0,"File Name");
	# $worksheet->write(0,1,"File Path");
	# $worksheet->write(0,2,"MRU List EX Order");
	# $worksheet->write(0,3,"Extension");
	# $worksheet->write(0,4,"Last Execution");
	# $worksheet->write(0,5,"Source");
	# $worksheet->write(0,6,"User");
	# $worksheet->write(0,7,"Action");

	my $row = 1;

	my %userDictionary;
	$reg = Parse::Win32Registry->new($software);
	$root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
	my $key = $root_key->get_subkey($key_path);
	my @subkeys = $key->get_list_of_subkeys();
	if (scalar(@subkeys) > 0) {
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
		$user =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$1$2_$currentNumber.dat/g;
		$reg = Parse::Win32Registry->new($user);
		$root_key = $reg->get_root_key;

# LastVistedMRU
		$key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32";
		my @vals;
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");

			my @subkeys = $key->get_list_of_subkeys();

			if (scalar @subkeys > 0) {
				foreach my $s (@subkeys) {
					if ($s->get_name() eq "LastVisitedMRU") {
						$row = 1;
						parseLastVisitedMRU($s, $row, $worksheet, $userDictionary{$userId});
					}

					if ($s->get_name() eq "OpenSaveMRU") {
						$row = 1;
						parseOpenSaveMRU($s, $row, $worksheet, $userDictionary{$userId});
					}

					if ($s->get_name() eq "LastVisitedPidlMRU" || $s->get_name() eq "LastVisitedPidlMRULegacy") {
						$row = 1;
						parseLastVisitedPidlMRU($s, $row, $worksheet, $userDictionary{$userId});
					}

					if ($s->get_name() eq "OpenSavePidlMRU") {
						$row = 1;
						parseOpenSavePidlMRU($s, $row, $worksheet, $userDictionary{$userId});
					}
				}
			}
		}
		$row = 1;
		$key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs";
		if ($key = $root_key->get_subkey($key_path)) {
	# Get RecentDocs values
			my %rdvals = getRDValues($key);
			if (%rdvals) {
				my $tag;
				if (exists $rdvals{"MRUListEx"}) {
					$tag = "MRUListEx";
				}
				elsif (exists $rdvals{"MRUList"}) {
					$tag = "MRUList";
				}
				else {

				}
				my $count = 0;
				my @list = split(/,/,$rdvals{$tag});
				foreach my $i (@list) {
					#File Name
					$worksheet->write($row,0,$rdvals{$i});
					#MRU List EX
					$worksheet->write($row,1,$count);
					#Extension
					$worksheet->write($row,2,"*");
					#User
					$worksheet->write($row,3,$userDictionary{$userId});
					$row++;
					$count++;
				}
			}
	# Get RecentDocs subkeys' values
			@subkeys = $key->get_list_of_subkeys();
			if (scalar(@subkeys) > 0) {
				foreach my $s (@subkeys) {
					my $count = 0;
					my %rdvals = getRDValues($s);
					if (%rdvals) {
						my $tag;
						if (exists $rdvals{"MRUListEx"}) {
							$tag = "MRUListEx";
						}
						elsif (exists $rdvals{"MRUList"}) {
							$tag = "MRUList";
						}
						else {

						}

						my @list = split(/,/,$rdvals{$tag});
						foreach my $i (@list) {
							#File Name
							$worksheet->write($row,0,$rdvals{$i});
							#MRU List EX Order
							$worksheet->write($row,1,$count);
							#Extension
							$worksheet->write($row,2,$s->get_name());
							#User
							$worksheet->write($row,3,$userDictionary{$userId});
							$row++;
							$count++;
						}
					}
				}
			}
		}
		$row = 1;
		my $version;
		my $tag = 0;
		my @versions = ("7\.0","8\.0", "9\.0", "10\.0", "11\.0");
		my %paths = ("7\.0" => "Microsoft Office 95",
	                 "8\.0" => "Microsoft Office 97",
	                 "9\.0" => "Microsoft Office 2000",
	                 "10\.0" => "Microsoft Office XP",
	                 "11\.0" => "Microsoft Office 2003");
		foreach my $ver (@versions) {
			$key_path = "Software\\Microsoft\\Office\\".$ver."\\Common\\Open Find";
			if (defined($root_key->get_subkey($key_path))) {
				$version = $ver;
				$tag = 1;
			}
		}

		if ($tag) {
			$key_path = "Software\\Microsoft\\Office\\".$version;
			my $of_key = $root_key->get_subkey($key_path);
			if ($of_key) {
	# Attempt to retrieve Word docs
				my @funcs = ("Open","Save As","File Save");
				foreach my $func (@funcs) {
					my $word = "Common\\Open Find\\Microsoft Office Word\\Settings\\".$func."\\File Name MRU";
					my $word_key = $of_key->get_subkey($word);
					if ($word_key) {
						my $value = $word_key->get_value("Value")->get_data();
						my @data = split(/\x00/,$value);
						map{::rptMsg("$_");}@data;
					}
				}
	# Attempt to retrieve Excel docs
				my $excel = 'Excel\\Recent Files';
				if (my $excel_key = $of_key->get_subkey($excel)) {
					my @vals = $excel_key->get_list_of_values();
					if (scalar(@vals) > 0) {
						my %files;
	# Retrieve values and load into a hash for sorting
						foreach my $v (@vals) {
							my $val = $v->get_name();
							my $data = $v->get_data();
							my $tag = (split(/File/,$val))[1];
							$files{$tag} = $val.":".$data;
						}
	# Print sorted content to report file
						my $count = 0;
						foreach my $u (sort {$a <=> $b} keys %files) {
							my ($val,$data) = split(/:/,$files{$u},2);
							#Extension
							my $extension = $data;
							$extension =~ s/.*(\.[a-zA-Z0-9]*).*/$1/;
							$worksheet->write($row,6,$extension);
							#MRU Ex Order
							$worksheet->write($row,5,$count);
							#Last Execution
							my $datetime = $data;
							$datetime =~ s/.*\.[a-zA-Z0-9]* (.*)/$1/;
							$worksheet->write($row,7,$datetime);
							$data =~ s/ $datetime//;
							$worksheet->write($row,4,$data);
							#User
							$worksheet->write($row,8,$userDictionary{$userId});
							$row++;
							$count++;
						}
					}
				}
	# Attempt to retrieve PowerPoint docs
				my $ppt = 'PowerPoint\\Recent File List';
				if (my $ppt_key = $of_key->get_subkey($ppt)) {
					my @vals = $ppt_key->get_list_of_values();
					if (scalar(@vals) > 0) {
						my %files;
	# Retrieve values and load into a hash for sorting
						foreach my $v (@vals) {
							my $val = $v->get_name();
							my $data = $v->get_data();
							my $tag = (split(/File/,$val))[1];
							$files{$tag} = $val.":".$data;
						}
	# Print sorted content to report file
						my $count = 0;
						foreach my $u (sort {$a <=> $b} keys %files) {
							my ($val,$data) = split(/:/,$files{$u},2);
							#Extension
							my $extension = $data;
							$extension =~ s/.*(\.[a-zA-Z0-9]*).*/$1/;
							$worksheet->write($row,6,$extension);
							#MRU Ex Order
							$worksheet->write($row,5,$count);
							#Last Execution
							my $datetime = $data;
							$datetime =~ s/.*\.[a-zA-Z0-9]* (.*)/$1/;
							$worksheet->write($row,7,$datetime);
							$data =~ s/ $datetime//;
							$worksheet->write($row,4,$data);
							#User
							$worksheet->write($row,8,$userDictionary{$userId});
							$row++;
							$count++;
						}
					}
				}
			}
		}
		else {
			$tag = 0;
			@versions = ("12\.0", "14\.0", "15\.0");
			%paths = ("12\.0" => "Microsoft Office 2007",
					  "14\.0" => "Microsoft Office 2010",
		              "15\.0" => "Microsoft Office 365/2013");
			foreach my $ver (@versions) {
				$key_path = "Software\\Microsoft\\Office\\".$ver."\\Common\\Open Find";
				if (defined($root_key->get_subkey($key_path))) {
					$version = $ver;
					$tag = 1;
				}
			}

			if ($tag) {
				$key_path = "Software\\Microsoft\\Office\\".$version;
				my $of_key = $root_key->get_subkey($key_path);
				if ($of_key) {
		# Attempt to retrieve Word docs
					my $word = 'Word\\File MRU';
					if (my $word_key = $of_key->get_subkey($word)) {
						my @vals = $word_key->get_list_of_values();
						if (scalar(@vals) > 0) {
							my %files;
		# Retrieve values and load into a hash for sorting
							foreach my $v (@vals) {
								my $val = $v->get_name();
								if ($val eq "Max Display") { next; }
								my $data = getWinTS($v->get_data());
								my $tag = (split(/Item/,$val))[1];
								$files{$tag} = $val.":".$data;
							}
		# Print sorted content to report file
							my $count = 0;
							foreach my $u (sort {$a <=> $b} keys %files) {
								my ($val,$data) = split(/:/,$files{$u},2);
								#Extension
								my $extension = $data;
								$extension =~ s/.*(\.[a-zA-Z0-9]*).*/$1/;
								$worksheet->write($row,6,$extension);
								#MRU Ex Order
								$worksheet->write($row,5,$count);
								#Last Execution
								my $datetime = $data;
								$datetime =~ s/.*\.[a-zA-Z0-9]* (.*)/$1/;
								$worksheet->write($row,7,$datetime);
								$data =~ s/ $datetime//;
								$worksheet->write($row,4,$data);
								#User
								$worksheet->write($row,8,$userDictionary{$userId});
								$row++;
								$count++;
							}
						}
					}

		# Attempt to retrieve Excel docs
					my $excel = 'Excel\\File MRU';
					if (my $excel_key = $of_key->get_subkey($excel)) {
						::rptMsg($key_path."\\".$excel);
						::rptMsg("LastWrite Time ".gmtime($excel_key->get_timestamp())." (UTC)");
						my @vals = $excel_key->get_list_of_values();
						if (scalar(@vals) > 0) {
							my %files;
		# Retrieve values and load into a hash for sorting
							foreach my $v (@vals) {
								my $val = $v->get_name();
								if ($val eq "Max Display") { next; }
								my $data = getWinTS($v->get_data());
								my $tag = (split(/Item/,$val))[1];
								$files{$tag} = $val.":".$data;
							}
		# Print sorted content to report file
							my $count = 0;
							foreach my $u (sort {$a <=> $b} keys %files) {
								my ($val,$data) = split(/:/,$files{$u},2);
								#Extension
								my $extension = $data;
								$extension =~ s/.*(\.[a-zA-Z0-9]*).*/$1/;
								$worksheet->write($row,6,$extension);
								#MRU Ex Order
								$worksheet->write($row,5,$count);
								#Last Execution
								my $datetime = $data;
								$datetime =~ s/.*\.[a-zA-Z0-9]* (.*)/$1/;
								$worksheet->write($row,7,$datetime);
								$data =~ s/ $datetime//;
								$worksheet->write($row,4,$data);
								#User
								$worksheet->write($row,8,$userDictionary{$userId});
								$row++;
								$count++;
							}
						}
					}

		# Attempt to retrieve Access docs
					my $access = 'Access\\File MRU';
					if (my $access_key = $of_key->get_subkey($access)) {
						::rptMsg($key_path."\\".$access);
						::rptMsg("LastWrite Time ".gmtime($access_key->get_timestamp())." (UTC)");
						my @vals = $access_key->get_list_of_values();
						if (scalar(@vals) > 0) {
							my %files;
		# Retrieve values and load into a hash for sorting
							foreach my $v (@vals) {
								my $val = $v->get_name();
								if ($val eq "Max Display") { next; }
								my $data = getWinTS($v->get_data());
								my $tag = (split(/Item/,$val))[1];
								$files{$tag} = $val.":".$data;
							}
		# Print sorted content to report file
							my $count = 0;
							foreach my $u (sort {$a <=> $b} keys %files) {
								my ($val,$data) = split(/:/,$files{$u},2);
								#Extension
								my $extension = $data;
								$extension =~ s/.*(\.[a-zA-Z0-9]*).*/$1/;
								$worksheet->write($row,6,$extension);
								#MRU Ex Order
								$worksheet->write($row,5,$count);
								#Last Execution
								my $datetime = $data;
								$datetime =~ s/.*\.[a-zA-Z0-9]* (.*)/$1/;
								$worksheet->write($row,7,$datetime);
								$data =~ s/ $datetime//;
								$worksheet->write($row,4,$data);
								#User
								$worksheet->write($row,8,$userDictionary{$userId});
								$row++;
								$count++;
							}
						}
					}

		# Attempt to retrieve PowerPoint docs
					my $ppt = 'PowerPoint\\File MRU';
					if (my $ppt_key = $of_key->get_subkey($ppt)) {
						::rptMsg($key_path."\\".$ppt);
						::rptMsg("LastWrite Time ".gmtime($ppt_key->get_timestamp())." (UTC)");
						my @vals = $ppt_key->get_list_of_values();
						if (scalar(@vals) > 0) {
							my %files;
		# Retrieve values and load into a hash for sorting
							foreach my $v (@vals) {
								my $val = $v->get_name();
								if ($val eq "Max Display") { next; }
								my $data = getWinTS($v->get_data());
								my $tag = (split(/Item/,$val))[1];
								$files{$tag} = $val.":".$data;
							}
		# Print sorted content to report file
							my $count = 0;
							foreach my $u (sort {$a <=> $b} keys %files) {
								my ($val,$data) = split(/:/,$files{$u},2);
								#Extension
								my $extension = $data;
								$extension =~ s/.*(\.[a-zA-Z0-9]*).*/$1/;
								$worksheet->write($row,6,$extension);
								#MRU Ex Order
								$worksheet->write($row,5,$count);
								#Last Execution
								my $datetime = $data;
								$datetime =~ s/.*\.[a-zA-Z0-9]* (.*)/$1/;
								$worksheet->write($row,7,$datetime);
								$data =~ s/ $datetime//;
								$worksheet->write($row,4,$data);
								#User
								$worksheet->write($row,8,$userDictionary{$userId});
								$row++;
								$count++;
							}
						}
					}
				}
			}
		}
	}
	$workbook->close();
}

sub getRDValues {
	my $key = shift;

	my $mru = "MRUList";
	my %rdvals;

	my @vals = $key->get_list_of_values();
	if (scalar @vals > 0) {
		foreach my $v (@vals) {
			my $name = $v->get_name();
			my $data = $v->get_data();
			if ($name =~ m/^$mru/) {
				my @mru;
				if ($name eq "MRUList") {
					@mru = split(//,$data);
				}
				elsif ($name eq "MRUListEx") {
					@mru = unpack("V*",$data);
				}
# Horrible, ugly cludge; the last, terminating value in MRUListEx
# is 0xFFFFFFFF, so we remove it.
				pop(@mru);
				$rdvals{$name} = join(',',@mru);
			}
			else {
# New code
				$data = decode("ucs-2le", $data);
				my $file = (split(/\x00/,$data))[0];
#				my $file = (split(/\x00\x00/,$data))[0];
#				$file =~ s/\x00//g;
				$rdvals{$name} = $file;
			}
		}
		return %rdvals;
	}
	else {
		return undef;
	}
}

sub getWinTS {
	my $data = $_[0];
	my $winTS;
	my $dateTime;
	(my $prefix, my $suffix) = split(/\*/,$data);
	if ($prefix =~ /\[.{9}\]\[T(.{16})\]/) {
		$winTS = $1;
		my @vals = split(//,$winTS);
		my $t0 = join('',@vals[0..7]);
		my $t1 = join('',@vals[8..15]);
		$dateTime = ::getTime(hex($t1),hex($t0));
	}
	return ($suffix ."  ". gmtime($dateTime));
}

sub parseLastVisitedMRU {
	my $key = shift;
	my $row = shift;
	my $worksheet = shift;
	my $user = shift;
	my %lvmru;
	my @mrulist;
	my @vals = $key->get_list_of_values();

	if (scalar(@vals) > 0) {
# First, read in all of the values and the data
		foreach my $v (@vals) {
			$lvmru{$v->get_name()} = $v->get_data();
		}
# Then, remove the MRUList value
		if (exists $lvmru{MRUList}) {
			::rptMsg("  MRUList = ".$lvmru{MRUList});
			@mrulist = split(//,$lvmru{MRUList});
			delete($lvmru{MRUList});
			foreach my $m (@mrulist) {
				my ($file,$dir) = split(/\x00\x00/,$lvmru{$m},2);
				$file =~ s/\x00//g;
				$dir  =~ s/\x00//g;
				#File Name
				$worksheet->write($row,9,$file);
				#File Path
				$worksheet->write($row,10,$dir);
				#MRU List EX
				$worksheet->write($row,11,$m);
				#User
				$worksheet->write($row,12,$user);
				$row++;
			}
		}
	}
}

sub parseOpenSaveMRU {
	my $key = shift;
	my $row = shift;
	my $worksheet = shift;
	my $user = shift;

	$row = parseOpenSaveValues($key, $row, $worksheet, $user);
# Now, let's get the subkeys
	my @sk = $key->get_list_of_subkeys();
	if (scalar(@sk) > 0) {
		foreach my $s (@sk) {
			parseOpenSaveValues($s, $row, $worksheet, $user);
		}
	}
}

sub parseOpenSaveValues {
	my $key = shift;
	my $row = shift;
	my $worksheet = shift;
	my $user = shift;
	my $order = 1;

	my %osmru;
	my @vals = $key->get_list_of_values();
	if (scalar(@vals) > 0) {
		map{$osmru{$_->get_name()} = $_->get_data()}(@vals);
		if (exists $osmru{MRUList}) {
			my @mrulist = split(//,$osmru{MRUList});
			delete($osmru{MRUList});
			foreach my $m (@mrulist) {
				#File Path
				$worksheet->write($row,13,$osmru{$m});
				#MRU List EX
				$worksheet->write($row,14,$m);
				#User
				$worksheet->write($row,16,$user);
				#Extension
				$worksheet->write($row,15,$key->get_name());
				$row++;
			}
		}
	}
  return $row;
}

sub parseLastVisitedPidlMRU {
	my $key = shift;
	my $row = shift;
	my $worksheet = shift;
	my $user = shift;
	my %lvmru;
	my @mrulist;
	my @vals = $key->get_list_of_values();
	my %mru;
	my $count = 0;

	if (scalar(@vals) > 0) {
# First, read in all of the values and the data
		foreach my $v (@vals) {
			$lvmru{$v->get_name()} = $v->get_data();
		}
# Then, remove the MRUList value
		if (exists $lvmru{MRUListEx}) {
			my @mrulist = unpack("V*",$lvmru{MRUListEx});
			foreach my $n (0..(scalar(@mrulist) - 2)) {
				$mru{$count++} = $lvmru{$mrulist[$n]};
			}
			delete $mru{0xffffffff};

			foreach my $m (sort {$a <=> $b} keys %mru) {
				my ($file,$shell) = split(/\x00\x00/,$mru{$m},2);
				$file =~ s/\x00//g;
				$shell =~ s/^\x00//;
				my $str = parseShellItem($shell);
				#File Name
				$worksheet->write($row,9,$file);
				#File Path
				$worksheet->write($row,10,$str);
				#MRU List EX
				$worksheet->write($row,11,$m);
				#User
				$worksheet->write($row,12,$user);
				$row++;
			}
		}
	}
}

#-----------------------------------------------------------
#
#-----------------------------------------------------------
sub parseOpenSavePidlMRU {
	my $key = shift;
	my $row = shift;
	my $worksheet = shift;
	my $user = shift;
	my @subkeys = $key->get_list_of_subkeys();

	if (scalar(@subkeys) > 0) {
		foreach my $s (@subkeys) {
			my @vals = $s->get_list_of_values();

			my %lvmru = ();
			my @mrulist = ();
			my %mru = ();
			my $count = 0;

			if (scalar(@vals) > 0) {
# First, read in all of the values and the data
				foreach my $v (@vals) {
					$lvmru{$v->get_name()} = $v->get_data();
				}
# Then, remove the MRUList value
				if (exists $lvmru{MRUListEx}) {
					my @mrulist = unpack("V*",$lvmru{MRUListEx});
					foreach my $n (0..(scalar(@mrulist) - 2)) {
						$mru{$count++} = $lvmru{$mrulist[$n]};
					}
					delete $mru{0xffffffff};

					foreach my $m (sort {$a <=> $b} keys %mru) {
						my $str = parseShellItem($mru{$m});
						#File Path
						$worksheet->write($row,13,$str);
						#MRUListEX
						$worksheet->write($row,14,$m);
						#User
						$worksheet->write($row,16,$user);
						#Extension
						$worksheet->write($row,15,$s->get_name());
						$row++;
					}
				}
			}
		}
	}
}

#-----------------------------------------------------------
#
#-----------------------------------------------------------
sub parseShellItem {
	my $data = shift;
	my $len = length($data);
	my $str;

	my $tag = 1;
	my $cnt = 0;
	while ($tag) {
		my %item = ();
		my $sz = unpack("v",substr($data,$cnt,2));
		$tag = 0 if (($sz == 0) || ($cnt + $sz > $len));

		my $dat = substr($data,$cnt,$sz);
		my $type = unpack("C",substr($dat,2,1));
		my $followingchar = unpack("C",substr($dat,3,1));
#		::rptMsg(sprintf "  Size: ".$sz."  Type: 0x%x",$type);

		if ($type == 0x1F) {
# System Folder
 			%item = parseSystemFolderEntry($dat);
 			$str .= "\\".$item{name};
 		}
 		elsif ($type == 0x2F) {
# Volume (Drive Letter)
 			%item = parseDriveEntry($dat);
 			$item{name} =~ s/\\$//;
 			$str .= "\\".$item{name};
 		}
 		elsif ($type == 0x31 || $type == 0x32 || $type == 0x3a || $type == 0x74) {
 			%item = parseFolderEntry($dat, $sz);
 			$str .= "\\".$item{name};
 		}
 		elsif ($type == 0x00) {
 		}
 		elsif ($type == 0xc3 || $type == 0x41 || $type == 0x42 || $type == 0x46 || $type == 0x47) {
# Network stuff
			my $id = unpack("C",substr($dat,3,1));
			if ($type == 0xc3 && $id != 0x01) {
				%item = parseNetworkEntry($dat);
			}
			else {
				%item = parseNetworkEntry($dat);
			}
			$str .= "\\".$item{name};
 		}
 		else {
 			$item{name} = sprintf "Unknown Type (0x%x)",$type;
 			$str .= "\\".$item{name};
# 			probe($dat);
 		}
		$cnt += $sz;
	}
	$str =~ s/^\\//;
	return $str;
}
sub parseFilePath {
	my $data = shift;
	my $id = shift;
	my $len = length($data);
	my $tag = 1;
	my $cnt = 0;
	my $check = 0;
	my $str;
	while ($tag) {
		my %item = ();
		my $sz = unpack("v",substr($data,$cnt,2));
		$tag = 0 if (($sz == 0) || ($cnt + $sz > $len));

		my $dat = substr($data,$cnt,$sz);
		my $type = unpack("C",substr($dat,2,1));
#		::rptMsg(sprintf "  Size: ".$sz."  Type: 0x%x",$type);

		if ($type == $id) {
			$check = 1;
		}
		if ($check) {
			$str .= "\\".$type;
		}
		$cnt += $sz;
	}
	return $str;
}

#-----------------------------------------------------------
#
#-----------------------------------------------------------
sub parseSystemFolderEntry {
	my $data     = shift;
	my %item = ();

	my %vals = (0x00 => "Explorer",
	            0x42 => "Libraries",
	            0x44 => "Users",
	            0x4c => "Public",
	            0x48 => "My Documents",
	            0x50 => "My Computer",
	            0x58 => "My Network Places",
	            0x60 => "Recycle Bin",
	            0x68 => "Explorer",
	            0x70 => "Control Panel",
	            0x78 => "Recycle Bin",
	            0x80 => "My Games");

	$item{type} = unpack("C",substr($data,2,1));
	$item{id}   = unpack("C",substr($data,3,1));
	if (exists $vals{$item{id}}) {
		$item{name} = $vals{$item{id}};
	}
	else {
		$item{name} = parseGUID(substr($data,4,16));
	}
	return %item;
}

#-----------------------------------------------------------
# parseGUID()
# Takes 16 bytes of binary data, returns a string formatted
# as an MS GUID.
#-----------------------------------------------------------
sub parseGUID {
	my $data     = shift;
  my $d1 = unpack("V",substr($data,0,4));
  my $d2 = unpack("v",substr($data,4,2));
  my $d3 = unpack("v",substr($data,6,2));
	my $d4 = unpack("H*",substr($data,8,2));
  my $d5 = unpack("H*",substr($data,10,6));
  return sprintf "{%08x-%x-%x-$d4-$d5}",$d1,$d2,$d3;
}

#-----------------------------------------------------------
#
#-----------------------------------------------------------
sub parseDriveEntry {
	my $data     = shift;
	my %item = ();
	$item{type} = unpack("C",substr($data,2,1));;
	$item{name} = substr($data,3,3);
	return %item;
}
#-----------------------------------------------------------
# parseNetworkEntry()
#
#-----------------------------------------------------------
sub parseNetworkEntry {
	my $data = shift;
	my %item = ();
	$item{type} = unpack("C",substr($data,2,1));

	my @n = split(/\x00/,substr($data,4,length($data) - 4));
	$item{name} = $n[0];
	$item{name} =~ s/^\W//;
	return %item;
}
#-----------------------------------------------------------
#
#-----------------------------------------------------------
sub parseFolderEntry {
	my $data     = shift;
	my $sz = shift;
	my %item = ();

	$item{type} = unpack("C",substr($data,2,1));
# Type 0x74 folders have a slightly different format

	my $ofs_mdate;
	my $ofs_shortname;

	if ($item{type} == 0x74) {
		$ofs_mdate = 0x12;
	}
	elsif (substr($data,4,4) eq "AugM") {
		$ofs_mdate = 0x1c;
	}
	elsif ($item{type} == 0x31 || $item{type} == 0x32 || $item{type} == 0x3a) {
		$ofs_mdate = 0x08;
	}
	else {}
# some type 0x32 items will include a file size
	if ($item{type} == 0x32) {
		my $size = unpack("V",substr($data,4,4));
		if ($size != 0) {
			$item{filesize} = $size;
		}
	}

	my @m = unpack("vv",substr($data,$ofs_mdate,4));
	($item{mtime_str},$item{mtime}) = convertDOSDate($m[0],$m[1]);

# Need to read in short name; nul-term ASCII
#	$item{shortname} = (split(/\x00/,substr($data,12,length($data) - 12),2))[0];
	$ofs_shortname = $ofs_mdate + 6;
	my $tag = 1;
	my $cnt = 0;
	my $str = "";
	while($tag) {
		my $s = substr($data,$ofs_shortname + $cnt,1);
		if ($s =~ m/\x00/ && ((($cnt + 1) % 2) == 0)) {
			$tag = 0;
		}
		else {
			$str .= $s;
			$cnt++;
		}
	}
#	$str =~ s/\x00//g;
	my $shortname = $str;
	my $ofs = $ofs_shortname + $cnt + 1;
# Read progressively, 1 byte at a time, looking for 0xbeef
	$tag = 1;
	$cnt = 0;
	while ($tag) {
		if (unpack("v",substr($data,$ofs + $cnt,2)) == 0xbeef) {
			$tag = 0;
		}
		else {
			$cnt++;
		}
	}
	$item{extver} = unpack("v",substr($data,$ofs + $cnt - 4,2));

#	::rptMsg(sprintf "  BEEF Offset: 0x%x",$ofs + $cnt);
#	::rptMsg("  Version: ".$item{extver});

	$ofs = $ofs + $cnt + 2;

	@m = unpack("vv",substr($data,$ofs,4));
	($item{ctime_str},$item{ctime}) = convertDOSDate($m[0],$m[1]);
	$ofs += 4;
	@m = unpack("vv",substr($data,$ofs,4));
	($item{atime_str},$item{atime}) = convertDOSDate($m[0],$m[1]);
	$ofs += 4;

	my $jmp;
	if ($item{extver} == 0x03) {
		$jmp = 8;
	}
	elsif ($item{extver} == 0x07) {
		$jmp = 22;
	}
	elsif ($item{extver} == 0x08) {
		$jmp = 26;
	}
	else {}

	$ofs += $jmp;
	::rptMsg(sprintf "  Offset: 0x%x",$ofs);

	$str = substr($data,$ofs,length($data) - $ofs - 1);

	my $longname;
	my @short;
	my $test = 1;
	@short = split(//,$shortname);
	$longname = (split(/\x00\x00/,$str,2))[1];
	chop($longname);
	$longname =~ s/\x00//g;
	$longname =~ s/\n//;
	::rptMsg($shortname);
	::rptMsg($longname);
	my $lower = lc $short[0];
	my $substring = "\@shell32.dll,-";
	if ($longname ne "") {
		$longname =~ s/^.*?($short[0]|$lower)/$1/;
		$item{name} = $longname;
		if (index($longname, $substring) != -1) {
			$longname =~ s/$substring.*$//;
			$item{name} = $longname;
		}
	}
	else {
		$item{name} = $shortname;
	}
	$item{name} =~ s/[\000-\010]|[\013-\014]|[\016-\037]*//;
	return %item;
}

#-----------------------------------------------------------
# convertDOSDate()
# subroutine to convert 4 bytes of binary data into a human-
# readable format.  Returns both a string and a Unix-epoch
# time.
#-----------------------------------------------------------
sub convertDOSDate {
	my $date = shift;
	my $time = shift;

	if ($date == 0x00 || $time == 0x00){
		return (0,0);
	}
	else {
		my $sec = ($time & 0x1f) * 2;
		$sec = "0".$sec if (length($sec) == 1);
		if ($sec == 60) {$sec = 59};
		my $min = ($time & 0x7e0) >> 5;
		$min = "0".$min if (length($min) == 1);
		my $hr  = ($time & 0xF800) >> 11;
		$hr = "0".$hr if (length($hr) == 1);
		my $day = ($date & 0x1f);
		$day = "0".$day if (length($day) == 1);
		my $mon = ($date & 0x1e0) >> 5;
		$mon = "0".$mon if (length($mon) == 1);
		my $yr  = (($date & 0xfe00) >> 9) + 1980;
		my $gmtime = timegm($sec,$min,$hr,$day,($mon - 1),$yr);
    return ("$yr-$mon-$day $hr:$min:$sec",$gmtime);
#		return gmtime(timegm($sec,$min,$hr,$day,($mon - 1),$yr));
	}
}
#-----------------------------------------------------------
# probe()
#
# Code the uses printData() to insert a 'probe' into a specific
# location and display the data
#
# Input: binary data of arbitrary length
# Output: Nothing, no return value.  Displays data to the console
#-----------------------------------------------------------
sub probe {
	my $data = shift;
	my @d = printData($data);

	foreach (0..(scalar(@d) - 1)) {
		print $d[$_]."\n";
	}
}
#-----------------------------------------------------------
# printData()
# subroutine used primarily for debugging; takes an arbitrary
# length of binary data, prints it out in hex editor-style
# format for easy debugging
#-----------------------------------------------------------
sub printData {
	my $data = shift;
	my $len = length($data);

	my @display = ();

	my $loop = $len/16;
	$loop++ if ($len%16);

	foreach my $cnt (0..($loop - 1)) {
# How much is left?
		my $left = $len - ($cnt * 16);

		my $n;
		($left < 16) ? ($n = $left) : ($n = 16);

		my $seg = substr($data,$cnt * 16,$n);
		my $lhs = "";
		my $rhs = "";
		foreach my $i ($seg =~ m/./gs) {
# This loop is to process each character at a time.
			$lhs .= sprintf(" %02X",ord($i));
			if ($i =~ m/[ -~]/) {
				$rhs .= $i;
    	}
    	else {
				$rhs .= ".";
     	}
		}
		$display[$cnt] = sprintf("0x%08X  %-50s %s",$cnt,$lhs,$rhs);
	}
	return @display;
}

1;
