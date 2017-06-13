#-----------------------------------------------------------
# officedocs2010.pl
#   Plugin to parse Office 2010 MRU entries (Word, Excel, Access, and PowerPoint)
#
# Change history
#   20110901 - updated to remove dependency on the DateTime module
#   20010415 [fpi] * added this banner and change the name from "officedocs"
#                    to "officedocs2010", since this plugins is little different
#                    from Harlan's one (merging suggested)
#   20110830 [fpi] + banner, no change to the version number
#
# References
# 
# copyright 2011 Cameron Howell
# modified 20110901, H. Carvey keydet89@yahoo.com
#-----------------------------------------------------------
package officedocsnew;
use strict;
use Excel::Writer::XLSX;
use Time::Piece;
use Regexp::Common qw(time);

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 2011090);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets user's Office doc MRU values";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
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

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching officedocsnew v.".$VERSION);
    ::rptMsg("officedocsnew v.".$VERSION); # banner
    ::rptMsg("(".getHive().") ".getShortDescr()."\n"); # banner

	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	# ::rptMsg("officedocs v.".$VERSION); # 20110830 [fpi] - redundant
	my $version;
	my $tag = 0;
	my @versions = ("12\.0", "14\.0", "15\.0");
	my %paths = ("12\.0" => "Microsoft Office 2007",
				"14\.0" => "Microsoft Office 2010",
             	"15\.0" => "Microsoft Office 365/2013");
	foreach my $ver (@versions) {
		my $key_path = "Software\\Microsoft\\Office\\".$ver."\\Common\\Open Find";
		if (defined($root_key->get_subkey($key_path))) {
			$version = $ver;
			$tag = 1;
		}
	}
	
	if ($tag) {
		my $workbook_name = $ntuser;
		$workbook_name =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$1Timeline-OfficeDocsNew-$3.xlsx/g;
		my @user = $ntuser =~ m/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/;
		my $currentuser = $user[1]."_".$user[2];
		my $workbook = Excel::Writer::XLSX->new($workbook_name);
		my $worksheet = $workbook->add_worksheet();
		my $row = 0;

		::rptMsg("MSOffice version ".$version." (".$paths{$version}.") located.");
		my $key_path = "Software\\Microsoft\\Office\\".$version;	                 
		my $of_key = $root_key->get_subkey($key_path);
		if ($of_key) {
# Attempt to retrieve Word docs
			my $word = 'Word\\File MRU';
			if (my $word_key = $of_key->get_subkey($word)) {
				::rptMsg($key_path."\\".$word);
				::rptMsg("LastWrite Time ".gmtime($word_key->get_timestamp())." (UTC)");
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
					foreach my $u (sort {$a <=> $b} keys %files) {
						my ($val,$data) = split(/:/,$files{$u},2);
						::rptMsg("  ".$val." -> ".$data);
						my $lastUsedDate = $data;
						my @date;
						my $lastUsedDate_parsed;
						if ($lastUsedDate !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
							@date = $lastUsedDate =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
				   			$lastUsedDate_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
				   		} else {
				   			my @parse = $lastUsedDate =~ m/(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(.*)/;
				   			$lastUsedDate = $parse[0].$parse[1];
				   			$lastUsedDate_parsed = Time::Piece->strptime($lastUsedDate, '%a %b  %d %H:%M:%S %Y');
				   		}
						$worksheet->write($row, 0, $lastUsedDate_parsed->strftime("%Y-%m-%d"));
						$worksheet->write($row, 1, $lastUsedDate_parsed->strftime("%H:%M:%S"));
						$worksheet->write($row, 2, ".A..");
						$worksheet->write($row, 3, "REG");
						$worksheet->write($row, 4, "Registry Key: Office Documents MRU");
						$worksheet->write($row, 5, "File Access Time");
						my $reg_key = $currentuser."\\".$key_path."\\".$word;
						my $description = "FILE:".$data;
						$description =~ s/$lastUsedDate_parsed//g;
						$worksheet->write($row, 6, $description);
						$worksheet->write($row, 7, "[".$reg_key."] ".$description);
						$row++;
					}
				}
				else {
					::rptMsg($key_path.$word." has no values.");
				}
			}
			else {
				::rptMsg($key_path.$word." not found.");
			}
			::rptMsg("");
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
					foreach my $u (sort {$a <=> $b} keys %files) {
						my ($val,$data) = split(/:/,$files{$u},2);
						::rptMsg("  ".$val." -> ".$data);
						my $lastUsedDate = $data;
						my @date;
						my $lastUsedDate_parsed;
						if ($lastUsedDate !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
							@date = $lastUsedDate =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
				   			$lastUsedDate_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
				   		} else {
				   			my @parse = $lastUsedDate =~ m/(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(.*)/;
				   			$lastUsedDate = $parse[0].$parse[1];
				   			$lastUsedDate_parsed = Time::Piece->strptime($lastUsedDate, '%a %b  %d %H:%M:%S %Y');
				   		}
						$worksheet->write($row, 0, $lastUsedDate_parsed->strftime("%Y-%m-%d"));
						$worksheet->write($row, 1, $lastUsedDate_parsed->strftime("%H:%M:%S"));
						$worksheet->write($row, 2, ".A..");
						$worksheet->write($row, 3, "REG");
						$worksheet->write($row, 4, "Registry Key: Office Documents MRU");
						$worksheet->write($row, 5, "File Access Time");
						my $reg_key = $currentuser."\\".$key_path."\\".$word;
						my $description = "FILE:".$data;
						$description =~ s/$lastUsedDate_parsed//g;
						$worksheet->write($row, 6, $description);
						$worksheet->write($row, 7, "[".$reg_key."] ".$description);
						$row++;
					}
				}
				else {
					::rptMsg($key_path.$excel." has no values.");
				}
			}
			else {
				::rptMsg($key_path.$excel." not found.");
			}
			::rptMsg("");
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
					foreach my $u (sort {$a <=> $b} keys %files) {
						my ($val,$data) = split(/:/,$files{$u},2);
						::rptMsg("  ".$val." -> ".$data);
						my $lastUsedDate = $data;
						my @date;
						my $lastUsedDate_parsed;
						if ($lastUsedDate !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
							@date = $lastUsedDate =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
				   			$lastUsedDate_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
				   		} else {
				   			my @parse = $lastUsedDate =~ m/(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(.*)/;
				   			$lastUsedDate = $parse[0].$parse[1];
				   			$lastUsedDate_parsed = Time::Piece->strptime($lastUsedDate, '%a %b  %d %H:%M:%S %Y');
				   		}
						$worksheet->write($row, 0, $lastUsedDate_parsed->strftime("%Y-%m-%d"));
						$worksheet->write($row, 1, $lastUsedDate_parsed->strftime("%H:%M:%S"));
						$worksheet->write($row, 2, ".A..");
						$worksheet->write($row, 3, "REG");
						$worksheet->write($row, 4, "Registry Key: Office Documents MRU");
						$worksheet->write($row, 5, "File Access Time");
						my $reg_key = $currentuser."\\".$key_path."\\".$word;
						my $description = "FILE:".$data;
						$description =~ s/$lastUsedDate_parsed//g;
						$worksheet->write($row, 6, $description);
						$worksheet->write($row, 7, "[".$reg_key."] ".$description);
						$row++;
						$row++;
					}
				}
				else {
					::rptMsg($key_path."\\".$access." has no values.");
				}
			}
			else {
				::rptMsg($key_path."\\".$access." not found.");
			}
			::rptMsg("");
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
					foreach my $u (sort {$a <=> $b} keys %files) {
						my ($val,$data) = split(/:/,$files{$u},2);
						::rptMsg("  ".$val." -> ".$data);
						my $lastUsedDate = $data;
						my @date;
						my $lastUsedDate_parsed;
						if ($lastUsedDate !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
							@date = $lastUsedDate =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
				   			$lastUsedDate_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
				   		} else {
				   			my @parse = $lastUsedDate =~ m/(Mon|Tue|Wed|Thu|Fri|Sat|Sun)(.*)/;
				   			$lastUsedDate = $parse[0].$parse[1];
				   			$lastUsedDate_parsed = Time::Piece->strptime($lastUsedDate, '%a %b  %d %H:%M:%S %Y');
				   		}
						$worksheet->write($row, 0, $lastUsedDate_parsed->strftime("%Y-%m-%d"));
						$worksheet->write($row, 1, $lastUsedDate_parsed->strftime("%H:%M:%S"));
						$worksheet->write($row, 2, ".A..");
						$worksheet->write($row, 3, "REG");
						$worksheet->write($row, 4, "Registry Key: Office Documents MRU");
						$worksheet->write($row, 5, "File Access Time");
						my $reg_key = $currentuser."\\".$key_path."\\".$word;
						my $description = "FILE:".$data;
						$description =~ s/$lastUsedDate_parsed//g;
						$worksheet->write($row, 6, $description);
						$worksheet->write($row, 7, "[".$reg_key."] ".$description);
						$row++;
					}
				}
				else {
					::rptMsg($key_path."\\".$ppt." has no values.");
				}		
			}
			else {
				::rptMsg($key_path."\\".$ppt." not found.");
			}			
		}
		else {
			::rptMsg("Could not access ".$key_path);
			::logMsg("Could not access ".$key_path);
		}
	}
	else {
		::logMsg("MSOffice version not found.");
		::rptMsg("MSOffice version not found.");
	}
}

1;