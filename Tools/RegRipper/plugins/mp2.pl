#-----------------------------------------------------------
# mp2.pl
# Plugin for Registry Ripper,
# MountPoints2 key parser
#
# Change history
#   20120330 - updated to include parsing of UUID v1 GUIDs to get unique
#              MAC addresses
#   20091116 - updated output/sorting; added getting 
#              _LabelFromReg value
#   20090115 - Removed printing of "volumes"
#
# References
#   http://support.microsoft.com/kb/932463
# 
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey
#-----------------------------------------------------------
package mp2;
use strict;
use Excel::Writer::XLSX;
use Time::Piece;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20120330);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets user's MountPoints2 key contents";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching mp2 v.".$VERSION);
	::rptMsg("mp2 v.".$VERSION); # banner
    ::rptMsg("(".getHive().") ".getShortDescr()."\n"); # banner
	my %drives;
	my %volumes;
	my %remote;
	my %macs;
	
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("MountPoints2");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				my $name = $s->get_name();
				if ($name =~ m/^{/) {
					my $label;
					eval {
						$label = $s->get_value("_LabelFromReg")->get_data();
					};
					
					my $m = (split(/-/,$name,5))[4];
					$m =~ s/}$//;
					$m = uc($m);
					$m = join(':',unpack("(A2)*",$m));
					$macs{$m} = 1;

					$name = $name." (".$label.")" unless ($@);
					
					push(@{$volumes{$s->get_timestamp()}},$name);
				}
				elsif ($name =~ m/^[A-Z]/) {
					push(@{$drives{$s->get_timestamp()}},$name);
				}
				elsif ($name =~ m/^#/) {
					push(@{$remote{$s->get_timestamp()}},$name);
				}
				else {
					::rptMsg("  Key name = ".$name);
				}
			}

			eval {
				my $workbook_name = $ntuser;
				$workbook_name =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$1Timeline-MountPoints2-$3.xlsx/g;
				my $workbook = Excel::Writer::XLSX->new($workbook_name);
				my $worksheet = $workbook->add_worksheet();
				my $row = 0;

				::rptMsg("");
				::rptMsg("Remote Drives:");
				foreach my $t (reverse sort {$a <=> $b} keys %remote) {
					::rptMsg(gmtime($t)." (UTC)");
					my $lastwritten = gmtime($t);
					if ($lastwritten !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
						my @date = $lastwritten =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
			   			$modtime_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
			   		} else {
			   			my @parse = $lastwritten =~ m/(Mon|Tue|Wed|Thu|Fri)(.*)/;
			   			$lastwritten = $parse[0].$parse[1];
			   			$modtime_parsed = Time::Piece->strptime($lastwritten, '%a %b  %d %H:%M:%S %Y');
			   		}
					foreach my $item (@{$remote{$t}}) {
						::rptMsg("  $item");
						$worksheet->write($row, 0, $modtime_parsed->strftime("%Y-%m-%d"));
						$worksheet->write($row, 1, $modtime_parsed->strftime("%H:%M:%S"));
						$worksheet->write($row, 2, "REG");
						$worksheet->write($row, 3, "Registry Last Written Time");
						my $reg_key = $ntuser;
						$reg_key =~ s/(.*\\)([^\\]*)_(USER_[^\\]*).dat$/$2_$3/g;
						$reg_key .= "\\".$key_path;
						$worksheet->write($row, 4, $reg_key);
						my $description = "REMOTE DRIVES:".$item;
						$worksheet->write($row, 5, $description);
						$row++;
					}
				}
				
				::rptMsg("");
				::rptMsg("Volumes:");
				foreach my $t (reverse sort {$a <=> $b} keys %volumes) {
					::rptMsg(gmtime($t)." (UTC)");
					my $lastwritten = gmtime($t);
					if ($lastwritten !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
						my @date = $lastwritten =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
			   			$modtime_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
			   		} else {
			   			my @parse = $lastwritten =~ m/(Mon|Tue|Wed|Thu|Fri)(.*)/;
			   			$lastwritten = $parse[0].$parse[1];
			   			$modtime_parsed = Time::Piece->strptime($lastwritten, '%a %b  %d %H:%M:%S %Y');
			   		}
					foreach my $item (@{$volumes{$t}}) {
						::rptMsg("  $item");
						$worksheet->write($row, 0, $modtime_parsed->strftime("%Y-%m-%d"));
						$worksheet->write($row, 1, $modtime_parsed->strftime("%H:%M:%S"));
						$worksheet->write($row, 2, "REG");
						$worksheet->write($row, 3, "Registry Last Written Time");
						my $reg_key = "HKEY_LOCAL_MACHINE\\".$key_path;
						$worksheet->write($row, 4, $reg_key);
						my $description = "VOLUME:".$item;
						$worksheet->write($row, 5, $description);
						$row++;
					}
				}
				::rptMsg("");
				::rptMsg("Drives:");
				foreach my $t (reverse sort {$a <=> $b} keys %drives) {
					my $d = join(',',(@{$drives{$t}}));
					::rptMsg(gmtime($t)." (UTC) - ".$d);
					my $lastwritten = gmtime($t);
					if ($lastwritten !~ m/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {2,}/) {
						my @date = $lastwritten =~ $RE{time}{strftime}{-pat => '%a %b %d %H:%M:%S %Y'}{-keep};
			   			$modtime_parsed = Time::Piece->strptime($date[0], '%a %b %d %H:%M:%S %Y');
			   		} else {
			   			my @parse = $lastwritten =~ m/(Mon|Tue|Wed|Thu|Fri)(.*)/;
			   			$lastwritten = $parse[0].$parse[1];
			   			$modtime_parsed = Time::Piece->strptime($lastwritten, '%a %b  %d %H:%M:%S %Y');
			   		}
					$worksheet->write($row, 0, $modtime_parsed->strftime("%Y-%m-%d"));
					$worksheet->write($row, 1, $modtime_parsed->strftime("%H:%M:%S"));
					$worksheet->write($row, 2, "REG");
					$worksheet->write($row, 3, "Registry Last Written Time");
					my $reg_key = "HKEY_LOCAL_MACHINE\\".$key_path;
					$worksheet->write($row, 4, $reg_key);
					my $description = "DRIVES:".$d;
					$worksheet->write($row, 5, $description);
					$row++;
				}
				::rptMsg("");
				::rptMsg("Unique MAC Addresses:");
				foreach (keys %macs) {
					::rptMsg($_);
				}
			
				::rptMsg("");
				::rptMsg("Analysis Tip: Correlate the Volume entries to those found in the MountedDevices");
				::rptMsg("entries that begin with \"\\??\\Volume\"\.");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;