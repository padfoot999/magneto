#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# userassist.pl
# Plugin for Registry Ripper, NTUSER.DAT edition - gets the 
# UserAssist values 
#
# Change history
#  20130603 - added alert functionality
#  20100322 - Added CLSID list reference
#  20100308 - created, based on original userassist.pl plugin
#  
# References
#  Control Panel Applets - http://support.microsoft.com/kb/313808
#  CLSIDs - http://www.autohotkey.com/docs/misc/CLSID-List.htm
# 
# copyright 2010 Quantum Analytics Research, LLC
#-----------------------------------------------------------
package userassist;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20130603);

my @paths = ("recycle","globalroot","temp","system volume information","appdata",
	              "application data");

my @alerts = ();

sub getConfig{return %config}
sub getShortDescr {
	return "Displays contents of UserAssist subkeys";	
}
sub getDescr{}
sub getRefs {"Description of Control Panel Files in XP" => "http://support.microsoft.com/kb/313808"}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching userassist2 v.".$VERSION);
	::rptMsg("shutdowncount v.".$VERSION); # banner
    ::rptMsg("(".getHive().") ".getShortDescr()); # banner
    ::rptMsg('//List all applications launched using the Windows GUI, aka  frequently used application list!');
    ::rptMsg('//List Run time, Run Count, Focus Time, Focus Counter');
    ::rptMsg('//This can be used to map a unique way someone launches an app or opens a file!'."\n");
    ::rptMsg('//Note:');
	::rptMsg('//ProgramFilesx64 - 6D809377-6AF0-444B-8957-A3773F02200E');
	::rptMsg('//ProgramFilesx86 - 7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E');
	::rptMsg('//System32 - 1AC14E77-02E7-4E5D-B744-2EB1AE5198B7');
	::rptMsg('//Systemx86 - D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27');
	::rptMsg('//Desktop - B4BFCC3A-DB2C-424C-B029-7FE99A87C641');
	::rptMsg('//Documents - FDD39AD0-238F-46AF-ADB4-6C85480369C7');
	::rptMsg('//Downloads - 374DE290-123F-4565-9164-39C4925E467B');
	::rptMsg('/C:\Users - 0762D272-C50A-4BB0-A382-697DCD729B80');
	::rptMsg('//Charmbar - BCB48336-4DDD-48FF-BB0B-D3190DACB3E2');
	::rptMsg('//Charmbar keeps track of (1) time an item was searched and (2) the number of times it was searched'."\n");
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	
	my $key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";              
	my $key;
	
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("UserAssist");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				::rptMsg($s->get_name());
				processKey($s);
				::rptMsg("");
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

sub processKey {
	my $ua = shift;
	my $row = shift;
	
	my $key = $ua->get_subkey("Count");

	my %ua;
	my $hrzr = "HRZR";
	
	my @vals = $key->get_list_of_values();
	if (scalar(@vals) > 0) {
		foreach my $v (@vals) {
			my $value_name = $v->get_name();
			my $data = $v->get_data();

# Windows XP/2003/Vista/2008
			if (length($data) == 16) {
				my ($session,$count,$val1,$val2) = unpack("V*",$data);
			 	if ($val2 != 0) {
					my $time_value = ::getTime($val1,$val2);
					if ($value_name =~ m/^$hrzr/) { 
						$value_name =~ tr/N-ZA-Mn-za-m/A-Za-z/;
					}
					$count -= 5 if ($count > 5);
					push(@{$ua{$time_value}},$value_name." (".$count.")");
				}
			}
# Windows 7				
			elsif (length($data) == 72) { 
				$value_name =~ tr/N-ZA-Mn-za-m/A-Za-z/;
#				if (unpack("V",substr($data,0,4)) == 0) {	
#					my $count = unpack("V",substr($data,4,4));
#					my @t = unpack("VV",substr($data,60,8));
#					next if ($t[0] == 0 && $t[1] == 0);
#					my $time_val = ::getTime($t[0],$t[1]);	
#					print "    .-> ".$time_val."\n";
#					push(@{$ua{$time_val}},$value_name." (".$count.")");
#				}
				my $count = unpack("V",substr($data,4,4));
				my @t = unpack("VV",substr($data,60,8));
				next if ($t[0] == 0 && $t[1] == 0);
				my $time_val = ::getTime($t[0],$t[1]);	
				push(@{$ua{$time_val}},$value_name." (".$count.")");
			}
			else {
# Nothing else to do
			}
		}
		foreach my $t (reverse sort {$a <=> $b} keys %ua) {
			::rptMsg(gmtime($t)." Z");
			foreach my $i (@{$ua{$t}}) {
				::rptMsg("  ".$i);
				
				my $lci = lc($i);
				foreach my $a (@paths) {
					push(@alerts,"ALERT: userassist: ".$a." found in path: ".$i) if (grep(/$a/,$lci));
				}
				
			}
		}
	}
	
	if (scalar(@alerts) > 0) {
		print "\n";
		print "Alerts:\n";
		foreach (@alerts) {
			::alertMsg($_);
		}
	}
}
1;