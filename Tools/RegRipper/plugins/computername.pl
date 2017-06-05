package computername;
use strict;

my %config = (hive          => "System",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20161115);

sub getConfig{return %config}

sub getShortDescr {
	return "Get ComputerName value";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching computername v.".$VERSION);
	::rptMsg("computername v.".$VERSION); # banner
    ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

# Code for System file, getting CurrentControlSet
 my $current;
	my $key_path = 'Select';
	my $key;
	my $ccs;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		$ccs = "ControlSet00".$current;
	}

	$key_path = $ccs."\\Control\\ComputerName\\ComputerName";
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("ComputerName");
		::rptMsg($key_path);
		my @vals = $key->get_list_of_values();
		my $found = 0;
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				if ($v->get_name() eq "ComputerName") {
					::rptMsg("ComputerName = ".$v->get_data());
					$found = 1;
				}
			}
			::rptMsg("ComputerName value not found.") if ($found == 0);
		}
		else {
			::rptMsg($key_path." has no values.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;
