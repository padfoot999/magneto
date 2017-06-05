package softwarerun;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 1,
              hasRefs       => 1,
              osmask        => 22,
              category      => "malware",
              version       => 20131009);
my $VERSION = getVersion();

# Functions #
sub getConfig {return %config}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
sub getDescr {}
sub getShortDescr {
	return "Get Autostart Programs from NTUSER";
}
sub getRefs {}

sub pluginmain {
	my $class = shift;
	my $hive = shift;

	# Initialize #
	::logMsg("Launching softwarerun v.".$VERSION);
  ::rptMsg("softwarerun v.".$VERSION); 
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n");     
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key;
	my $count = 0;
	
	my @paths = ("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
	             "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
	
	foreach my $key_path (@paths) {
		if ($key = $root_key->get_subkey($key_path)) {
			my @vals = $key->get_list_of_values();
			if (scalar @vals > 0) {
				foreach my $v (@vals) {
					my $name = $v->get_name();
					my $data = $v->get_data();
					::rptMsg($name." = ".$data);
				}
			}
		}
		else {
			::rptMsg($key_path." not found.");
		}
	}
}

1;
