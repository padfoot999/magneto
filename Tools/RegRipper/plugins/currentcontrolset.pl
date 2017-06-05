package currentcontrolset;
use strict;

my %config = (hive          => "System",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20090727);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets Current Control Set information";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching currentcontrolset v.".$VERSION);
	::rptMsg("currentcontrolset v.".$VERSION); # banner
    ::rptMsg("(".$config{hive}.") ".getShortDescr()); # banner
    ::rptMsg('//If Current shows 0x1, we should examine ControlSet001');
	::rptMsg('//If Last Known Good shows 0x2, it means that is the snapshot of the registry during the last successful boot'."\n");
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
# First thing to do is get the ControlSet00x marked current...this is
# going to be used over and over again in plugins that access the system
# file
	my ($current,$lastknown);
	my $key_path = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		::rptMsg("Current    = ".$current);
		$lastknown = $key->get_value("LastKnownGood")->get_data();
		::rptMsg("Last Known Good    = ".$lastknown);
	}
	else {
		::rptMsg($key_path." not found.");
		::logMsg($key_path." not found.");
	}
}

1;