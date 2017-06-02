package usbportabledevices;
use strict;

my %config = (hive          => "Software",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20141111);

sub getConfig{return %config}

sub getShortDescr {
	return "Get Volume Name mapped to USB from Windows Portable Devices";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching usbportabledevices v.".$VERSION);
	::rptMsg("usbportabledevices v.".$VERSION); # banner
  	::rptMsg("(".getHive().") ".getShortDescr()); # banner
  	::rptMsg("//Identify volume name mapped to the USB"."\n");
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\Windows Portable Devices\\Devices";
	if (my $key = $root_key->get_subkey($key_path)) {
		::rptMsg("USBPortableDevices");
		::rptMsg($key_path);
		::rptMsg("");
		
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				::rptMsg($s->get_name()." [".gmtime($s->get_timestamp())."]");
				::rptMsg($s->get_value("FriendlyName")->get_data());
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
1;
