#-----------------------------------------------------------
# usbstor
#
# History:
#   20141111 - updated check for key LastWrite times
#		20141015 - added subkey LastWrite times
#   20130630 - added FirstInstallDate, InstallDate query
#   20080418 - created
#
# Ref:
#   http://studioshorts.com/blog/2012/10/windows-8-device-property-ids-device-enumeration-pnpobject/
#
# copyright 2014 QAR, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package usbmounted;
use strict;

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
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching usbvol v.".$VERSION);
	::rptMsg("usbvol v.".$VERSION); # banner
  	::rptMsg("(".getHive().") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key_path = "MountedDevices";
	if (my $key = $root_key->get_subkey($key_path)) {
		::rptMsg("USBVol");
		::rptMsg($key_path);
		::rptMsg("");
		my @data = $key->get_list_of_values();
		foreach my $d (@data) {
			::rptMsg($d->get_name());
			my $data = $d->get_data();
			$data =~ s/\x00//g;
			::rptMsg($data);
			::rptMsg("");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;
