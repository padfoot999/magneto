package officemru;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20080324);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of user's Office doc MRU keys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching officemru v.".$VERSION);
	::rptMsg("officemru v.".$VERSION); # banner
    ::rptMsg("(".getHive().") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	::rptMsg("officemru v.".$VERSION);
# First, let's find out which version of Office is installed
	my $version;
	my $tag = 0;
	my @versions = ("15\.0");
	foreach my $ver (@versions) {
		my $key_path = "Software\\Microsoft\\Office\\".$ver."\\Common\\Open Find";
		if (defined($root_key->get_subkey($key_path))) {
			$version = $ver;
			$tag = 1;
		}
	}
	
	if ($tag) {
		::rptMsg("MSOffice version ".$version." located.");
		my $key_path = "Software\\Microsoft\\Office\\".$version;	                 
		my $of_key = $root_key->get_subkey($key_path);
		if ($of_key) {
# Attempt to retrieve Word docs			
			my $word = "Word\\File MRU";
			my $word_key = $of_key->get_subkey($word);
			if ($word_key) {
				::rptMsg($word);
				::rptMsg("LastWrite Time ".gmtime($word_key->get_timestamp())." (UTC)");
				::rptMsg("");
				my @vals = $word_key->get_list_of_values();
				if (scalar(@vals) > 0) {
					foreach my $v (@vals) { 
						my $name = $v->get_name();
						my $data = (split(/\*/,$v->get_data()))[1];
						::rptMsg($name." = ".$data);
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
					foreach my $v (@vals) {
						my $name = $v->get_name();
						my $data = (split(/\*/,$v->get_data()))[1];
						::rptMsg($name." = ".$data);
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
# Attempt to retrieve PowerPoint docs			
			my $ppt = 'PowerPoint\\File MRU';
			if (my $ppt_key = $of_key->get_subkey($ppt)) {
				::rptMsg($key_path."\\".$ppt);
				::rptMsg("LastWrite Time ".gmtime($ppt_key->get_timestamp())." (UTC)");
				my @vals = $ppt_key->get_list_of_values();
				if (scalar(@vals) > 0) {
					foreach my $v (@vals) {
						my $name = $v->get_name();
						my $data = (split(/\*/,$v->get_data()))[1];
						::rptMsg($name." = ".$data);
					}
				}
				else {
					::rptMsg($key_path.$excel." has no values.");
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