How to compile Perl Script to EXE executable:
1. Install Strawberry Perl from perl2exe
2. Install all necessary packages using cpan client (i.e. XLSX::Writer)
3. Install pp (follow: http://stackoverflow.com/questions/15925992/perl-install-parpacker-problems if there are problems)
4. Modify rip.pl to include following 
my $data_dir = "$ENV{PAR_TEMP}/inc";

my $plugindir = "$data_dir/script";
5. pp -M modules -a .\plugins -o <output file> <perl file>