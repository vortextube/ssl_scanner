#!/usr/bin/perl
# sslv3_scanner.pl
# Version 1.0

# Copyright 2014 Charles R. Hill <hill.charles.robert@gmail.com> 

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;
use constant DEBUG              => 1;
use constant TIMEOUT            => 5;
use constant DEFAULT_DELIMITER  => ',';
use constant DEFAULT_OPENSSL    => 'openssl';
use Getopt::Long;

# make unbuffered for timely output to screen
select STDOUT; $| = 1;  

#sub prototypes
sub check_for_net_ip(); 
sub main(); 
sub usage();

# command line options
my $protocols   = ['ssl3']; #
#$my $protocols = ['ssl2', 'ssl3', 'tls1', 'tls1_1', 'tls1_2'];
my $openssl     = '';
my $delimeter   = '';
my $outfile     = '';
my $hostfile    = '';;
my $host        = '';
my $timeout     = '';
my $help        = '';

# Provide usage if requested then stop.
if ($help) {
    usage();
    exit(0);
}

check_for_net_ip();


main();
    
sub main() {

    my $hosts           = [];

    # command line variables
    $delimeter   = '';
    $outfile     = '';
    $hostfile    = '';;
    $openssl     = '';
    $host        = '';
    $timeout     = '';

    GetOptions ('delimter:s'  => \$delimeter,
                'outfile:s'   => \$outfile,
                'hostfile:s'  => \$hostfile,
                'openssl:s'   => \$openssl,
                'host:s'      => \$host,
                'timeout:i'   => \$timeout);

    # validate command line parameters
    # set the delimeter to what is passed, otherwise the default
    if ($delimeter eq '') {
        $delimeter = DEFAULT_DELIMITER;
    }
    
    # set openssl to what is passed, otherwise the default
    if ($openssl eq '') {
        $openssl = DEFAULT_OPENSSL;
    }

    if ($outfile ne '') {
        if ($outfile =~ /[A-Za-z0-9_\-.]/) {
            #outfile OK
        } else {
            warn "Outfile may only contain the letters numbers dashes underscores and periods. (A-Z a-z 0-9 _ . - ) \n\n";
            usage();
            exit(0);
        }
    } else {
        #out to stdout only
    }

    print "hostfile = $hostfile \n";
    print "host = $host \n";
    
    if ($hostfile ne '' and $host ne '') {
        warn "Please specify a hostfile or a host but not both.\n\n";
        usage();
        exit(0);
    }
    
    if ($hostfile eq '' and $host eq '') {
        warn "Please specify at least one of the parameters 'host' or 'hostfile'.\n\n";
        usage();
        exit(0);
    }
    
    if ($hostfile ne '') { 
        my $host_cidr_list = read_host_cidr_file($hostfile);
        $hosts = expand_host_cidr_list($host_cidr_list);
    }
    
    if ($host ne '') {
        $hosts = expand_host_cidr_list([$host]);
    }

    test_hosts($hosts);
    
}


sub expand_host_cidr_list() {
    my ($hosts) = @_;
    my $expanded_hosts = [];
    
    #read the host file line by line and add the host or if its a CIDR add all of the hosts
    foreach my $host (@$hosts) {
        #make sure its a host or an address or address range we can expand
        if ($host =~ /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/) {
            #add host to list
            push @$expanded_hosts, $host;
        } else {
            #print cidr ??  ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$";
            
            #add ip or ip range to list
            my $ip = new Net::IP ($host) || die;
            do {
                my $expanded_host = $ip->ip();
                push @$expanded_hosts, $expanded_host;
            } while (++$ip);
 
        }
    }
    
    return $expanded_hosts;
}
        

    
sub test_hosts() {

    my ($hosts) = @_;
    
    foreach my $host (@$hosts) {

        foreach my $protocol (@$protocols) {
            print "Testing $host for $protocol ... "; 
            
            my $test_result = -1;
            my $test_command_result;
            
            my $test_command = 'echo "" | ' . $openssl . ' s_client -' . $protocol . ' -connect ' . $host . ':443 2>&1';
            #warn "Test command = $test_command \n" if DEBUG;
            
            eval {
                local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
                alarm TIMEOUT;

                $test_command_result = `$test_command`;
                #warn "Test command result = $test_command_result \n" if DEBUG;
            
                alarm 0;
            };
            
            if ($@) {
                die unless $@ eq "alarm\n";   # propagate unexpected errors
                $test_command_result = '';
                print " unknown, timeout.\n";
            }

            if ($test_command_result =~ /CONNECTED/) {
                if ($test_command_result =~ /ssl handshake failure/) {
                    $test_result = 0;
                    print "unsupported. \n";
                } else {
                    $test_result = 1;
                    print "supported. \n";
                }
            }
            
            if ($outfile ne '') {
                open OUTFILE, ">$outfile" or die "error opening $outfile: $!";
                print OUTFILE "$host$delimeter$protocol$delimeter$test_result\n";
                close OUTFILE;
            }
        }
    }
    
}

sub read_host_cidr_file {
    my $hostfile = @_;

    my $hosts_and_cidrs = [];
    
    open my $fh, '<', $hostfile or die "error opening $hostfile: $!";

    #read the host file line by line and add the host or if its a CIDR add all of the hosts
    while (my $host = <$fh>) {
        push @$hosts_and_cidrs, $host;
    }
    return $hosts_and_cidrs;
    
}


# Net::IP is required for address range expansion
# it is not included with the base perl and may
# not be installed.  If it isn't the user is
# advised how to install.
sub check_for_net_ip () {
    my $check = eval {
        require Net::IP;
        1;
    };

    if($check) {
        # OK Net:IP installed
    } else {
        # Not OK: advise on how to install
        print "This script requires the perl module Net::IP be installed.\n";
        print "It can be installed at root with the following command: \n";
        print "perl -MCPAN -e 'install Net::IP' \n";
        #yum install perl-Net-IP
        exit(0);
    }

}

sub usage() {
    print qq[
This script tests for SSLv3 on remote hosts.  It attempts to connection using
the 'openssl s_client' command.  If successful it reports back its findings.

It requires openssl, perl, and Net::Ip.

If you do not have Net::Ip installed you can get it in several ways.
    The perish way:

    On RPM based systems like RedHat/Fedora/CentOS:
    
    On deb based systems like Ubuntu:

Options:

    Specifying the target hosts
    ============================================
    -host - The hostname, IP address, or CIDR to be scanned.  If provided the
            'hostfile' parameter must not be passed.
    
        e.g.
        ./sslv3_scanner.pl -host=www.yahoo.com
        
        ./sslv3_scanner.pl -host=98.136.183.24
        
        ./sslv3_scanner.pl -host=98.136.183.0/30
    
    -hostfile - A file containing hostnames, IP Addresses, or CIDRs to be
                scanned.  If provided the 'host' parameter must not be passed.
                
    One of either parameters,-host or -hostfile, must be passed.
    
    Getting result into a file
    ============================================
    -outfile - This optional parameter specifies the name of a file to be
               written containing the results of the scan.
               
        The outfile format is:
            <hostname>,<protocol>,<support flag>
            
        Where support flag is one of the following:
            -1 - Unknown, connect timeout or otherwise indeterminate.
             0 - Unsupported.
             1 - Supported.
    
    Other
    ============================================
    -timeout - This optional parameter specifies a timeout in second to wait
               for a sucessful connection. The default value of this parameter
               is 5 seconds.
    
    -openssl - This script requires openssl and expects to find it in the path.
               If openssl is not in the path it can be specified 

    ];
    
}