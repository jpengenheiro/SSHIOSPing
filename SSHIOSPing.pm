package Smokeping::probes::skel;

=head1 301 Moved Permanently

This is a Smokeping probe module. Please use the command 

C<smokeping -man Smokeping::probes::skel>

to view the documentation or the command

C<smokeping -makepod Smokeping::probes::skel>

to generate the POD document.

=cut

use strict;
use warnings;
use Net::SSH2::Cisco;
use base qw(Smokeping::probes::basefork); 
# or, alternatively
# use base qw(Smokeping::probes::base);
use Carp;

sub pod_hash {
	return {
		name => <<DOC,
Smokeping::probes::SSHIOSPing - A Probe that runs on SSH for Cisco devices
DOC
		description => <<DOC,
This probe connects to Cisco IOS devices and runs ping commands to arbitrary hosts
using the SSH protocol with password authentication.
DOC
		authors => <<'DOC',
 João Silva <joao.miranda.silva@pt.clara.net>,
DOC
		see_also => <<DOC
L<smokeping_extend>
DOC
	};
}

sub new($$$)
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);

    # no need for this if we run as a cgi
    unless ( $ENV{SERVER_SOFTWARE} ) {
    	# if you have to test the program output
	# or something like that, do it here
	# and bail out if necessary
    };

    return $self;
}

# This is where you should declare your probe-specific variables.
# The example shows the common case of checking the availability of
# the specified binary.

sub probevars {
	my $class = shift;

	return $class->_makevars($class->SUPER::probevars, {
		_mandatory => [ 'binary' ],

		binary => { 
			_doc => "The location of your ssh client.",
			_example => '/usr/bin/ssh',
			_sub => sub { 
				my $val = shift;
                return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
				return undef;
			},
		},

		ping_timeout => { 
			_doc => "ping command timeout in seconds",
			_example => '20',
			_sub => sub { 
				my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
				return undef;
			},
		},

		packet_size => { 
			_doc => "ICMP packet size",
			_example => '200',
			_sub => sub { 
				my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
				return undef;
			},
		},

	});

}

# Here's the place for target-specific variables

sub targetvars {
	my $class = shift;
		_mandatory => [ 'user', 'password', 'enable_secret' ],

		user => { 
			_doc => "Your IOS username",
			_example => 'johnny.b.good',
			_sub => sub { 
				my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
				return undef;
			},
		},

		password => { 
			_doc => "Your IOS user's password",
			_example => 'supergroovalisticprosifunkstication',
			_sub => sub { 
				my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
				return undef;
			},
		},

		enable_secret => { 
			_doc => "Your device's enable password to access exec mode",
			_example => 'supergroovalisticprosifunkstication',
			_sub => sub { 
				my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
				return undef;
			},
		},

		repeats => { 
			_doc => "how many pings",
			_example => 'supergroovalisticprosifunkstication',
			_sub => sub { 
				my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
				return undef;
			},
		},

		source => { 
			_doc => "ping source interface",
			_example => '10.10.10.10',
			_sub => sub { 
				my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
				return undef;
			},
		},

}

sub ProbeDesc($){
    my $self = shift;
    return "pingpong points";
}

# this is where the actual stuff happens
# you can access the probe-specific variables
# via the $self->{properties} hash and the
# target-specific variables via $target->{vars}

# If you based your class on 'Smokeping::probes::base',
# you'd have to provide a "ping" method instead
# of "pingone"

sub pingone ($){
    my $self = shift;
    my $target = shift;

    # my $binary = $self->{properties}{binary};
    # my $weight = $target->{vars}{weight}
    # my $count = $self->pings($target); # the number of pings for this targets

    # ping one target

    # execute a command and parse its output
    # you should return a sorted array of the measured latency times
    # it could go something like this:

    my @times;

    #for (1..$count) {
    #        open(P, "$cmd 2>&1 |") or croak("fork: $!");
    #        while (<P>) {
    #                /time: (\d+\.\d+)/ and push @times, $1;
    #        }
    #        close P;
    #}


    return @times;
}

# That's all, folks!

1;
