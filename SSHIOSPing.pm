package Smokeping::probes::SSHIOSPing;

=head1 301 Moved Permanently

This is a Smokeping probe module. Please use the command 

C<smokeping -man Smokeping::probes::skel>

to view the documentation or the command

C<smokeping -makepod Smokeping::probes::skel>

to generate the POD document.

=cut

use Data::Dumper;
use Sys::Syslog qw(:standard :macros);
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

		debugLevel => { 
			_doc => "syslog logging level [0-7]",
			_example => '3',
			_sub => sub { 
				my $val = shift;
                return "ERROR: syslog level must be between 0 and 7" unless ( $val =~ /^[0-7]$/ );
				return undef;
			},
		},

	});

}

# Here's the place for target-specific variables

sub targetvars {
	my $class = shift;
	return $class->_makevars($class->SUPER::probevars, {
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

		iosHost => { 
			_doc => "Your IOS device",
			_example => 'my-router.some.domain',
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

		packetSize => { 
			_doc => "ICMP packet size",
			_example => '200',
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
	});

};

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

# Configuração a obter do ficheiro do smokeping
# Variáveis de probe
    my $binary       = $self->{properties}{binary};
    my $debugLevel   = $self->{properties}{debugLevel};
    my $ping_timeout = $self->{properties}{ping_timeout};
    my $packetSize   = $target->{properties}{packetSize};

# Variáveis de target
    my $enable_secret = $target->{vars}{enable_secret};
    my $user          = $target->{vars}{user};
    my $password      = $target->{vars}{password};
    my $iosHost       = $target->{vars}{iosHost};
    my $repeats       = $target->{vars}{repeats};
    my $psource       = $target->{vars}{psource};
    my $host          = $target->{vars}{host};

# initialize syslog functionality
    my $debug = _setLogLevel( $debugLevel ) and openlog(  "SSHIOSPing", "ndelay", "user");


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

    my %pingOptions = (
        "timeout" => $ping_timeout,
        "source" => $psource,
        "repeat" => "1",
        "size" => $packetSize
    );

    my $pingCommand = _buildPingCommand( $host, %pingOptions );
    my @pingValues = ();
    _syslog( $debug, LOG_INFO, "Returned Ping Command: $pingCommand" );

    _syslog( $debug, LOG_INFO, "Connecting to $iosHost" );
    my $session = Net::SSH2::Cisco->new();
    # Não queremos que uma ligação falhada mande o script todo abaixo:
    $session->errmode( 'return' );
    $session->timeout( 20 );
    my $host_session = $session->connect( $iosHost ) or _syslog( $debug, LOG_ERR, "failed to connect to $iosHost" );

    $session->login( $user, $password );

    _syslog( $debug, LOG_INFO, "Trying to reach exec mode" );
    if ( ! $session->is_enabled() and $enable_secret ) {
        $session->enable( $enable_secret ) or _syslog( $debug, LOG_ERR, "Could not reach exec mode to run ping command" ) and return undef;
    } elsif ( ! $session->is_enabled() ) {
        _syslog( $debug, LOG_ERR, "User \"$user\" requires Exec mode to run ping command properly" ) and return undef;
    };

    #$session->input_log('/root/admin_sandbox/perl.log');

    _syslog( $debug, LOG_INFO, "Running command : \"$pingCommand\" on $iosHost");

    # run $repeats ping commands, smokeping will perform all statistical computations
    for my $count ( 1 .. $repeats ) {
        my @output = $session->cmd( $pingCommand ) or _syslog( $debug, LOG_ERR, "Could not run command" );

        #print @output;

        my $result = _parsePingCommand( $iosHost, @output ) or _syslog( $debug, LOG_ERR, "Could not validate ping command output on host $iosHost") ;

        if ( $result ) {

            #print "Got $result for ping number $count\n";
            push @pingValues, $result if $result;

        } else {
            #print "Correu mal\n";
            next;
        }

        #print Dumper( \%result );

    };

    _syslog( $debug, LOG_INFO, "For host $iosHost I got: " . scalar @pingValues . " out of $repeats\n") ;

    _syslog( $debug, LOG_INFO, "Closing connection to $iosHost");
    $session->close;

    #return @times;

    return "@pingValues";
}

# That's all, folks!

sub _buildPingCommand {

    my $_host = shift ;
    my %_pingOptions = @_ ;

    #print "HOST : $_host\n";
    #print Dumper ( %_pingOptions );
    #print "I AM HERE\n";
    _syslog( $Smokeping::probes::SSHIOSPing::debug, LOG_INFO, "AAAAAAAAAAAAA " . scalar %_pingOptions) ;
    #while ( my ( $_key, $_value ) = each ( %_pingOptions ) ) {
    #    print "$_key : $_value\n";
    #};
    #print "OPTIONS @_pingOptions\n";

    my @pingCommand = ( 'ping', $_host ) ;
    while (my ( $param, $value ) = each %_pingOptions ) {
        #if ( ! $param ) {
        #    print "PARAM NOT THERE\n";
        #};
        #print "PARAM : $param\n";
        if ( $value ) {
            push @pingCommand, $param, $value;
        }
    }
    my $result = join(' ', @pingCommand );
    _syslog( $Smokeping::probes::SSHIOSPing::debug, LOG_INFO, "ping Command: $result") ;
    return join(' ', @pingCommand );
};

sub _syslog {
    my ( $_debug, $_logLevel, $_message ) = @_;

#    print "DEBUGSUB : $_debug\n";
#    print "LOGLEVELSUB : $_logLevel\n";
#    print "LOG : $_message\n";

    syslog( $_logLevel, $_message) if ( $_debug ) ;
    return 1;
};

sub _parsePingCommand {

    local $" = "";

    my $_host = shift;
    my @pingOutput = @_;
    my @infoLine ;
    my $successTest = '^success rate is 100 percent';
    my $pattern = '/(\d+) (\w+)$';

# se não conseguirmos validar a linha das informações vamos terminar a função
    @infoLine = grep {/^Success/} @pingOutput ;
    if ( ! @infoLine ) {
        _syslog( $Smokeping::probes::SSHIOSPing::debug, LOG_ERR, "Could not validate ping command output on host $_host") ;
        return ();
    };

    my $line = "@infoLine";
#squeeze all spaces
    $line =~ s/\s+/ /g;
#trim
    $line =~ s/^\s+|\s+$//g;
    $line = lc $line;

    _syslog( $Smokeping::probes::SSHIOSPing::debug, LOG_INFO, "Matched information line: $line" );

    $line =~ m|$successTest| or _syslog( $Smokeping::probes::SSHIOSPing::debug, LOG_ERR, "Metrics pattern was not matched") and return ();

    my ( $time, $unit ) = ( $line =~ m|$pattern| ) or _syslog( $Smokeping::probes::SSHIOSPing::debug, LOG_ERR, "Could not get time and units") and return ();

    _syslog( $Smokeping::probes::SSHIOSPing::debug, LOG_INFO, "Ping RTT time: $time $unit" ) ;

    return $time;
};

sub _setLogLevel( $ ) {

    my $_debugLevel = shift;
    #print "THIS: $debugLevel\n";

    return undef unless ( $_debugLevel =~ /[0-7]/ ) ;

    my %maskMap = (
        "0" => LOG_EMERG,
        "1" => LOG_ALERT,
        "2" => LOG_CRIT,
        "3" => LOG_ERR,
        "4" => LOG_WARNING,
        "5" => LOG_NOTICE,
        "6" => LOG_INFO,
        "7" => LOG_DEBUG
    );

    for my $num ( 0 .. 7 ) {
        if ( $num == $_debugLevel ) {
            #print "DEBUGLEVEL : $num\n";
            setlogmask( LOG_UPTO ( $maskMap{ $num } ) );
            return 1 ;
        };
    };

    return 0 ;
};

1;
