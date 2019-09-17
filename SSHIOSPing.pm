package Smokeping::probes::SSHIOSPing;

=head1 301 Moved Permanently

This is a Smokeping probe module. Please use the command 

C<smokeping -man Smokeping::probes::SSHIOSPing>

to view the documentation or the command

C<smokeping -makepod Smokeping::probes::SSHIOSPing>

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

binmode(STDOUT, ":encoding(utf8)");

sub pod_hash {
    return {
        name => <<DOC,
Smokeping::probes::SSHIOSPing - A ping latency Probe that runs on SSH for Cisco devices
DOC
        description => <<DOC,
This probe connects to Cisco IOS devices and runs ping commands to arbitrary hosts
using the SSH protocol with password authentication.
Has basic syslog functionality for debug.
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

        ping_timeout => { 
            _doc => "ping command timeout in seconds defaults to 1 second.",
            _example => '20',
            _sub => sub { 
                my $val = shift;
                return "ERROR: Ping command timeout must be positive integer." unless $val =~ /^[1-9][0-9]*$/;
                return undef;
            },
        },

        debug_level => { 
            _doc => "syslog logging level [0-7], defaults to LOG_ERR (3).",
            _example => '3',
            _sub => sub { 
                my $val = shift;
                return "ERROR: debug level must be between 0 and 7 according to syslog standards." unless ( $val =~ /^[0-7]$/ );
                return undef;
            },
        },

    });

}

# Here's the place for target-specific variables

sub targetvars {
    my $class = shift;
    return $class->_makevars($class->SUPER::probevars, {
        _mandatory => [ 'user', 'password', 'enable_secret', 'ios_host' ],

        user => { 
            _doc => "Your IOS username.",
            _example => 'johnny.b.good',
            _sub => sub { 
                my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
                return undef;
            },
        },

        password => { 
            _doc => "Your IOS user's password.",
            _example => 'supergroovalisticprosifunkstication',
            _sub => sub { 
                my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
                return undef;
            },
        },

        ios_host => { 
            _doc => "Your IOS device.",
            _example => 'my-router.some.domain',
            _sub => sub { 
                my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
                return undef;
            },
        },

        enable_secret => { 
            _doc => "Your device's enable password to access exec mode.",
            _example => 'supergroovalisticprosifunkstication',
            _sub => sub { 
                my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
                return undef;
            },
        },

        repeats => { 
            _doc => "how many pings the probe should send. Defaults to 20.",
            _example => '15',
            _sub => sub { 
                my $val = shift;
                return "ERROR: Number of pings must be positive integer" unless $val =~ /[1-9][0-9]*/;
                return undef;
            },
        },

        packet_size => { 
            _doc => "ICMP packet size. Defaults to 100.",
            _example => '200',
            _sub => sub { 
                my $val = shift;
                return "ERROR: Packet size must be positive integer" unless $val =~ /[1-9][0-9]*/;
                return undef;
            },
        },

        source => { 
            _doc => "Ping source interface. IP address or interface description.",
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

# Configuration obtained from smokeping config file
# probe variables
    #my $binary        = $self->{properties}{binary};
    my $debug_level   = $self->{properties}{debug_level} // 3;
    my $ping_timeout  = $self->{properties}{ping_timeout} // 1;
    my $packet_size   = $target->{properties}{packet_size} // 100;

# target variables
    my $enable_secret = $target->{vars}{enable_secret};
    my $user          = $target->{vars}{user};
    my $password      = $target->{vars}{password};
    my $ios_host      = $target->{vars}{ios_host};
    my $repeats       = $target->{vars}{repeats} // 20;
    my $source        = $target->{vars}{source} // '';
    my $host          = $target->{vars}{host};

# syslog functions receive macros
    my %maskHash = (
        0 => LOG_EMERG,
        1 => LOG_ALERT,
        2 => LOG_CRIT,
        3 => LOG_ERR,
        4 => LOG_WARNING,
        5 => LOG_NOTICE,
        6 => LOG_INFO,
        7 => LOG_DEBUG
    );

# initialize syslog functionality
    setlogmask( LOG_UPTO ( $maskHash{ $debug_level } ) );
    openlog(  "SSHIOSPing", "ndelay", "user" );
    syslog( LOG_INFO, "Starting logging to syslog with priority: " . $maskHash{ $debug_level } );


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
        "source" => $source,
        "repeat" => "1",
        "size" => $packet_size
    );

    my $pingCommand = _buildPingCommand( $host, %pingOptions );
    my @pingValues = ();
    syslog( LOG_INFO, "Returned Ping Command: $pingCommand" );

    syslog( LOG_INFO, "Connecting to $ios_host" );
    my $session = Net::SSH2::Cisco->new();
    # We don't want a failed connection to kill the whole script:
    $session->errmode( 'return' );
    # Seems like a reasonable connection timeout
    $session->timeout( 20 );
    my $host_session = $session->connect( $ios_host ) or syslog( LOG_ERR, "failed to connect to $ios_host" );

    $session->login( $user, $password ) or syslog( LOG_ERR, "failed to authenticate \"$user\"") and die ;

    syslog( LOG_INFO, "Trying to reach exec mode on \"$ios_host\"" );
    if ( ! $session->is_enabled() and $enable_secret ) {
        $session->enable( $enable_secret ) or syslog( LOG_ERR, "Could not reach exec mode to run ping command on $ios_host" ) and die ;
    } elsif ( ! $session->is_enabled() ) {
        syslog( LOG_ERR, "User \"$user\" requires Exec mode to on $ios_host to run ping command properly" ) and die ;
    };

    #$session->input_log('/root/admin_sandbox/perl.log');

    syslog( LOG_INFO, "Running command : \"$pingCommand\" on $ios_host $repeats times");

    # run $repeats ping commands, smokeping will perform all statistical computations
    for my $count ( 1 .. $repeats ) {
        my @output = $session->cmd( $pingCommand ) or syslog( LOG_ERR, "Could not run ping command on $ios_host" );

        #print @output;

        my $result = _parsePingCommand( $ios_host, @output ) or syslog( LOG_ERR, "Could not validate ping command output from $ios_host") ;

        if ( $result ) {

            #print "Got $result for ping number $count\n";
            push @pingValues, $result if $result;

        } else {
            #print "Correu mal\n";
            next;
        }

        #print Dumper( \%result );

    };

    syslog( LOG_INFO, "From $ios_host I got: " . scalar @pingValues . " out of $repeats\n") ;

    syslog( LOG_INFO, "Closing connection to $ios_host");
    $session->close;

    #return @times;

    return "@pingValues";
}

# That's all, folks!

sub _buildPingCommand {

    my $_host = shift ;
    my %_pingOptions = @_ ;

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
    syslog( LOG_INFO, "ping Command: $result") ;
    return join(' ', @pingCommand );
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
        syslog( LOG_ERR, "Could not validate ping command output on host $_host") ;
        return ();
    };

    my $line = "@infoLine";
#squeeze all spaces
    $line =~ s/\s+/ /g;
#trim
    $line =~ s/^\s+|\s+$//g;
    $line = lc $line;

    syslog( LOG_INFO, "Matched information line: $line" );

    $line =~ m|$successTest| or syslog( LOG_ERR, "Metrics pattern was not matched") and return ();

    my ( $time, $unit ) = ( $line =~ m|$pattern| ) or syslog( LOG_ERR, "Could not get time and units") and return ();

    syslog( LOG_INFO, "Ping RTT time: $time $unit" ) ;

    return $time;
};

1;
