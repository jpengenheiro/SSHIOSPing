package Smokeping::probes::SSHNXOSPing;

=head1 301 Moved Permanently

This is a Smokeping probe module. Please use the command 

C<smokeping -man Smokeping::probes::SSHIOSPing>

to view the documentation or the command

C<smokeping -makepod Smokeping::probes::SSHIOSPing>

to generate the POD document.

=cut

use Net::SSH::Perl;
use strict;
use warnings;
use base qw(Smokeping::probes::basefork); 
use Carp;

sub pod_hash {
    return {
        name => <<DOC,
Smokeping::probes::SSHNXOSPing - A ping latency Probe that runs over SSH for Cisco NXOS devices
DOC
        description => <<DOC,
This probe connects to Cisco NXOS devices and runs ping commands to arbitrary hosts
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

sub new($$$) {
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

sub ProbeDesc($){
    my $self = shift;
    return "Cisco Nexus ICMP host pinger";
}

sub probevars {
    my $class = shift;

    return $class->_makevars( $class->SUPER::probevars, {

        ping_timeout => { 
            _doc => "ping command timeout in seconds, defaults to 1.",
            _example => '20',
            _default => 1,
            _sub => sub { 
                my $val = shift;
                return "ERROR: Ping timeout must be positive integer." unless $val =~ /^[1-9][0-9]*$/;
                return undef;
            },
        },

        repeats => { 
            _doc => "Number of pings the probe should send. Defaults to 20.",
            _example => '15',
            _default => 20,
            _sub => sub { 
                my $val = shift;
                return "ERROR: Number of pings must be positive integer" unless $val =~ /[1-9][0-9]*/;
                return undef;
            },
        },

    } );

}

# Here's the place for target-specific variables

sub targetvars {
    my $class = shift;
    return $class->_makevars($class->SUPER::probevars, {
        _mandatory => [ 'user', 'password', 'host', 'nxos_host' ],

        user => { 
            _doc => "Username to login to NXOS device.",
            _example => 'johnny.b.good',
            _sub => sub { 
                my $val = shift;
                return "ERROR: Invalid username $val" unless $val =~ /^[\w][-\.\w]+[\w]+$/;
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

        nxos_host => { 
            _doc => "Your NXOS device.",
            _example => 'my-router.some.domain',
            _sub => sub { 
                my $val = shift;
                return "ERROR: hostname must be a single word" unless $val =~ /^\S+$/;
                return undef;
            },
        },

        host => { 
            _doc => "Target device.",
            _example => 'host-behind-nexus.some.domain',
            _sub => sub { 
                my $val = shift;
                return "ERROR: hostname must be a single word" unless $val =~ /^\S+$/;
                return undef;
            },
        },

        packet_size => { 
            _doc => "ICMP packet size. Defaults to 100.",
            _example => '200',
            _default => 100,
            _sub => sub { 
                my $val = shift;
                return "ERROR: Packet size must be positive integer" unless $val =~ /[1-9][0-9]*/;
                return undef;
            },
        },

        source_interface => {
            _doc => "Ping source interface. Must be an interface name.",
            _example => 'Ethernet 1/1',
            _sub => sub { 
                my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
                return undef;
            },
        },

        source => {
            _doc => "Ping source. IP address or hostname.",
            _example => '10.10.10.10',
            _sub => sub { 
                my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
                return undef;
            },
        },

        vrf => {
            _doc => "Ping host using specific VRF. Is prepended to `source' if `source' exists",
            _example => 'myVRF',
            _sub => sub { 
                my $val = shift;
                #return "ERROR: ssh 'binary' does not point to an executable" unless -f $val and -x _;
                return undef;
            },
        },

    });

};

sub pingone ($){
    my $self   = shift;
    my $target = shift;

    # our probe variables
    my $ping_timeout = $self->{properties}{ping_timeout};
    # print "ping timeout: $ping_timeout";
    qx( echo ping timeout: $ping_timeout | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing INFO: ping-timeout: $ping_timeout" );
    my $repeats      = $self->{properties}{repeats};
    # print "repeats: $repeats";
    qx( echo repeats: $repeats | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing INFO: repeats: $repeats" );

    # our target variables
    my $user             = $target->{vars}{user};
    # print "user: $user";
    qx( echo user: $user | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing INFO: user: $user" );
    my $password         = $target->{vars}{password};
    # print "password: $password";
    qx( echo password: $password | nc 127.0.0.1 12200 );
    my $host             = $target->{vars}{host};
    # print "host: $host";
    qx( echo host: $host | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing INFO: user: $user" );
    my $nxos_host        = $target->{vars}{nxos_host};
    # print "nxos_host: $nxos_host";
    qx( echo nxos_host: $nxos_host | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing INFO: nexus host: $nxos_host" );
    my $packet_size      = $target->{vars}{packet_size};
    # print "packet_size: $packet_size";
    qx( echo packet_size: $packet_size | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing INFO: nexus host: $nxos_host" );

    # these are mandatory options
    my %pingOptions;
    $pingOptions{"count"}       = $repeats;
    $pingOptions{"host"}        = $host;
    $pingOptions{"packet-size"} = $packet_size;
    $pingOptions{"timeout"}     = $ping_timeout;
    qx( echo built mandatory options | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing INFO: mandatory configs successfully built" );

    # specify all the supported options to create a valid ping NXOS command

    $pingOptions{"source"}           = $target->{"vars"}{"source"}
        if defined $target->{"vars"}{"source"};
    $pingOptions{"source-interface"} = $target->{"vars"}{"source_interface"}
        if defined $target->{"vars"}{"source_interface"};
    $pingOptions{"vrf"}              = $target->{"vars"}{"vrf"}
        if defined $target->{"vars"}{"vrf"};
    qx( echo built other options | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing INFO: optional configs successfully built" );

    my $nexus = Net::SSH::Perl->new( $nxos_host, ( "protocol" => "2" ) );
    qx( echo connected to $nxos_host | nc 127.0.0.1 12200 );
    $self->do_log( "SSHNXOSPing WARN: successfully connected to $nxos_host" );

    if ( $nexus->login( $user, $password ) ) {
        $self->do_log( "Failed connecting to $nxos_host" )
    };
    my $pingCommand = _buildPingCommand( %pingOptions );
    $self->do_log( "$host will get: `$pingCommand'" );
    my ( $stdout, $stderr, $exit ) = $nexus->cmd( $pingCommand );

    # print $stdout, "\n";
    # print $stderr, "\n";
    # print $exit, "\n";

    # $exit: 0 is success
    if ( $exit == 0 ) {
        $self->do_log( "$nxos_host Successfully ran ping command against $host" );
        return _parsePingCommand( $stdout );
    } else {
        $self->do_log( "$nxos_host ERROR: $stderr" );
    };

};

sub _parsePingCommand {
    my $stdout = shift;
    my @measurements;
    for ( split( /^/, $stdout ) ) {
        /\btime=(\S+)\sms$/ or next;
        # print;
        push @measurements, $1;
    };
    @measurements = map { sprintf "%.10e", $_ } sort { $a <=> $b } @measurements;
    return @measurements;
};

sub _buildPingCommand {
    my %pingOptions      = shift;
    my $host             = $pingOptions{"host"};
    my $vrf              = $pingOptions{"vrf"};
    my $source_interface = $pingOptions{"source-interface"};
    delete $pingOptions{"host"};
    delete $pingOptions{"vrf"};
    delete $pingOptions{"source-interface"};

    my $pingCommand      = "ping $host";
    $pingCommand = $vrf ? "$pingCommand vrf $vrf" :
                   $source_interface ? "$pingCommand source-interface $source_interface" :
                   $pingCommand;
    for my $key ( keys %pingOptions ) {
        $pingCommand .= " " . $key . " " . $pingOptions{$key};

    };
    return $pingCommand;
};

1;
