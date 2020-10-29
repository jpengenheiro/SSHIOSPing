package Smokeping::probes::SSHNXOSPing;

=head1 301 Moved Permanently

This is a Smokeping probe module. Please use the command 

C<smokeping -man Smokeping::probes::SSHIOSPing>

to view the documentation or the command

C<smokeping -makepod Smokeping::probes::SSHIOSPing>

to generate the POD document.

=cut

use Net::SSH::Perl;
use Time::Out qw( timeout );
use strict;
use warnings;
use base qw(Smokeping::probes::basefork); 
use Carp;

sub pod_hash {
    my %pod = {
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
    return \%pod;
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

        connection_timeout => { 
            _doc => "SSH connection timeout in seconds, defaults to 5.",
            _example => '20',
            _default => 5,
            _sub => sub { 
                my $val = shift;
                return "ERROR: SSH connection timeout must be positive integer." unless $val =~ /^[1-9][0-9]*$/;
                return undef;
            },
        },

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
            _doc => "Your NXOS user's password.",
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

        # host => { 
        #     _doc => "Target device.",
        #     _example => 'host-behind-nexus.some.domain',
        #     _sub => sub { 
        #         my $val = shift;
        #         return "ERROR: hostname must be a single word" unless $val =~ /^\S+$/;
        #         return undef;
        #     },
        # },

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

    my %pingOptions;

    # our probe variables
    my $connection_timeout = $self->{properties}{connection_timeout};
    $self->do_log( "INFO: connection_timeout: $connection_timeout" );

    my $ping_timeout = $self->{properties}{ping_timeout};
    $self->do_log( "INFO: ping_timeout: $ping_timeout" );

    my $repeats      = $self->{properties}{repeats};
    $self->do_log( "INFO: repeats: $repeats" );

    # our target variables
    my $user             = $target->{vars}{user};
    $self->do_log( "INFO: user: $user" );

    my $password         = $target->{vars}{password};

    my $host             = $target->{vars}{host};
    $self->do_log( "INFO: host: $host" );

    my $nxos_host        = $target->{vars}{nxos_host};
    $self->do_log( "INFO: nexus host: $nxos_host" );

    my $packet_size      = $target->{vars}{packet_size};
    $self->do_log( "INFO: nexus packet-size: $packet_size" );

    # these are mandatory options
    $pingOptions{"count"}       = $repeats;
    $pingOptions{"host"}        = $host;
    $pingOptions{"packet-size"} = $packet_size;
    $pingOptions{"timeout"}     = $ping_timeout;

    $self->do_log( "INFO: mandatory configs successfully built" );

    # specify all the supported options to create a valid ping NXOS command

    if ( $target->{"vars"}{"source"} ) {
        $pingOptions{"source"} = $target->{"vars"}{"source"};
        $self->do_log( "INFO: source: $pingOptions{'source'}" );
    } else {
        $pingOptions{"source"} = '';
    };

    if ( $target->{"vars"}{"source_interface"} ) {
        $pingOptions{"source-interface"} = $target->{"vars"}{"source_interface"};
        $self->do_log( "INFO: source_interface: $pingOptions{'source-interface'}" );
    } else {
        $pingOptions{"source-interface"} = '';
    };

    if ( $target->{"vars"}{"vrf"} ) {
        $pingOptions{"vrf"} = $target->{"vars"}{"vrf"};
        $self->do_log( "INFO: vrf: $pingOptions{'vrf'}" );
    } else {
        $pingOptions{"vrf"} = '';
    };

    $self->do_log( "INFO: optional configs successfully built" );

    # for my $key ( keys %pingOptions ) {
    #     $self->do_log( "DUMP: $key : $pingOptions{$key}" );
    # };

    $self->do_log( "INFO: attempting connection to $nxos_host" );

    # prevents a huge timeout that kills the probe
    my $nexus = timeout $connection_timeout => sub {
        return Net::SSH::Perl->new( $nxos_host, ( "protocol" => "2" ) );
    };
    if ($@) {
        $self->do_log( "WARN: failed to connect to $nxos_host" );
        return ();
    }

    $self->do_log( "INFO: successfully connected to $nxos_host" );

    $nexus->login( $user, $password );

    my $pingCommand = _buildPingCommand( ( \%pingOptions, $self ) );
    $self->do_log( "$nxos_host will get: `$pingCommand'" );
    my ( $stdout, $stderr, $exit ) = $nexus->cmd( $pingCommand );

    # $exit: 0 is success
    if ( $exit == 0 ) {
        $self->do_log( "$nxos_host Successfully ran ping command against $host" );
        return _parsePingCommand( $stdout, $self, $nexus_host );
    } else {
        $self->do_log( "$nxos_host ERROR: $stderr" );
    };

};

sub _parsePingCommand {
    my $stdout = shift;
    my $self   = shift;
    my $nexus_host   = shift;
    my @measurements;
    my $measurement;
    for ( split( /^/, $stdout ) ) {
        # we only expect measurements in milliseconds,
        # could not find any information about ther being any other unit
        # besides milliseconds so...
        /\btime=(\S+)\sms$/ or next;
        # print;
        # convert to seconds as expected by smokeping
        $measurement = $1 / 1000 ;
        $self->do_log( "$nxos_host returned measurements @measurements" );
        push @measurements, $measurement;
    };
    $self->do_log( "$nxos_host returned measurements @measurements" );
    @measurements = map { sprintf "%.10e", $_ } sort { $a <=> $b } @measurements;
    $self->do_log( "$nxos_host returned measurements @measurements" );
    return @measurements;
};

sub _buildPingCommand {
    my $pingOptions = shift;
    my $self      = shift;

    # for my $key ( keys %$pingOptions ) {
    #     $self->do_log( "DUMP: SUB: $key : $pingOptions->{$key}" );
    # };

    my $host             = $pingOptions->{"host"};
    my $source_interface = $pingOptions->{"source-interface"};
    # my $vrf              = $pingOptions->{"vrf"};
    delete $pingOptions->{"host"};
    delete $pingOptions->{"source-interface"};
    delete $pingOptions->{"vrf"}    unless $pingOptions->{"vrf"};
    delete $pingOptions->{"source"} unless $pingOptions->{"source"};

    my $pingCommand      = "ping $host";
    # $pingCommand = $vrf ? "$pingCommand vrf $vrf" :
    #                $source_interface ? "$pingCommand source-interface $source_interface" :
    #                $pingCommand;

    # "source-interface" allows "vrf" and "source" options,
    # but "vrf" and "source" do not allow "source-interface"
    # so "source-interface" must be concatenated first
    $pingCommand .= " source-interface $source_interface" if $source_interface;

    for my $key ( keys %$pingOptions ) {
        $pingCommand .= " $key " . $pingOptions->{$key};

    };

    return $pingCommand;
};

1;
