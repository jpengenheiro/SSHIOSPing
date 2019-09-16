#! /usr/bin/perl

use Data::Dumper;
use Net::SSH2::Cisco;
use strict;
use warnings;
use Sys::Syslog qw(:standard :macros);

# Configuração a obter do ficheiro do smokeping
my $debug = '0' ;
my $debugLevel = '7' ;
my $user = 'teste';
my $password = 'Passw0rd';
my $enable_secret = 'Passw0rd';
my $repeats = 20;
my $ping_timeout = 15;
my $psource = "";
my $packetsize = "200";
my $host = '1.1.1.1';

my %pingOptions = (
    "timeout" => $ping_timeout,
    "source" => $psource,
    "repeat" => "1",
    "size" => $packetsize
);

sub _buildPingCommand {

    my $_host = shift ;
    my %_pingOptions = @_ ;

    print "\tHOST : $_host\n";
    #print Dumper ( %_pingOptions );
    while ( my ( $_key, $_value) = each ( %_pingOptions ) ) {
        print "\t$_key : $_value\n";
    };
    #print "OPTIONS @_pingOptions\n";

    my @pingCommand = ( 'ping', $_host ) ;
    while (my ( $param, $value ) = each %_pingOptions ) {
        if ( $value ) {
            push @pingCommand, $param, $value;
        }
    }
    my $result = join(' ', @pingCommand );
    _syslog( $debug, LOG_INFO, "ping Command: $result") ;
    return join(' ', @pingCommand );
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

    $debug = _setLogLevel( $debugLevel ) and openlog(  "SSHIOSPing", "ndelay", "user");

# se não conseguirmos validar a linha das informações vamos terminar a função
    @infoLine = grep {/^Success/} @pingOutput ;
    if ( ! @infoLine ) {
        _syslog( $debug, LOG_ERR, "Could not validate ping command output on host $_host") ;
        return ();
    };

    my $line = "@infoLine";
#squeeze all spaces
    $line =~ s/\s+/ /g;
#trim
    $line =~ s/^\s+|\s+$//g;
    $line = lc $line;

    _syslog( $debug, LOG_INFO, "Matched information line: $line" );

    $line =~ m|$successTest| or _syslog( $debug, LOG_ERR, "Metrics pattern was not matched") and return ();

    my ( $time, $unit ) = ( $line =~ m|$pattern| ) or _syslog( $debug, LOG_ERR, "Could not get time and units") and return ();

    _syslog( $debug, LOG_INFO, "Ping RTT time: $time $unit" ) ;

    return $time;
};

my $pingCommand = _buildPingCommand( $host, %pingOptions );
my @pingValues = ();

#for ( @ioshosts ) {
#print "Starting run on " . scalar @ARGV . " hosts\n";
for ( sort @ARGV ) {
    @pingValues = ();

    _syslog( $debug, LOG_DEBUG, "Connecting to $_" );
    my $session = Net::SSH2::Cisco->new();
    # Não queremos que uma ligação falhada mande o script todo abaixo:
    $session->errmode( 'return' );
    $session->timeout( 20 );
    my $host_session = $session->connect( $_ ) or _syslog( $debug, LOG_ERR, "failed to connect to $_" ) and next;

    $session->login( $user, $password );

    _syslog( $debug, LOG_DEBUG, "Trying to reach exec mode" );
        if ( ! $session->is_enabled() and $enable_secret ) {
            $session->enable( $enable_secret ) or _syslog( $debug, LOG_ERR, "Could not reach exec mode to run ping command" ) and next;
        } elsif ( ! $session->is_enabled() ) {
            _syslog( $debug, LOG_ERR, "User \"$user\" requires Exec mode to run ping command properly" );
            next;
        };

        #$session->input_log('/root/admin_sandbox/perl.log');

        _syslog( $debug, LOG_DEBUG, "Running command : \"$pingCommand\" on $_");

        # run $repeats ping commands, smokeping will perform all statistical computations
        for my $count ( 1 .. $repeats ) {
            my @output = $session->cmd( $pingCommand ) or _syslog( $debug, LOG_ERR, "Could not run command" );

            #print @output;

            my $result = _parsePingCommand( $_, @output ) ;

            if ( $result ) {

                #print "Got $result for ping number $count\n";
                push @pingValues, $result if $result;

            } else {
                #print "Correu mal\n";
                next;
            }

            #print Dumper( \%result );

        };

        _syslog( $debug, LOG_INFO, "For host $_ I got: " . scalar @pingValues . " out of $repeats\n") ;

        _syslog( $debug, LOG_DEBUG, "Closing connection to $_");
        $session->close;

};

# Execute a command
#my @output = $session->cmd('show version');
#print @output;
 
# Enable mode
#if ($session->enable("Passw0rd") ) {
#    my @output = $session->cmd('ping ip 8.8.8.8 repeat 20');
#    print "@output\n";
#    my $error_mode = $session->errmode;
#    print "$error_mode\n";
#} else {
#    warn "Can't enable: " . $session->errmsg;
#}

#my $mode = $session->autopage();
#$mode = $session->autopage(1);
#print "terminal length : $mode\n";
#my @running_config = $session->cmd('show running-config');
#my $counter = 0;
#for my $line ( @running_config ) {
#    chomp $line;
#    print ++$counter . " : $line\n";
#}
