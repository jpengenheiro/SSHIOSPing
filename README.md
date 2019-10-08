# SSHIOSPing
Cisco IOS ping probe for smokeping, using SSH password authentication
This is an attempt at making a probe that connects to IOS devices using SSH

It can run ping commands on IOS devices to the hosts of your choice.

Currently it does not work out of the box with distributed setup, however I succeded in using with a single node

To install just drop SSHIOSPing.pm in your lib/Smokeping/probes directory

options are documented with:

smokeping -man Smokeping::probes::SSHIOSPing

a config template will be available eventually
