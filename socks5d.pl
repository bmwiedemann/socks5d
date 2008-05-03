#!/usr/bin/perl -w
use strict;
# Copyright 2008 Bernhard M. Wiedemann
# Licensed under GNU GPL - use, copy, modify as you like

use Getopt::Long;
use Time::HiRes qw(gettimeofday tv_interval);
use IO::Socket;
use IO::Socket::INET6;
use IO::Select;
use Net::Server::Fork;
use Net::Server::Daemonize qw(daemonize);
our @ISA = qw(Net::Server::Fork);


my %options=qw(
timeout	1
port     1080
);
my @options=qw(port|p=i timeout|w=i source|s=s verbose|v+ debug);
if(!GetOptions(\%options, @options)) {die "invalid option on commandline. @ARGV\n"}
my @opts;

sub diag($)
{
	if($options{debug}) {
		print STDERR @_,"\n";
	}
}

sub myread
{ sysread($_[0], $_[1], $_[2]); }

sub process_request {
	diag "accepted";
	my $head;
	my $fd=\*STDIN;
	my $outsocket;
	myread($fd, $head, 1);
	if(ord($head)==4) {
		diag("socks4 - TODO");
	} elsif(ord($head)==5) {
		diag("socks5");
		# myread auth methods supported by client
		myread($fd, $head, 1);
		myread($fd, $head, ord($head));
		# always choose "none" auth
		print "\x05\x00";
		# myread a request
		myread($fd, $head, 5);
		my($ver,$req, $res1, $addrtype, $size)=unpack("C*", $head);
		if($ver==5 and $req==1) {
			my $paddr;
			my $pport;
			if($addrtype==3) { # domain name
				myread($fd, $paddr, $size);
				myread($fd, $pport, 2);
				$pport=unpack("n", $pport);
			}
			diag("connection request for $paddr:$pport");
			if($paddr) {
				$outsocket=IO::Socket::INET6->new(@opts, PeerAddr=>$paddr, PeerPort=>$pport, Timeout=>$options{timeout});
				if(!$outsocket) {
					diag("error connecting: $!");
					# TODO: evaluate $! ?
					print "\x05\x05";
					return;
				}
				diag("success: established connection");
				print "\x05\x00\x00",chr($addrtype),chr($size),$paddr,pack("n",$pport);
			}
		}
	} elsif($head eq "G" or $head eq "H") {
		print "HTTP/1.0 200 OK\015\012Content-Type: text/html\015\012\015\012This is not a HTTP-proxy. Please use a client that supports SOCKS5.\n";
		return;
	} else {
		print "This is a SOCKS5 proxy\n";
		return;
	}

	# main forwarding of data


	my $willexit=0;
	my $exittime;
	my $sel=IO::Select->new($outsocket, $fd);
	MAINLOOP:
	while(1) {
		my @ready = $sel->can_read(1);
		if($willexit>1 || ($willexit && tv_interval($exittime)>$options{timeout})) {
			last
		}
		foreach my $f (@ready) {
			my $wfd= (($fd == $f)?$outsocket : $fd);
			my $data;
			my $numbytes=sysread($f, $data, 65000);
			if(!$numbytes) { 
				# we are done when the remote socket is closed
				if($f == $outsocket) { 
					diag("Remote side closed connection. Stopping transmission immediately.");
					last MAINLOOP 
				}
				diag("Internal side closed connection. Waiting $options{timeout} seconds for responses.");
				$willexit++; $sel->remove($f); close($f); $exittime||=[gettimeofday()]; next; 
			}
			syswrite($wfd, $data, $numbytes);
		}
	}
}

#daemonize( 'nobody', 'nobody', 'socks5d.pid');

__PACKAGE__->run(port => $options{port});

