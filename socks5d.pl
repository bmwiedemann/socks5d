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
timeout	3
port     1080
);
my @options=qw(port|p=i timeout|w=i source|s=s verbose|v+ debug);
if(!GetOptions(\%options, @options)) {die "invalid option on commandline. @ARGV\n"}
my @opts;
my @serveropts=(port=>$options{port});
if($options{source}) {
	push(@serveropts, "host", $options{source});
}
if(!$options{debug}) {
	push(@serveropts, "background", 1);
} else {
	push(@serveropts, "debug", 1);
}

sub diag($)
{
	if($options{debug}) {
		print STDERR @_,"\n";
	}
}

sub myread
{ sysread($_[0], $_[1], $_[2]); }

sub binip4tostr($)
{ my($ip)=@_;
	return sprintf("%i.%i.%i.%i", (($ip>>24)&0xff), (($ip>>16)&0xff), (($ip>>8)&0xff), ($ip&0xff))
}

sub process_request {
	diag "accepted";
	my $head;
	my $fd=\*STDIN;
	my $outsocket;
	myread($fd, $head, 1);
	if(ord($head)==4) {
		diag("socks4");
		myread($fd, $head, 700);
		my($req, $pport, $ip, $username, $paddr)=unpack("CnNZ*Z*", $head);
		if($req==1) {
			diag("ip:$ip :$pport $username $paddr");
			if($ip<256) {
				diag("socks4a");
			} else {
				$paddr=binip4tostr($ip);
			}
			$outsocket=IO::Socket::INET6->new(@opts, PeerAddr=>$paddr, PeerPort=>$pport, Timeout=>$options{timeout});
			if(!$outsocket) {
				diag("error connecting: $!");
				print("\x00\x5b",pack("n",$pport),"\x00\x00\x00\x00");
				return;
			}
			print("\x00\x5a",pack("n",$pport),"\x00\x00\x00\x00");
		}
	} elsif(ord($head)==5) {
		diag("socks5");
		# myread auth methods supported by client
		myread($fd, $head, 1);
		myread($fd, $head, ord($head));
		# always choose "none" auth
		print "\x05\x00";
		# myread a request
		myread($fd, $head, 4);
		my($ver,$req, $res1, $addrtype)=unpack("C*", $head);
		if($ver==5 and $req==1) {
			my $paddr;
			my $pport;
			if($addrtype==3) { # domain name
				myread($fd, $head, 1);
				my $size=ord($head);
				myread($fd, $paddr, $size);
				myread($fd, $pport, 2);
				$pport=unpack("n", $pport);
			} elsif($addrtype==1) {
				myread($fd, $head, 6);
				my $ip;
				($ip, $pport)=unpack("Nn", $head);
				$paddr=binip4tostr($ip);
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
				my $laddr=$outsocket->sockhost();
				diag("success: established connection from $laddr");
				if($laddr=~m/:/) {
					# causes assertion in dante-client-1.1.19
					#$addrtype=4;
					#$paddr=$outsocket->sockaddr();
					$paddr=chr(length($paddr)).$paddr;
				} else {
					$addrtype=1;
					$paddr=$outsocket->sockaddr();
				}
				print("\x05\x00\x00",chr($addrtype),$paddr,pack("n",$outsocket->sockport()));
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
			my $wfd= (($fd == $f)?$outsocket : \*STDOUT); # fd to write to
			syswrite($wfd, $data, $numbytes);
		}
	}
}

#daemonize( 'nobody', 'nobody', 'socks5d.pid');

__PACKAGE__->run(@serveropts);

