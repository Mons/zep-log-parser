#!/usr/bin/env perl

use 5.010;
use strict;
use POSIX 'strftime';

sub Y2013() { 1356984000 }

sub RSIZE() { 4096*1000 }
my %stat;
@ARGV or die "Usage: \n\t$0 binlog [binlog ...]\n";

for (@ARGV) {
	open my $f,'<:raw',$_ or do {warn "Can't open `$_': $!"; next;};
	my $buf;
	while () {
		my $r = sysread($f, $buf, RSIZE, length($buf));
		if ($r) {
			my $len = length $buf;
			my $pos = 0;
			while ( $pos + 12 <= $len ) {
				my ($ts,$uid,$ua) = unpack 'VVV', substr($buf,$pos,12);
				use integer;
				my $hid = ($ts - Y2013)/3600;
				my $did = ($ts - Y2013)/86400;
				
				#my ($time) = strftime("%y-%m-%d-%H",localtime($ts));
				#my ($day) = strftime("%y-%m-%d",localtime($ts));
				#print "$time - $uid - $ua\n";
				$stat{$hid}{hits}++;
				$stat{$hid}{users}{$uid}=1;
				$stat{$hid}{agent}{$ua}{$uid}=1;
				
				$stat{$did}{hits}++;
				$stat{$did}{users}{$uid}=1;
				$stat{$did}{agent}{$ua}{$uid}=1;
				
				$stat{summary}{hits}++;
				$stat{summary}{users}{$uid}=1;
				$stat{summary}{agent}{$ua}{$uid}=1;
				
				$pos += 12;
			}
			$buf = substr($buf,$pos);
		}
		elsif (defined $r) {
			last;
		}
		else {
			warn "read failed: $!";
			last;
		}
	}
}

my @ag = 0..6,2**32-1;
my %agents = (
	2**32-1 => 'unk',
	0       => 'non',
	1       => 'ios',
	2       => 'and',
	3       => 'win',
	4       => 'mac',
	5       => 'lin',
	6       => 'www',
);


printf "%-16s",'day-hour';
say join("\t", (map $agents{$_},@ag), qw(hits users));

for my $key ( sort keys %stat ) {
	my @agents = map { 0+keys %{ $stat{$key}{agent}{$_} } } @ag;
	printf "%-16s",$key;
	say join("\t",@agents, $stat{$key}{hits}, 0+keys %{$stat{$key}{users}} );
}
