#!/usr/bin/perl -w

use strict;

package misc::MakeMakerMod;

sub add_steps {
	my %args = @_;
	my $file = $args{file} || "Makefile";
	my $step = $args{step} || "install";
	my $what = $args{what} || die "must provide a what argument";

	#read the Makefile
	open(MF, "<$file") || die "can't open Makefile for reading";
	my @lines = <MF>;
	close(MF);

	#find the step we're interested in
	my ($c, $ln) = (0,0);
	map { $c++; $ln = $c if(grep(/^$step\s+\:/, $_)); } @lines;

	#write the Makefile back out with extra commands in the install step
	open(MF, ">$file") || die "can't open Makefile for writing";
	map { print MF $_ } @lines[0..$ln-1];
	map { my $l = "\t$_"; chomp($l); print MF "$l\n" } 
		split("\n", $what);
	map { print MF $_ } @lines[$ln..$#lines];
	close(MF);
}

1;

