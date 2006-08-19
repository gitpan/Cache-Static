#!/usr/bin/perl -w

package Apache::scache;

use strict;
use Apache::Constants qw(:common);
use Cache::Static;
use Net::HTTP;

#NOTE: unless you really know what you're doing, you almost certainly
#don't want a trailing slash here, it will be automatically added
my $BACKEND = "http://localhost:80/mason";
my $SCACHE_ROOT = "/scache.pl";
my $VERBOSITY = 1;

#some quick initialization - split backend into HOST, PATH
my @t = split(/\//, $BACKEND);
my $HOST = $t[2];
my $PATH = join('/', @t[3..$#t]);
$PATH = "/$PATH";

sub handler {
	my $r = shift;
	$r->content_type('text/html');
	$r->send_http_header;
	my $uri = $r->uri;
	$uri =~ s/^$SCACHE_ROOT//;
	my %args = $r->args;
	my $fkey = Cache::Static::make_friendly_key($uri, \%args);
	my $key = Cache::Static::make_key_from_friendly($fkey);
	my $ret = Cache::Static::get_if_same($key);
	if(defined($ret)) {
		if($VERBOSITY > 1) {
			$r->print("<p>scache serving cached component for $fkey ($key)</p>\n");
		} elsif($VERBOSITY) {
			$r->print("<!-- scache serving cached component for $fkey ($key) -->\n");
		}
		$r->print($ret);
	} else {
		my $s = Net::HTTP->new(Host => $HOST) || die $@;
		#TODO: pass along cookies, user agent, etc. (?)
		$s->write_request(GET => "$PATH$uri", 'User-Agent' => "Mozilla/5.0");
		my ($code, $mess, %h) = $s->read_response_headers;
		while(1) {
			my($buf, $n);
			$n = $s->read_entity_body($buf, 8192);
			die "read failed: $!" unless defined($n);
			last unless $n;
			$r->print($buf);
		}
	}
	return OK;
}

1;

