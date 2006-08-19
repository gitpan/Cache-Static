use 5.005;
use ExtUtils::MakeMaker;

my @extensions = qw ( XML::Comma HTML::Mason DBI ) ;
my @wrappers   = qw ( DBI );

sub usage {
	my $arg = shift;
	chomp($arg);

	my @ext = (@extensions, @wrappers);
	print STDERR "$arg\n";
	print STDERR "perl Makefile.PL\n";
	print STDERR '   [ -$extension1 -$extension2 ... ]'."\n";
	print STDERR "      valid extensions are: @ext\n";
	print STDERR "      note that wrappers can also be included here\n";
	print STDERR "   [ -hmc ]\n";
	print STDERR "      this disables HTML_Mason_Util trying to detemrine\n";
	print STDERR "      which component files to depend on - useful if you\n";
	print STDERR "      have, for example, overridden the resolver class\n";
	exit(1);
}

my $disable_hmc = 0;
foreach my $arg (@ARGV) {
	if($arg =~ /^-hmc$/i) {
		$disable_hmc = 1;
	} elsif($arg =~ /^\-.*$/) {
		my $name = substr($arg, 1);
		#remove an extension/wrapper
		@extensions = grep(!/^$name$/, @extensions);
		@wrappers = grep(!/^$name$/, @wrappers);
	} elsif($arg =~ /^\+.*$/) {
		die "do we really want to allow force-adding an extension/wrapper?";
	} else {
		usage("unknown argument to Makefile.PL: $arg");
	}
}

my $prereq_pms = { Digest::MD5 => 0, Storable => 0 };
my $pms = { 'lib/Cache/Static.pm' => 'blib/lib/Cache/Static.pm' };

#foo::bar -> Cache::Static::foo_bar_Util
foreach my $ext (@extensions) {
	eval "require $ext";
	if ($@) {
		warn "skipping $ext\n";
	} else {
		warn "including extension: $ext\n";
		my $name = $ext.'_Util';
		$name =~ s/\:\:/_/g;
		$prereq_pms->{$ext} = 0;
		$pms->{"lib/Cache/Static/$name.pm"} = 
			"blib/lib/Cache/Static/$name.pm";
		if($ext eq 'HTML::Mason') {
			if($disable_hmc) {
				warn "disabling HTML::Mason compiler as per your request\n";
			} else {
				$pms->{"lib/Cache/Static/HTML_Mason_Util/hmc.pm"} = 
					"blib/lib/Cache/Static/HTML_Mason_Util/hmc.pm";
			}
		}
	}
}

#foo::bar -> Cache::Static::foo_bar
foreach my $ext (@wrappers) {
	eval "require $ext";
	if ($@) {
		warn "skipping $ext\n";
	} else {
		warn "including wrapper: $ext\n";
		my $name = $ext;
		$name =~ s/\:\:/_/g;
		$prereq_pms->{$ext} = 0;
		$pms->{"lib/Cache/Static/$name.pm"} = 
			"blib/lib/Cache/Static/$name.pm";
	}
}

WriteMakefile(
	NAME              => 'Cache::Static',
	VERSION_FROM      => 'lib/Cache/Static.pm', # finds $VERSION
	PREREQ_PM         => $prereq_pms,
	PM                => $pms,
);

#install cache_static.macro
use misc::MakeMakerMod;
misc::MakeMakerMod::add_steps(
	step => "install",
	what => "perl misc/install-extras.pl"
);
