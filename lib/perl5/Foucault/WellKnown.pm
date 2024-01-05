#

package Foucault::WellKnown;

use strict;
use English;
use Template;
use JSON::XS;

our $REGMARK;

####

sub new ($) {
	my ($class) = @_;
	return bless {
		'wellknowndir' => undef,
		'rules' => {},
	};
}

####

sub set_wellknowndir ($$) {
	my ( $this, $d ) = @_;
	die "$d: is not directory, stopped" unless -d $d;
	$$this{wellknowndir} = $d;
}

####

sub quotemetaex ($) {
	local $_ = shift;
	s{([\x24\x28-\x2b\x2e\x3f\x5b-\x5e\x7b-\x7d])}{\\$1}g;
	return $_;
}

####

sub read_regexpfile ($$) {
	my ( $this, $f ) = @_;
	open my $h, '<', $f or do {
		print "read_regexpfile: $f: cannot read.\n";
		return undef, undef;
	};
	my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
	    $atime, $mtime, $ctime, $blksize, $blocks) = stat $h;
	my $regexp = join '', <$h>;
	chomp $regexp;
	close $h;
	my $regexp_compiled;
	eval {
		$regexp_compiled = qr"^$regexp$";
	};
	unless( defined $regexp_compiled ){
		print "read_regexpfile: $f: cannot compile.\n";
		return undef, undef;
	}
	return $regexp_compiled, $mtime;
}

sub read_rulefile ($$) {
	my ($this, $patternname) = @_;
	my $rules        = $$this{rules};
	my $wellknowndir = $$this{wellknowndir};
	my $conffile = "$wellknowndir/$patternname.rules";

	my $mark = "rule0000";
	my $lastmark;
	my %mark2replace;
	my @res;
	open my $h, '<', $conffile or die "$conffile: cannot open, stopped";
	while( <$h> ){
		chomp;
		s{^\s*}{}g;
		next if m{^\s*($|#)};
		my @c = split m{\s+};
		if( m"^\s*(ignore|replace)\s+(\S.*)$" ){
			my $pattern = $2;
			eval { qr"$pattern"; };
			unless( $@ eq "" ){
				print STDERR "$conffile:$.: syntax error. \n";
				print STDERR "$conffile:$.: $@\n";
				next;
			}
			push @res, "$pattern(*:$mark)";
			$mark2replace{$mark} = $pattern;
			$lastmark = $mark;
			$mark++;
		}elsif( m"^\s*(as|with)\s+(\S.*)$" ){
			my $pattern = $2;
			eval { qr"$pattern"; };
			unless( $@ eq "" ){
				print STDERR "$conffile:$.: syntax error. \n";
				print STDERR "$conffile:$.: $@\n";
				next;
			}
			$mark2replace{$lastmark} = $pattern;
		}else{
			die "$conffile:$.: illegal format, stopped";
		}
	}
	close $h;
	my $re = "(" . join("|", @res) . ")";

	$$rules{$patternname} = {
		conffile     => $conffile,
		regexp       => qr"$re",
		mark2replace => \%mark2replace,
	};
}

sub read_patternfile ($$) {
	my ($this, $patternname) = @_;
	my $wellknowndir = $$this{wellknowndir};
	my $conffile = "$wellknowndir/$patternname.regexp";

	open my $h, '<', $conffile or die "$conffile: cannot open, stopped";
	my $pattern = join '', <$h>;
	close $h;
	chomp $pattern;
	return qr"^$pattern$";
}

sub generalize ($$) {
	my ($this, $patternname, $sample) = @_;
	my $rule = $$this{rules}->{$patternname};
	die unless defined $rule;

        my $rule_regexp  = $$rule{regexp};
	my $mark2replace = $$rule{mark2replace};

        my $generalized;
        while( $sample =~ m"$rule_regexp"p ){
                $generalized .= quotemetaex ${^PREMATCH};
                $generalized .= $$mark2replace{$REGMARK};
                $sample = ${^POSTMATCH};
        }
        $generalized .= quotemetaex $sample;
        return $generalized;
}

####

#### test confs

sub add_sample ($$$$) {
        my ($stats, $sample, $pattern_fracture, $unixtime) = @_;
        my $samples         = $$stats{samples};
        my $fracture2sample = $$stats{fracture2sample};

        if    ( $$samples{$sample} ){
                # nothing to do
        }elsif( my $s = $$fracture2sample{$pattern_fracture} ){
		my $i = $$samples{$s};
                $$i{total}++;
        }else{
		eval { qr"$pattern_fracture"; };
                if( $@ ){
                	print STDERR "ERROR: invalid pattern fracture\n",
				"       $samples\n",
				"       $pattern_fracture\n";
		}
                $$samples{$sample} = {
			pattern_fracture => $pattern_fracture,
                unixtime => $unixtime,
                total => 1,
                };
                $$fracture2sample{$pattern_fracture} = $sample;
                return 1;
	}
	return undef;
}

sub get_mtime ($) {
	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
	    $atime,$mtime,$ctime,$blksize,$blocks) = stat $_[0];
	return $mtime;
}

#### sub-commands

sub build_patterns ($) {
	my ($this) = @_;
	my $WELLKNOWNSDIR = $$this{wellknowndir};
	my $CONFDIR;
	my $BINDIR;
	opendir my $d, $WELLKNOWNSDIR or do {
		die "$WELLKNOWNSDIR: cannot open, stopped";
	};
	my %mtime;
	my %option;
	while( my $e = readdir $d ){
		next if $e =~ m"^\.";
		if    ( $e =~ m"^([-\w]+)\.regexp$" ){
			my $mtime = get_mtime "$WELLKNOWNSDIR/$e";
			next unless $mtime > 0;
			$mtime{$1}->{pattern} = $mtime;
		}elsif( $e =~ m"^([-\w]+)\.rules$" ){
			my $mtime = get_mtime "$WELLKNOWNSDIR/$e";
			next unless $mtime > 0;
			$mtime{$1}->{src} = $mtime if
				not defined($mtime{$1}->{src}) or
				$mtime > $mtime{$1}->{src};
		}elsif( $e =~ m"^([-\w]+)(?:\+([-\w]+))?\.samples$" ){
			my $mtime = get_mtime "$WELLKNOWNSDIR/$e";
			next unless $mtime > 0;
			$mtime{$1}->{src} = $mtime if
				not defined($mtime{$1}->{src}) or
				$mtime > $mtime{$1}->{src};
			push @{ $option{$1} }, $2 if $2;
		}
	}
	close $d;

	while( my ($k, $v) = each %mtime ){
		my $samplefile	  = "$WELLKNOWNSDIR/$k.samples";
		my $rulefile	  = "$WELLKNOWNSDIR/$k.rules";
		my $regexpfile	  = "$WELLKNOWNSDIR/$k.regexp";
		my $diagnosisfile = "$WELLKNOWNSDIR/$k.diagnosis";
		
		my $cmd;
		unless( -f $samplefile ){
		        $cmd .= "cp /dev/null $samplefile ;";
		        print "$samplefile: created.\n";
		}
		unless( -f $rulefile ){
		        $cmd .= "cp $CONFDIR/rules.template $rulefile ;";
		        print "$rulefile: created.\n";
		}
		next if -f $regexpfile and $$v{src} < $$v{pattern};
		$cmd .= "$BINDIR/panopticfilter build";
		$cmd .= " -r $rulefile -d $diagnosisfile";
		$cmd .= " -o $regexpfile -f $samplefile";
		foreach my $i ( @{$option{$k} // []} ){
			$cmd .= " -e $i -f $WELLKNOWNSDIR/$k+$i.samples";
		}
		system "$cmd\n";
	}

	exit 0;
}

sub cmd_analyze ($$$$) {
	my ($this, $rulefile, $patternfile, $diagnosisfile, $statisticsfile) = @_;
	$| = 1;
	my ($rule_re, %mark2replace) = $this->read_rulefile( $rulefile );
	my $regexp = $this->read_patternfile( $patternfile ) if defined $patternfile;
	my $now = time;

	my $decoder = JSON::XS->new;
	while(<STDIN>){
		chomp;
		next if m"^\s*(#|$)";

		utf8::decode($_);
		my $obj = encode_obj $decoder->decode( $_ );
		my $unixtime = $$obj{unixtime};
		my $message  = $$obj{message};

		next if $message =~ m"^\s*(#|$)";
		next if defined $regexp and $message =~ m"$regexp"  && $+[0] == length($message);

		my $pattern_fracture = $this->generalize("pattern", $message);
		my $r = $this->add_sample( $message, $pattern_fracture, $unixtime );
		next unless $r;

		#print $diagnosisfh "$pattern_fracture\n" if $diagnosisfh;

	}
	#write_statisticsfile $statisticsfile, $stats;
	exit 0;
}

####

1;

 
