#

package Foucault::WellKnown;

use strict;
use English;
use JSON::XS;
use Regexp::Assemble;
use Foucault::Common;

our $REGMARK;

####

sub new ($) {
	my ($class) = @_;
	return bless {
		'infologger'   => undef,
		'errorlogger'  => undef,
		'wellknowndir' => undef,
		'rules' => {},
	};
}

####

sub infologger ($;$) {
	my ($this, $logger) = @_;
	return $$this{'infologger'} unless defined $logger;
	$$this{'infologger'} = $logger;
}

sub errorlogger ($;$) {
	my ($this, $logger) = @_;
	return $$this{'errorlogger'} unless defined $logger;
	$$this{'errorlogger'} = $logger;
}

sub infolog ($$;@) {
	my ($this, $format, @params) = @_;
	$$this{'infologger'}->write( $format, @params ) if defined $$this{'infologger'};
}

sub errorlog ($$;@) {
	my ($this, $format, @params) = @_;
	$$this{'errorlogger'}->write( $format, @params ) if defined $$this{'errorlogger'};
}

#### Setup functions

sub set_path_of_wellknowndir ($$) {
	my ( $this, $d ) = @_;
	die "$d: is not directory, stopped" unless -d $d;
	$$this{wellknowndir} = $d;
}

#### I/O functions

sub read_patternregexp_file_of ($$) {
	my ( $this, $pattern ) = @_;
	my $wellknowndir = $$this{wellknowndir};
	my $f = "$wellknowndir/$pattern.regexp";
	open my $h, '<', $f or do {
		print "read_patternregexp_file_of: $f: cannot read.\n";
		return undef;
	};
	my $mtime = mtime_of_fh $h;
	my $regexp_text = join '', <$h>;
	chomp $regexp_text;
	close $h;
	my $regexp;
	eval { $regexp = qr"^$regexp_text$"; };
	unless( defined $regexp ){
		print "read_patternregexp_file_of: $f: cannot compile.\n";
		return undef;
	}

	$$this{patternregexps}->{$pattern} = {
		'file'      => $f,
		'mtime'     => $mtime,
		'regexp'    => $regexp,
		'diagnosis' => undef,
	};
	return 1;
}

sub write_patternregexp_file_of ($$) {
	my ( $this, $pattern ) = @_;
	my $wellknowndir = $$this{wellknowndir};
	my $regexp = $$this{patternregexps}->{$pattern}->{regexp};

	my $f = "$wellknowndir/$pattern.regexp";
	open my $h, '>', $f or do {
		print "write_patternregexp_file_of: $f: cannot write.\n";
		return undef;
	};
	print $h "$regexp\n";
	close $h;

	$$this{patternregexps}->{$pattern}->{file}  = $f;
	$$this{patternregexps}->{$pattern}->{mtime} = time;
	return 1;
}

sub create_patternregexp_file_of ($$) {
	my ( $this, $pattern ) = @_;
	my $wellknowndir = $$this{wellknowndir};
	my $src = "$wellknowndir/template_of_regexp";
	my $dst = "$wellknowndir/$pattern.regexp";
	system "cp -p \"$src\" \"$dst\"";
	$this->read_patternregexp_file_of($pattern);
}

sub read_generalizerules_file_of ($$) {
	my ( $this, $pattern ) = @_;
	my $wellknowndir = $$this{wellknowndir};
	my $f = "$wellknowndir/$pattern.rules";
	open my $h, '<', $f or do {
		print "read_generalizerules_file_of: $f: cannot read.\n";
		return undef;
	};
	my $mtime = mtime_of_fh $h;

	my $mark = "rule0000";
	my $lastmark;
	my %mark2replace;
	my @regexps;
	while( <$h> ){
		chomp;
		s{^\s*}{}g;
		next if m{^\s*($|#)};
		my @c = split m{\s+};
		if( m"^\s*(ignore|replace)\s+(\S.*)$" ){
			my $pattern = $2;
			eval { qr"$pattern"; };
			unless( $@ eq "" ){
				$this->errorlog( "$f:$.: syntax error." );
				$this->errorlog( "$f:$.: %s", $@ );
				next;
			}
			push @regexps, "$pattern(*:$mark)";
			$mark2replace{$mark} = $pattern;
			$lastmark = $mark;
			$mark++;
		}elsif( m"^\s*(as|with)\s+(\S.*)$" ){
			my $pattern = $2;
			eval { qr"$pattern"; };
			unless( $@ eq "" ){
				$this->errorlog( "$f:$.: syntax error." );
				$this->errorlog( "$f:$.: %s", $@ );
				next;
			}
			$mark2replace{$lastmark} = $pattern;
		}else{
			die "$f:$.: illegal format, stopped";
		}
	}
	close $h;
	my $regexp_text = "(" . join("|", @regexps) . ")";
	my $regexp;
	eval { $regexp = qr"$regexp_text"; };
	unless( defined $regexp ){
		print "read_generalizerules_file_of: $f: cannot compile.\n";
		return undef;
	}

	$$this{generalizerules}->{$pattern} = {
		'file'         => $f,
		'mtime'        => $mtime,
		'regexp'       => $regexp,
		'mark2replace' => \%mark2replace,
	};
	return 1;
}

sub create_generalizerules_file_of ($$) {
	my ( $this, $pattern ) = @_;
	my $wellknowndir = $$this{wellknowndir};
	my $src = "$wellknowndir/template_of_rules";
	my $dst = "$wellknowndir/$pattern.rules";
	system "cp -p \"$src\" \"$dst\"";
	$this->read_generalizerules_file_of($pattern);
}

sub read_samples_file_of ($$) {
	my ( $this, $pattern ) = @_;
	my $wellknowndir = $$this{wellknowndir};

	opendir my $d, $wellknowndir or do {
		die "$wellknowndir: cannot open, stopped";
	};

	my %set_of_samples;
	while( my $e = readdir $d ){
		next if $e =~ m"^\.";
		next unless -f "$wellknowndir/$e";
		next unless $e =~ m"^([-\w]+)(?:\+([-\w]+))?\.samples$";
		my $patternname = $1;
		my $eventname   = $2 eq "" ? "50WELLKNOWN" : $2;
		next unless $patternname eq $pattern;

		open my $h, '<', "$wellknowndir/$e" or do {
			print "read_regexpfile: $wellknowndir/$e: cannot read.\n";
			return undef;
		};
		my $mtime = mtime_of_fh $h;
		my @texts;
		while( <$h> ){ chomp; push @texts, $_; }
		close $h;

		$set_of_samples{$eventname} = {
			'event' => $eventname,
			'file'  => "$wellknowndir/$e",
			'mtime' => $mtime,
			'texts' => \@texts,
		};
	}
	close $d;

	return undef unless %set_of_samples;

	$$this{samples}->{$pattern} = \%set_of_samples;
	return 1;
}

sub create_samples_file_of ($$) {
	my ( $this, $pattern ) = @_;
	my $wellknowndir = $$this{wellknowndir};
	my $src = "$wellknowndir/template_of_samples";
	my $dst = "$wellknowndir/$pattern.samples";
	system "cp -p \"$src\" \"$dst\"";
	$this->read_samples_file_of($pattern);
}

sub write_diagnosis_file_of ($$) {
	my ( $this, $pattern ) = @_;
	my $wellknowndir = $$this{wellknowndir};
	my $diagnosis = $$this{patternregexps}->{$pattern}->{diagnosis};

	my $f = "$wellknowndir/$pattern.diagnosis";
	open my $h, '>', $f or do {
		print "write_patternregexp_file_of: $f: cannot write.\n";
		return undef;
	};
	my $encoder = JSON::XS->new->pretty(1)->indent(4)->space_after(1)->canonical(1);
	my $diagnosis_json = $encoder->encode($diagnosis);

	print $h "$diagnosis_json\n";
	close $h;
	return 1;
}

####

sub get_patternregexp_of ($$) {
	my ( $this, $pattern ) = @_;
	my $regexp = $$this{patternregexp}->{$pattern}->{regexp};
	return $$this{patternregexps}->{$pattern}->{regexp};
}

sub get_mtime_of_patternregexp_of ($$) {
	my ( $this, $pattern ) = @_;
	return $$this{patternregexps}->{$pattern}->{mtime};
}

sub get_generalizeregexp_of ($$) {
	my ( $this, $pattern ) = @_;
	return $$this{generalizerules}->{$pattern}->{regexp};
}

sub get_mtime_of_generalizeregexp_of ($$) {
	my ( $this, $pattern ) = @_;
	return $$this{generalizerules}->{$pattern}->{mtime};
}

sub get_samples_of ($$) {
	my ( $this, $pattern ) = @_;
	return $$this{samples}->{$pattern};
}

sub get_mtime_of_samples_of ($$) {
	my ( $this, $pattern ) = @_;

	my $set_of_samples = $$this{samples}->{$pattern};
	return undef unless defined $set_of_samples;

	my $latest_mtime;
	while( my ($eventname, $samples) = each %$set_of_samples ){
		$latest_mtime = $$samples{mtime} if $$samples{mtime} > $latest_mtime;
	}
	return $latest_mtime;
}

####

sub generalize ($$$) {
	my ($this, $patternname, $sample) = @_;
	my $rule = $$this{generalizerules}->{$patternname};
	die "$patternname: not defined, stopped" unless defined $rule;

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

sub compile_as_fracture ($$$$) {
	my ($this, $pattern, $samples, $out_diagnosis) = @_;
	my $file  = $$samples{file};
	my $event = $$samples{event};
	my $texts = $$samples{texts};

	my $optimize = 1;
	my $ra = Regexp::Assemble->new;

	my %generalized_text_cache;
	my @generalized_texts;
	my @generalized_regexps;

	my $linenum = 0;
	foreach my $text ( @$texts ){
		$linenum++;

		next if $text =~ m"^\s*$";
		next if $text =~ m"^\s*#";

		my $generalized_text = $this->generalize($pattern, $text);
		next if $generalized_text_cache{$generalized_text};
		next if match_regexps $text, \@generalized_regexps;

		eval {
			my $regexp = qr"^$generalized_text$";
			push @generalized_texts,   $generalized_text;
			push @generalized_regexps, $regexp;
			$generalized_text_cache{$generalized_text} = 1;
		};
		if( $@ ){
			$this->errorlog("$file:$linenum: cannot compile.");
			die "$file:$linenum: cannot compile, stopped";
		}

		$ra->add( $generalized_text ) if $optimize;
		push @$out_diagnosis, {
			"pattren"     => $pattern,
			"event"       => $event,
			"file"        => $file,
			"linenum"     => $linenum,
			"sample"      => $text,
			"generalized" => $generalized_text,
		}
	}

	my $regexp = $optimize ? $ra : "(?:" . join('|', @generalized_texts) . ")";
	return "$regexp(*:$event)";
}

sub compile ($$) {
	my ($this, $pattern) = @_;

	my $generalize_regexp = $this->get_generalizeregexp_of( $pattern );
	my $set_of_samples    = $this->get_samples_of( $pattern );
	my $diagnosis         = [];

	my @regexp_fractures;
	foreach my $eventname ( sort keys %$set_of_samples ){
		my $samples = $$set_of_samples{$eventname};
		my $regexp_fracture = $this->compile_as_fracture($pattern, $samples, $diagnosis);
		push @regexp_fractures, $regexp_fracture;
	}

	my $regexp = "(" . join("|", @regexp_fractures) . ")";
	eval { qr"$regexp"; };
	if( $@ ){
		die;
	}
	
	$$this{patternregexps}->{$pattern}->{regexp} = $regexp;
	$$this{patternregexps}->{$pattern}->{mtime}  = time;
	$$this{patternregexps}->{$pattern}->{diagnosis} = $diagnosis;
}

####

1;

