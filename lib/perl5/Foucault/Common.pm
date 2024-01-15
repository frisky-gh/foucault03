#
package Foucault::Common;

use Exporter import;
our @EXPORT = (
	'expand_time_placeholders',
	'expand_named_placeholders',
	'quotemetaex',
	'mtime_of_fh',
	'timestamp',
	'unixtime2timestring',
	'timestring2unixtime',
	'compile_subnet_list',
	'check_subnet_list',
	'append_hashlist',
	'hash2ltsv',
	'ltsv2hash',
	'hash2json',
	'json2hash',
	'sendmail',
	'mkdir_or_die',
	'rm_r_or_die',
	'rsync_or_die',
	'link_or_die',
	'match_regexps',
	'capture_by_regexps',
	'capture_all_by_regexps',
	'common_set',
);

use strict;
use English;
use Socket;
use JSON::XS;
use Time::Local;
use Encode;
use MIME::EncWords ':all';
use MIME::QuotedPrint;

our $JSON_CODEC = JSON::XS->new;
our $SENDMAIL_EXE = '/usr/lib/sendmail';

#### string functions

sub expand_time_placeholders ($) {
	my ($t) = @_;
	my ($sec, $min, $hour, $day, $mon, $year) = localtime;
	$t =~ s{(%[ymdHMS]|\~)}{
		if   ( $1 eq '%y' ){ sprintf "%04d", $year+1900; }
		elsif( $1 eq '%m' ){ sprintf "%02d", $mon+1; }
		elsif( $1 eq '%d' ){ sprintf "%02d", $day; }
		elsif( $1 eq '%H' ){ sprintf "%02d", $hour; }
		elsif( $1 eq '%M' ){ sprintf "%02d", $min; }
		elsif( $1 eq '%S' ){ sprintf "%02d", $sec; }
		elsif( $1 eq '~' ) { $ENV{HOME}; }
	}eg;
	return $t;
}

sub expand_named_placeholders ($\%) {
	my ($t, $captures) = @_;
	$t =~ s{(?:<(\w+)>)}{
		$$captures{$1};
	}eg;
	return $t;
}

sub quotemetaex ($) {
	local $_ = shift;
	s{([\x24\x28-\x2b\x2e\x3f\x5b-\x5e\x7b-\x7d])}{\\$1}g;
	return $_;
}

sub mtime_of_fh ($) {
	my ($fh) = @_;
	my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $fh;
	return $mtime;
}

sub timestamp () {
	my ($sec,$min,$hour,$day,$mon,$year) = localtime time;
	return sprintf '%04d-%02d-%02d_%02d:%02d:%02d', $year+1900, $mon+1, $day, $hour, $min, $sec;
}

sub unixtime2timestring ($) {
	my ($sec, $min, $hour, $day, $mon, $year) = localtime shift;
	return sprintf "%04d-%02d-%02d_%02d:%02d",
		$year+1900, $mon+1, $day, $hour, $min;
}

sub timestring2unixtime ($) {
	my ($timestring) = @_;
	return undef unless $timestring =~ m"^(\d{4})-(\d{2})-(\d{2})_(\d{2}):(\d{2})$";
	return timelocal 0, $5, $4, $3, $2-1, $1;
}

sub compile_subnet ($) {
	my $subnet = shift;
	if( $subnet =~ m"^(\d+\.\d+\.\d+\.\d+)/(\d+)$" ){
		my $addr = $1;
		my $netbit = $2;
		my $bin_netmask = inet_aton '255.255.255.255';
		for( my $i = $netbit; $i < 32; ++$i ){ 
			vec($bin_netmask, $i, 1) = 0;
		}
		my $bin_addr = inet_aton $addr;
		my $bin_subnet = $bin_addr & $bin_netmask;
		return [$bin_addr, $bin_netmask];
	}elsif( $subnet =~ m"^(\d+\.\d+\.\d+\.\d+)$" ){
		my $bin_netmask = inet_aton '255.255.255.255';
		my $bin_addr = inet_aton $subnet;
		return [$bin_addr, $bin_netmask];
	}
	return undef;
}

sub compile_subnet_list ($) {
	my ($subnet_list) = @_;
	my @r;
	foreach my $subnet ( split m",", $subnet_list ){
		push @r, compile_subnet $subnet;
	}
	return @r;
}

sub check_subnet_list ($$) {
	my ($bin_addr, $allow_subnets) = @_;
	foreach my $subnet_netmask ( @$allow_subnets ){
		if( $$subnet_netmask[0] eq ($bin_addr & $$subnet_netmask[1]) ){
			return 1;
		}
	}
	return undef;
}

sub append_hashlist ($$) {
	my ($augend, $addend) = @_;
	while( my ($k, $v) = each %$addend ){
		push @{ $$augend{$k} }, @$v;
	}
}

sub sendmail ($$$) {
	my ($mail, $mailfrom, $mailto) = @_;
	my $from_quoted = quotemeta $mailfrom;
	my $to_quoted = quotemeta $mailto;
	my $enc = find_encoding "utf-8";

	open my $h, '|-', "$SENDMAIL_EXE -f $from_quoted $to_quoted" or do {
		die "$SENDMAIL_EXE: cannot execute, stopped";
	};
	chomp $mail;
	my @mail = split m"\n", $mail;
	while( 1 ){
		$_ = shift @mail;
		last if $_ eq '';

		my $text = encode_mimewords $_, Encoding => 'q', Charset => 'utf-8';
		print $h $text, "\n";
	}
	print $h "MIME-Version: 1.0\n";
	print $h "Content-Transfer-Encoding: quoted-printable\n";
	print $h "Content-Type: text/plain; charset=utf-8\n",
		"\n";
	while( 1 ){
		$_ = shift @mail;
		last unless defined $_;
		eval {
			my $tmp = $_;
			my $utf8 = $enc->decode($tmp, 1);
		};
		if( $@ ){
			s{[\x80-\xff]}{'$'.uc(unpack('H2',$&))}eg;
		}

		if( m"^[\x20-\x3c\x3e-\x7e]*$" ){
			print $h $_, "\n";
		}else{
			my $text = encode_qp($_);
			print $h $text, "\n";
		}
	}
	close $h;
}

sub mkdir_or_die ($) {
	my ($d) = @_;
	return if -d $d;
	mkdir $d or die "$d: cannot create, stopped";
}

sub rm_r_or_die ($) {
	my ($d) = @_;
	opendir my $h, $d or do { die "$d: cannot open, stopped"; };
	while( my $e = readdir $h ){
		next if $e =~ m"^(\.|\.\.)$";
		if   ( -f "$d/$e" ){ unlink "$d/$e" or die; }
		elsif( -l "$d/$e" ){ unlink "$d/$e" or die; }
		elsif( -d "$d/$e" ){ rm_r_or_die( "$d/$e" ); }
		else{ die "$d/$e: cannot remove, stopped"; }
	}
	close $h;
	rmdir $d or die "$d: cannot remove, stopped";
}

sub rsync_or_die ($$) {
	my ($src, $dst) = @_;
	my $r = system "rsync", "-aqSx", "$src/", "$dst/";
	if( ($r << 8) > 0 ){
		die "$dst: cannot rsync, stopped";
	}
}

sub link_or_die ($$) {
	my ($src, $dst) = @_;
	link $src, $dst or die "$dst: cannot create, stopped";
}

sub match_regexps ($$;$) {
	my ($text, $regexps, $if_undefined) = @_;
	return $if_undefined unless defined $regexps;
	return $if_undefined unless @$regexps;
	foreach my $regexp ( @$regexps ){
		return 1 if $text =~ $regexp;
	}
	return undef;
}

sub capture_by_regexps ($$;$$) {
	my ($text, $regexps, $if_undefined, $stop_at_first_hit) = @_;
	return $if_undefined unless defined $regexps;
	return $if_undefined unless @$regexps;
	my @captured;
	my $hit = undef;
	foreach my $regexp ( @$regexps ){
		next unless $text =~ $regexp;
		$hit = 1;
		push @captured, %+;
		last if $stop_at_first_hit;
	}
	return $hit, @captured;
}

sub capture_all_by_regexps ($$;$$) {
	my ($text, $regexps, $if_undefined, $stop_at_first_hit) = @_;
	return $if_undefined unless defined $regexps;
	return $if_undefined unless @$regexps;
	my %captured;
	my $hit = undef;
	foreach my $regexp ( @$regexps ){
		next unless $text =~ $regexp;
		$hit = 1;
		while( my ($k, $v) = each %- ){
			foreach my $i ( @$v ){ next if $i eq ""; $captured{$k} = $i; };
		}
		last if $stop_at_first_hit;
	}
	return $hit, %captured;
}

sub common_set ($$) {
	my ($left, $right) = @_;
	my %s;
	foreach my $i (@$left) { $s{$i} += 1; }
	foreach my $i (@$right){ $s{$i} += 2; }
	my (@left_only, @right_only, @common);
	while( my ($k, $v) = each %s ){
		if   ( $v == 1 ){ push @left_only,  $k; }
		elsif( $v == 2 ){ push @right_only, $k; }
		else	    { push @common,     $k; }
	}
	return \@left_only, \@right_only, \@common;
}

#### Read / Write / Encode / Decode

sub hash2ltsv ( \% ){
	my ($var) = @_;
	my @ltsv;
	push @ltsv, "host_service:".$var->{host_service} if defined $var->{host_service};
	foreach my $k ( sort {$a cmp $b} keys %$var ){
		next if $k eq 'host_service';
		push @ltsv, "$k:".$var->{$k};
	}
	return join "\t", @ltsv;
}

sub ltsv2hash ( $ ){
	my ($ltsv) = @_;
	my %var;
	foreach my $kv ( split m"\t", $ltsv ){
		$kv =~ m"^([-./\[\]\w]+):(.*)$" or do {
			next;
		};
		my $k = $1;
		my $v = $2;
		$var{$k} = $v;
	}
	return %var;
}

sub json2hash ($) {
	my ($json) = @_;
	return undef if $json =~ m"^\s*$";
	my $hash;
	utf8::decode($json);
	eval {
		$hash = $JSON_CODEC->decode( $json );
	};
	unless( defined $hash ){
		die "$@\n JSON->decode() failed: $json\n stopped" if $@;
		die "JSON->decode() returns undef: $json\n stopped";
	}
	return %$hash;
}

sub hash2json (\%) {
	my ($hash) = @_;
	return undef unless defined $hash;
	my $json = $JSON_CODEC->encode( $hash );
	return $json;
}

####

1;

