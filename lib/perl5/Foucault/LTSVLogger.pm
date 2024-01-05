#

package Foucault::LTSVLogger;

use strict;
use Encode;
use Foucault::Common;

####

sub new ($$) {
	my ($class, $path_pattern) = @_;

	my $path = expand_path $path_pattern;
	open my $fh, ">>", $path or die;
	$fh->autoflush;
	my %r = (
		'PATH_PATTERN' => $path_pattern,
		'PATH'         => $path,
		'FH'           => $fh,
	);
	return bless \%r;
}

#### logging functions

sub refresh ($) {
	my ($this) = @_;

	my $last_path = $$this{PATH};
	my $last_fh   = $$this{FH};

	my $path = expand_path $$this{PATH_PATTERN};
	unless( $last_path eq $path ){
		close $last_fh if defined $last_fh;
		open my $fh, ">>", $path or die;
		$fh->autoflush;
		$$this{PATH} = $path;
		$$this{FH}   = $fh;
	}
}

sub write ($$) {
	my ($this, $obj) = @_;
	my $fh       = $$this{FH};

	my @ltsv;
	foreach my $k ( sort keys %$obj ){
		my $v = $$obj{$k};
		push @ltsv, "$k:$v";
	}
	my $ltsv = join "\t", @ltsv;
	my $timestamp = timestamp;
	print $fh "timestamp:$timestamp	$ltsv\n";
}

####

1;

