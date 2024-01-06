#

package Foucault::FileLogger;

use strict;
use Foucault::Common;

####

sub new ($$$) {
	my ($class, $path_pattern, $priority) = @_;

	my $path = expand_time_placeholders $path_pattern;
	open my $fh, ">>", $path or die;
	$fh->autoflush;
	my %r = (
		'PATH_PATTERN' => $path_pattern,
		'PATH'         => $path,
		'FH'           => $fh,
		'PRIORITY'     => $priority,
	);
	return bless \%r;
}

#### logging functions

sub refresh ($) {
	my ($this) = @_;

	my $last_path = $$this{PATH};
	my $last_fh   = $$this{FH};

	my $path = expand_time_placeholders $$this{PATH_PATTERN};
	unless( $last_path eq $path ){
		close $last_fh if defined $last_fh;
		open my $fh, ">>", $path or die;
		$fh->autoflush;
		$$this{PATH} = $path;
		$$this{FH}   = $fh;
	}
}

sub write ($$;@) {
	my ($this, $format, @args) = @_;
	my $fh       = $$this{FH};
	my $priority = $$this{PRIORITY};
	my $t        = timestamp;
	printf $fh "$t [$$] [$priority] $format\n", @args;
}

####

1;

