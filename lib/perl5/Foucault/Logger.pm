#

package Foucault::Logger;

use strict;
use Foucault::Common;

####

sub new ($$) {
	my ($class, $filehandle, $priority) = @_;
	$filehandle->autoflush;
	my %r = (
		'FH'       => $filehandle,
		'PRIORITY' => $priority,
	);
	return bless \%r;
}

#### logging functions

sub refresh ($) {
	my ($this) = @_;
}

sub write ($$;@) {
	my ($this, $format, @args) = @_;
	my $fh       = $$this{FH};
	my $priority = $$this{PRIORITY};
	my $t        = timestamp;
	printf $fh "$t [$priority] $format\n", @args;
}

####

1;

