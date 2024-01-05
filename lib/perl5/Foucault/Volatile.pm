#

package Foucault::Volatile;

use strict;
use English;
use JSON::XS;
use Foucault::Common;

our $JSONENCODER = JSON::XS->new;

####

sub new ($$$) {
	my ($class, $concatdir, $trafficdir) = @_;
	die unless -d $concatdir;
	die unless -d $trafficdir;
	my %r = (
		'concatdir'   => $concatdir,
		'trafficdir'  => $trafficdir,
		'infologger'  => undef,
		'errorlogger' => undef,

		'concatbuffer' => {},
		'trafficstatus' => {},
		'trafficstatus_summary' => {},

		'trafficmonitor_viewpoints' => [],
	);
	return bless \%r;
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

#### concat buffer functions

sub load_concatbuffer ($) {
	my ($this) = @_;
	my $concatdir = $$this{concatdir};
	my $f = "$concatdir/concatbuffer.json";

	open my $h, '<', $f or do {
		$$this{concatbuffer} = {};
		return;
	};
	my $json = join '', <$h>;
	close $h;
	my $now = time;
	$$this{concatbuffer} = $JSONENCODER->decode( $json );
	while( my ($k, $v) = each %{$$this{concatbuffer}} ){
		foreach my $i ( @$v ){
			utf8::encode($i);
		}
	}
}

sub save_concatbuffer ($) {
	my ($this) = @_;
	my $concatdir = $$this{concatdir};
	my $f = "$concatdir/concatbuffer.json";

	my $log = $JSONENCODER->encode( $$this{concatbuffer} );
	open my $h, '>', $f or die;
	print $h "$log\n";
	close $h;
	return;
}

sub get_concatbuffer ($) {
	my ($this) = @_;
	return $$this{concatbuffer};
}

####

sub load_trafficstatus ($) {
	my ($this) = @_;
	my $trafficdir = $$this{trafficdir};
	my $f = "$trafficdir/trafficstatus.json";

	open my $h, '<', $f or do {
		$$this{concatbuffer} = {};
		return;
	};
	my $json = join '', <$h>;
	close $h;
	my $now = time;
	$$this{trafficstatus} = $JSONENCODER->decode( $json );
}

sub save_trafficstatus ($) {
	my ($this) = @_;
	my $trafficdir = $$this{trafficdir};
	my $f = "$trafficdir/trafficstatus.json";

	my $json = $JSONENCODER->encode( $$this{trafficstatus} );
	open my $h, '>', $f or die;
	print $h "$json\n";
	close $h;

	my $f = "$trafficdir/trafficstatus_summary.json";
	my $json = $JSONENCODER->encode( $$this{trafficstatus_summary} );
	open my $h, '>', $f or die;
	print $h "$json\n";
	close $h;
}

sub update_trafficstatus ($$$) {
	my ($this, $events, $out_changes) = @_;
	my $last_status = $$this{trafficstatus};
	my $curr_status = {};
	my $unixtime  = time;
	my $timestamp = timestamp;

	foreach my $event ( @$events ){
		my $detectorid       = $$event{detectorid};
		my $tag              = $$event{tag};
		my $viewpoint        = $$event{viewpoint};
		my $statusid         = "$detectorid $viewpoint $tag";
		$$curr_status{$statusid} = $event;
	}
	while( my ($statusid, $event) = each %$curr_status ){
		unless( exists $$last_status{$statusid} ){
			push @$out_changes, {
				'unixtime'   => $unixtime,
				'timestamp'  => $timestamp,
				'detectorid' => $$event{detectorid},
				'tag'        => $$event{tag},
				'viewpoint'  => $$event{viewpoint},
				'status'     => $$event{status},
				'old_status' => 'ok',
				'boundary'   => $$event{boundary},
			};
			next;
		}
		my $curr_viewpoint_status = $$event{status};
		my $last_viewpoint_status = $$last_status{$statusid}->{status};
		unless( $curr_viewpoint_status eq $last_viewpoint_status ){
			push @$out_changes, {
				'unixtime'   => $unixtime,
				'timestamp'  => $timestamp,
				'detectorid' => $$event{detectorid},
				'tag'        => $$event{tag},
				'viewpoint'  => $$event{viewpoint},
				'status'     => $curr_viewpoint_status,
				'old_status' => $last_viewpoint_status,
				'boundary'   => $$event{boundary},
			};
		}
	}
	while( my ($statusid, $event) = each %$last_status ){
		unless( exists $$curr_status{$statusid} ){
			push @$out_changes, {
				'unixtime'   => $unixtime,
				'timestamp'  => $timestamp,
				'detectorid' => $$event{detectorid},
				'tag'        => $$event{tag},
				'viewpoint'  => $$event{viewpoint},
				'status'     => 'ok',
				'old_status' => $$event{status},
				'boundary'   => $$event{boundary},
			};
			next;
		}
	}
	$$this{trafficstatus} = $curr_status;

	# build trafficstatus summary

	my %trafficstatus_summary = ( 'timestamp' => $timestamp, 'unixtime' => $unixtime );
	foreach my $viewpoint ( @{ $$this{trafficmonitor_viewpoints} } ){
		$trafficstatus_summary{$viewpoint} = 0;
	}
	foreach my $event ( @$events ){
		my $viewpoint = $$event{viewpoint};
		$trafficstatus_summary{$viewpoint}++;
	}
	$$this{trafficstatus_summary} = \%trafficstatus_summary;
}

sub set_trafficmonitor_viewpoints ($@) {
	my ($this, @viewpoints) = @_;
	@{ $$this{trafficmonitor_viewpoints} } = @viewpoints;
}

####

sub check ($) {
	my ($this) = @_;
	my $ok = 1;
	unless( -w $$this{concatdir} ){
		$this->errorlog("check: %s: cannot write.", $$this{concatdir});
		$ok = undef;
	}
	unless( -w $$this{trafficdir} ){
		$this->errorlog("check: %s: cannot write.", $$this{trafficdir});
		$ok = undef;
	}
	return $ok;
}

####

1;

