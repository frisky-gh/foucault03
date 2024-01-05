#

package Foucault::TrafficVolume;

use Carp::Always;
use English;
use JSON::XS;
use strict;
use Foucault::Common;

our $JSONENCODER = JSON::XS->new;

####

sub new ($$) {
	my ($class, $trafficdir) = @_;

	my $now = time;
	my $mod = $now % 60;
	my $datetime = $now - $mod;

	my %r = (
		'trafficdir'  => $trafficdir,
		'infologger'  => undef,
		'errorlogger' => undef,

		# timeline is a list of timeslice
		'LATEST_DATETIME'   => $datetime,
		'LATEST_SLICE'      => {
			'datetime'           => $datetime,
			'volume'             => {},
		},
		'TIMESPAN2TIMELINE' => {},
		'TIMESPAN2VOLUME'   => {},
		'timespans'         => [],
		'longesttimespan'   => undef,
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

#### initialize functions

sub set_timespans ($@) {
	my ($this, @timespans) = @_;
	@{ $$this{timespans} } = sort {$a <=> $b} @timespans;
	$$this{longesttimespan} = $$this{timespans}->[-1];

	my $timespan2timeline = $$this{TIMESPAN2TIMELINE};
	my $timespan2volume   = $$this{TIMESPAN2VOLUME};
	foreach my $timespan (@timespans) {
		$$timespan2timeline{$timespan} = [];
		$$timespan2volume  {$timespan} = {};
	}
}

#### traffic monitor functions

# traffic timeslice on timeID=[YYYY-MM-DD HH:MM]  
#     YYYY-MM-DD HH:MM:00 -----+-- traffic timeslice
#     ...                      |
#     ...                      |
#     ...                      |
#     YYYY-MM-DD HH:MM:59 -----+
#
# traffic timeslice epoch on [YYYY-MM-DD HH:MM] is "YYYY-MM-DD HH:MM:00"
#
# timeline is a aggregation of timeslices
#     traffic timeslice [time01] --+-- traffic timeline
#     traffic timeslice [time02]   |
#     traffic timeslice [time03]   |
#     ...                          |
#     traffic timeslice [timeNN] --+
# 
# traffic timeslice[time01]
#  + traffic timeslice[time02]
#  + ...
#  + traffic timeslice[timeNN] = traffic total
#
#

sub remove_timeslicefile ($$) {
	my ($this, $timeid) = @_;
	my $trafficdir = $$this{trafficdir};
	my $timestring = unixtime2timestring $timeid;
	my $f = "$trafficdir/$timestring.traffic";
	unlink $f if -f $f;
}

sub save_timeslicefile ($$$) {
	my ($this, $datetime, $volume) = @_;
	my $trafficdir = $$this{trafficdir};
	my $timestring = unixtime2timestring $datetime;
	my $f = "$trafficdir/$timestring.traffic";
	open my $h, ">", $f or die;
	foreach my $name ( sort keys %$volume ){
		my $value = $$volume{$name};
		print $h "$name	$value\n";
	}
	close $h;
}

sub load_timeslicefile ($$) {
	my ($this, $datetime) = @_;
	my $trafficdir = $$this{trafficdir};
	my $timestring = unixtime2timestring $datetime;
	my $f = "$trafficdir/$timestring.traffic";

	my %volume;
	open my $h, "<", $f or die "$f: cannot load, stopped";
	while( <$h> ){
		chomp;
		next unless m"^(\S+)\s+(\d+)";
		$volume{$1} = $2;
	}
	close $h;
	return \%volume;
}

sub list ($) {
	my ($this) = @_;
	my $trafficdir = $$this{trafficdir};
	opendir my $h, $trafficdir or die;
	my @r;
	while( my $e = readdir $h ){
		next unless $e =~ m"^(\d{4}-\d{2}-\d{2}_\d{2}:\d{2})\.traffic$";
		my $datetime_string = $1;
		my $datetime = timestring2unixtime $datetime_string;
		push @r, $datetime;
	}
	close $h;
	return sort @r;
}

sub save ($) {
	my ($this) = @_;

	$this->save_timeslicefile( $$this{LATEST_DATETIME}, $$this{LATEST_SLICE}->{volume} );
}

sub load ($$$) {
	my ($this, $out_timespan2added, $out_timespan2removed) = @_;
	my $now = time;
	my $mod = $now % 60;
	my $curr_datetime = $now - $mod;
	my @datetime = $this->list;
	my $longesttimespan = $$this{longesttimespan};
	my $timespans = $$this{timespans};
	my $timespan2volume = $$this{TIMESPAN2VOLUME};

	$this->infolog("load: load time slice files...");
	foreach my $datetime ( @datetime ){
		my $timestring = unixtime2timestring $datetime;

		if( $datetime < $curr_datetime - $longesttimespan ){
			$this->remove_timeslicefile($datetime);
			$this->infolog("load: $timestring: removed.");
			next;
		}

		my $loaded_volume = $this->load_timeslicefile($datetime);
		$this->add_slice( $out_timespan2added, $datetime, $loaded_volume );
		$this->infolog("load: $timestring: loaded.");
	}
	$this->infolog("load: maintenance each timelines...");
	$this->remove_old_slice($out_timespan2removed);
}

####

sub add_slice ($$$) {
	my ($this, $out_timespan2added, $added_datetime, $added_volume) = @_;

	my $latest_datetime = $$this{LATEST_DATETIME};
	my $latest_slice    = $$this{LATEST_SLICE};
	my $timespans       = $$this{timespans};

	my $added_slice = {
		'datetime'           => $added_datetime,
		'volume'             => $added_volume,
	};
	$$this{LATEST_DATETIME} = $added_datetime;
	$$this{LATEST_SLICE}    = $added_slice;

	return unless defined $latest_slice;

	my $latest_volume = $$latest_slice{volume};
	my $timespan2timeline = $$this{TIMESPAN2TIMELINE};
	my $timespan2volume   = $$this{TIMESPAN2VOLUME};
	foreach my $timespan ( @$timespans ){
		my $timeline = $$timespan2timeline{$timespan};
		my $volume   = $$timespan2volume{$timespan};
		my $added    = $$out_timespan2added{$timespan};
		unless( $added ){
			$added = {};
			$$out_timespan2added{$timespan} = $added;
		}
		push @$timeline, $latest_slice;
		while( my ($latest_trxid, $latest_times) = each %$latest_volume ){
			my $already_existed = 1 if defined $$volume{$latest_trxid};
			$$volume{$latest_trxid} += $latest_times;
			next if $already_existed;
			$$added{$latest_trxid} = 1;
		}
	}
}

sub add_new_slice ($$) {
	my ($this, $out_timespan2added) = @_;
	my $now = time;
	my $mod = $now % 60;
	my $new_datetime = $now - $mod;

	my $latest_datetime = $$this{LATEST_DATETIME};
	my $latest_slice    = $$this{LATEST_SLICE};

	return unless $latest_datetime < $new_datetime;

	$this->save_timeslicefile($latest_datetime, $$latest_slice{volume});
	$this->add_slice( $out_timespan2added, $new_datetime, {} );
}

sub remove_old_slice ($$) {
	my ($this, $out_timespan2removed) = @_;
	my $now = time;
	my $mod = $now % 60;
	my $new_datetime = $now - $mod;

	my $timespan2timeline = $$this{TIMESPAN2TIMELINE};
	my $timespan2volume   = $$this{TIMESPAN2VOLUME};
	my $timespans         = $$this{timespans};
	my $longesttimespan   = $$this{longesttimespan};

	foreach my $timespan ( @$timespans ){
		my $timeline = $$timespan2timeline{$timespan};
		my $volume   = $$timespan2volume{$timespan};
		my $removed  = $$out_timespan2removed{$timespan};
		unless( $removed ){
			$removed = {};
			$$out_timespan2removed{$timespan} = $removed;
		}

		while( @$timeline ){
			my $datetime = $$timeline[0]->{datetime};
			my $elapsed  = $new_datetime - $datetime;
			my $elapsed_min = int( $elapsed / 60 );
			last if $elapsed <= $timespan;

			my $expired_slice = shift @$timeline;
			my $expired_volume = $$expired_slice{volume};
			while( my ($expired_trxid, $expired_times) = each %$expired_volume ){
				$$volume{$expired_trxid} -= $expired_times;
				next unless $$volume{$expired_trxid} <= 0;
				delete $$volume{$expired_trxid};
				$$removed{$expired_trxid} = 1;
			}

			next unless $timespan == $longesttimespan;
			$this->remove_timeslicefile( $datetime );
			$this->infolog( "remove_old_slice: $timespan: expire slice $datetime. ($elapsed_min min elapsed)" );
		}
	}
}

sub get_volume ($$) {
	my ($this, $timespan) = @_;
	return $$this{TIMESPAN2VOLUME}->{$timespan};
}

sub add_transactions ($$) {
	my ($this, $trxid2times) = @_;
	my $latest_volume = $$this{LATEST_SLICE}->{volume};
	while( my ($trxid, $times) = each %$trxid2times ){
		$$latest_volume{$trxid} += $times;
	}
}

####

sub check ($) {
	my ($this) = @_;
	my $ok = 1;
	unless( -w $$this{trafficdir} ){
		$this->errorlog("check: %s: cannot write.", $$this{trafficdir});
		$ok = undef;
	}
	return $ok;
}

####

1;

