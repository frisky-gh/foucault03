#

package Foucault::Monitor;

use strict;
use Foucault::Common;

our $REGMARK;

####

sub new ($) {
	my ($class) = @_;
	return bless {
		'infologger'   => undef,
		'errorlogger'  => undef,
		'tracelogger'  => undef,

		'anomalymonitor_rules'                            => [],
		'anomalymonitor_rulecache'                        => {},

		'timespan2trafficmonitor_rules'                   => {},
		'timespan2trafficmonitor_rulecache_for_threshold' => {},
		'timespan2trafficmonitor_detectorid2status'       => {},
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

sub tracelogger ($;$) {
	my ($this, $logger) = @_;
	return $$this{'tracelogger'} unless defined $logger;
	$$this{'tracelogger'} = $logger;
}

sub infolog ($$;@) {
	my ($this, $format, @args) = @_;
	$$this{infologger}  ->write( $format, @args ) if defined $$this{infologger};
}

sub errorlog ($$;@) {
	my ($this, $format, @args) = @_;
	$$this{errorlogger} ->write( $format, @args ) if defined $$this{errorlogger};
}

sub tracelog ($$;@) {
	my ($this, $format, @args) = @_;
	$$this{tracelogger} ->write( $format, @args ) if defined $$this{tracelogger};
}

####

sub set_anomalymonitor_rules ($@) {
	my ( $this, @rules ) = @_;
	@{ $$this{anomalymonitor_rules} } = @rules;
}

sub get_anomalymonitor_rule ($$) {
	my ($this, $tag) = @_;
	my $rules = $$this{anomalymonitor_rules};
	my $cache = $$this{anomalymonitor_rulecache};

	if( exists $$cache{$tag} ){ return @{$$cache{$tag}}; }

	foreach my $rule ( @$rules ){
		my $name           = $$rule{name};
		my $targets        = $$rule{targets};
		my $pattern        = $$rule{pattern};
		my $pattern_regexp = $$rule{pattern_regexp};
		my $redirects      = $$rule{redirects};
		foreach my $target ( @$targets ){
			next unless $tag =~ m"$target";

			my $captures_from_tag = { %+ };
			$this->infolog("get_anomalymonitor_rule: $tag => $name");

			@{$$cache{$tag}} = ($name, $pattern, $pattern_regexp, $redirects, $captures_from_tag);
			return @{$$cache{$tag}};
		}
	}
	@{$$cache{$tag}} = (undef, undef, undef, undef, undef);
	return undef, undef, undef, undef, undef;
}

####

sub set_trafficmonitor_rules ($$@) {
	my ( $this, $timespan, @rules ) = @_;
	@{ $$this{timespan2trafficmonitor_rules}->{$timespan} } = @rules;
}

sub add_trafficmonitor_rulecache ($$$) {
	my ($this, $timespan, $added) = @_;

	my $rules = $$this{timespan2trafficmonitor_rules}->{$timespan};

	my $cache = $$this{timespan2trafficmonitor_rulecache_for_threshold}->{$timespan};
	unless( defined $cache ){
		$cache = {};
		$$this{timespan2trafficmonitor_rulecache_for_threshold}->{$timespan} = $cache;
	}

	while( my ($trxid, undef) = each %$added ){
		next if exists $$cache{$trxid};

		my @r;
		foreach my $rule ( @$rules ){
			my $targets    = $$rule{targets};
			next unless defined $targets;

			foreach my $target ( @$targets ){
				next unless $trxid =~ m"$target";
				push @r, $rule;
				last;
			}
		}
		$$cache{$trxid} = \@r;
	}

	my $detectorid2status = $$this{timespan2trafficmonitor_detectorid2status}->{$timespan};
	unless( defined $detectorid2status ){
		$detectorid2status = {};
		$$this{timespan2trafficmonitor_detectorid2status}->{$timespan} = $detectorid2status;
	}

	foreach my $rule ( @$rules ){
		my $detectorid = $$rule{detectorid};
		next unless defined $detectorid;
		my $targets    = $$rule{targets};
		next unless defined $targets;

		next unless $$rule{lower} > 0;

		my $status = $$detectorid2status{$detectorid};
		unless( defined $status ){
			$status = {
				'trxids' => {},
				'rule'   => $rule,
			};
			$$detectorid2status{$detectorid} = $status;
		}

		outside:
		foreach my $target ( @$targets ){
			while( my ($trxid, undef) = each %$added ){
				next unless $trxid =~ m"$target";
				$$status{trxids}->{$trxid} = 1;
				keys %$added;  # reset iterator of %$added
				last outside;
			}
		}
	}
}

sub remove_trafficmonitor_rulecache ($$$) {
	my ($this, $timespan, $removed) = @_;

	my $cache = $$this{timespan2trafficmonitor_rulecache_for_threshold}->{$timespan};
	if( defined $cache ){
		while( my ($trxid, undef) = each %$removed ){
			next if exists $$cache{$trxid};
			delete $$cache{$trxid};
		}
	}

	my $detectorid2status = $$this{timespan2trafficmonitor_detectorid2status}->{$timespan};
	if( defined $detectorid2status ){
		while( my ($detectorid, $status) = each %$detectorid2status ){
			while( my ($trxid, undef) = each %$removed ){
				delete $$status{trxids}->{$trxid};
			}
		}
	}
}

####

sub monitor_traffic_by_threshold ($$$) {
	my ($this, $volume, $events) = @_;
	
	my $unixtime  = time;
	my $timestamp = timestamp;
	
	my $timespan2rulecache = $$this{timespan2trafficmonitor_rulecache_for_threshold};
	while( my ($timespan, $rulecache) = each %$timespan2rulecache ){
		while( my ($trxid, $times) = each %$volume ){
			foreach my $rule ( @{ $$rulecache{$trxid} } ){
				my $detectorid = $$rule{detectorid};
				my $viewpoint  = $$rule{viewpoint};
				my $lower      = $$rule{lower};
				my $upper      = $$rule{upper};
				if    ( $lower ne '' and $times < $lower ){
					push @$events, {
						'detectorid'  => $detectorid,
						'viewpoint'   => $viewpoint,
						'boundary'    => "[$lower,$upper]",
						'status'      => 'underflow',
						'trxid'       => $trxid,
						'times'       => $times,
						'unixtime'    => $unixtime,
						'timestamp'   => $timestamp,
					};
				}elsif( $upper ne '' and $times > $upper ){
					push @$events, {
						'detectorid'  => $detectorid,
						'viewpoint'   => $viewpoint,
						'boundary'    => "[$lower,$upper]",
						'status'      => 'overflow',
						'trxid'       => $trxid,
						'times'       => $times,
						'unixtime'    => $unixtime,
						'timestamp'   => $timestamp,
					};
				}
			}
		}
	}
}

sub monitor_traffic_by_interval ($$) {
	my ($this, $events) = @_;
	
	my $unixtime  = time;
	my $timestamp = timestamp;
	
	my $timespan2detectorid2status = $$this{timespan2trafficmonitor_detectorid2status};
	while( my ($timespan, $detectorid2status) = each %$timespan2detectorid2status ){
		while( my ($detectorid, $status) = each %$detectorid2status ){
			my $trxids = $$status{trxids};
			next if %$trxids;

			my $rule      = $$status{rule};
			my $viewpoint = $$rule{viewpoint};
			my $lower     = $$rule{lower};
			my $upper     = $$rule{upper};
			push @$events, {
				'unixtime'    => $unixtime,
				'timestamp'   => $timestamp,
				'detectorid'  => $detectorid,
				'viewpoint'   => $viewpoint,
				'boundary'    => "[$lower,$upper]",
				'status'      => 'notseenrecently',
				'timespan'    => $timespan,
			};
		}
	}
}

####

sub redirect ($$$$$) {
	my ($this, $out_redirected_tag2cmessages, $event, $redirect_rules, %params) = @_;

	my $redirected = undef;
	foreach my $redirect_rule ( @$redirect_rules ){
		my $redirect_event   = $$redirect_rule{event};
		next unless $redirect_event eq $event;
		my $redirect_name    = $$redirect_rule{name};
		my $redirect_tag     = $$redirect_rule{tag};
		my $redirect_message = $$redirect_rule{message};
		my $tag_without_expansion     = $$redirect_rule{tag_without_expansion};
		my $message_without_expansion = $$redirect_rule{message_without_expansion};

		my $redirected_tag     = expand_named_placeholders $redirect_tag,     %params;
		my $redirected_message = expand_named_placeholders $redirect_message, %params;
		next if $redirected_tag     eq $tag_without_expansion;
		next if $redirected_message eq $message_without_expansion;
		push @{$$out_redirected_tag2cmessages{$redirected_tag}}, $redirected_message;

		$redirected = 1;
		$this->tracelog("monitor_anomaly: %s: redirected to %s.", $redirect_event, $redirected_tag);
	}
	return $redirected;
}

sub monitor_anomaly ($$$$$$) {
	my ($this, $tag, $cmessages, $out_redirected_tag2cmessages, $out_events, $out_unmonitored) = @_;
	my $unixtime  = time;
	my $timestamp = timestamp;

	my ($name, $pattern, $regexp, $redirect_rules, $captures_from_tag) = $this->get_anomalymonitor_rule($tag);
	unless( defined $name ){
		foreach my $message ( @$cmessages ){
			push @$out_unmonitored, {
				'unixtime'  => $unixtime,
				'timestamp' => $timestamp,
				'tag' => $tag,
				'message' => $message,
				'event' => 'UNMONITORED',
			};
		}
		return;
	}

	foreach my $m ( @$cmessages ){
		$this->tracelog( "monitor_anomaly: %s: check \"%s\"", $pattern, $m );
		my $event;
		unless( $m =~ m"$regexp" ){
			$event = "ANOMALY";
		}elsif( $+[0] == length($m) ){
			$event = $REGMARK;
		}else{
			$this->errorlog( "monitor_anomaly: %s:%s: %d != %d", $pattern, $REGMARK, $+[0], length($m) );
			$event = $REGMARK;
		}

		next if $event =~ m"WELLKNOWN";
		$this->tracelog( "monitor_anomaly: %s: %s: hit.", $pattern, $event );

		if( $redirect_rules ){
			next if $this->redirect( $out_redirected_tag2cmessages, $event, $redirect_rules, (%+, %$captures_from_tag) );
		}

		utf8::decode($m);
		push @$out_events, {
			'unixtime'  => $unixtime,
			'timestamp' => $timestamp,
			'tag'       => $tag,
			'message'   => $m,
			'event'     => $event,
			'pattern'   => $pattern,
		};
	}
}

sub monitor_all_anomalies ($$$$$) {
	my ($this, $tag2cmessages, $out_redirected_tag2cmessages, $out_events, $out_unmonitored) = @_;
	while( my ($tag, $cmessages) = each %$tag2cmessages ){
		$this->monitor_anomaly( $tag, $cmessages, $out_redirected_tag2cmessages, $out_events, $out_unmonitored );
	}
}

sub monitor_all_anomalies_repeatedly ($$$$$) {
	my ($this, $tag2cmessages, $out_redirected_tag2cmessages, $out_events, $out_unmonitored) = @_;

	append_hashlist $out_redirected_tag2cmessages, $tag2cmessages;
	my $i = 0;
	while( %$tag2cmessages ){
		unless( $i++ < 10 ){
			last;
		}
		my $out_tag2cmessages = {};
		$this->monitor_all_anomalies($tag2cmessages, $out_tag2cmessages, $out_events, $out_unmonitored);
		$tag2cmessages = $out_tag2cmessages;
		append_hashlist $out_redirected_tag2cmessages, $out_tag2cmessages;
	}
}

####

sub check ($) {
	my ($this) = @_;
	return 1;
}

####

1;

