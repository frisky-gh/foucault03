#

package Foucault::Runtime;

use strict;
use English;

use Foucault::Common;
use Foucault::Logger;
use Foucault::FileLogger;
use Foucault::JSONLogger;
use Foucault::LTSVLogger;
use Foucault::Configuration;
use Foucault::Monitor;
use Foucault::Filter;
use Foucault::TrafficVolume;
use Foucault::Volatile;
use Foucault::WellKnown;

our $REGMARK;

####

sub new ($$) {
	my ($class, $toolhome) = @_;
	return bless {
		'TOOLHOME' => $toolhome,
		'TRACE' => 0,
		'INFO'  => 0,
		'DEBUG' => 0,

		'tracelogger'  => undef,
		'infologger'   => undef,
		'errorlogger'  => undef,
		'accesslogger' => undef,
		'anomalydetectlogger' => undef,
		'trafficdetectlogger' => undef,
		'unmonitoredlogger'   => undef,

		'CONF'           => undef,
		'volatile'       => undef,
		'MONITOR'        => undef,
		'FILTER'         => undef,
		'traffic_volume' => undef,
		'wellknown'      => undef,
	};
}

####

sub infolog ($$;@) {
	my ($this, $format, @args) = @_;
	$$this{infologger}  ->write( $format, @args ) if defined $$this{infologger};
}

sub errorlog ($$;@) {
	my ($this, $format, @args) = @_;
	$$this{errorlogger} ->write( $format, @args );
}

sub accesslog ($$;@) {
	my ($this, $format, @args) = @_;
	$$this{accesslogger}->write( $format, @args );
}

sub tracelog ($$;@) {
	my ($this, $format, @args) = @_;
	$$this{tracelogger}->write( $format, @args ) if defined $$this{tracelogger};
}

sub infolog_as_parent ($$;@) {
	my ($this, $format, @args) = @_;
 	my $logger = $$this{infologger};
 	return unless defined $logger;
	$logger->refresh;
	$logger->write( $format, @args );
}

sub errorlog_as_parent ($$;@) {
	my ($this, $format, @args) = @_;
 	my $logger = $$this{errorlogger};
 	return unless defined $logger;
	$logger->refresh;
	$logger->write( $format, @args );
}

#### initial functions

sub setup_first ($) {
	my ($this) = @_;

	#### first setup
	my $infologger   = new Foucault::Logger *STDOUT, "INFO";
	my $errorlogger  = new Foucault::Logger *STDOUT, "ERROR";
	$$this{infologger}   = $infologger;
	$$this{errorlogger}  = $errorlogger;

	# init conf
	my $conf = Foucault::Configuration->new($$this{TOOLHOME});
	$$this{CONF} = $conf;

	# setup daemon conf
	$conf->infologger ($infologger);
	$conf->errorlogger($errorlogger);
	$conf->read_foucault03d_conf;

	# init volatile
	my $volatile = Foucault::Volatile->new($conf->get_path_of_concatdir, $conf->get_path_of_trafficdir);
	$$this{volatile} = $volatile;

	# init monitor
	my $monitor = Foucault::Monitor->new;
	$$this{MONITOR} = $monitor;

	# init filter
	my $filter = Foucault::Filter->new;
	$$this{FILTER} = $filter;

	# init traffic status
	my $traffic_volume = Foucault::TrafficVolume->new( $conf->get_path_of_trafficdir );
	$$this{traffic_volume} = $traffic_volume;

	# init wellkown
	my $wellknown = Foucault::WellKnown->new;
	$$this{wellknown} = $wellknown;
}

sub setup_loggers ($) {
	my ($this) = @_;
	my $conf = $$this{CONF};

	# logger for system
	my $logfile = $conf->get_path_of_logfile;
	my $infologger   = $conf->is_recording_info  ? Foucault::FileLogger->new($logfile, "INFO")  : undef;
	my $errorlogger  = Foucault::FileLogger->new($logfile, "ERROR");
	my $tracelogger  = $conf->is_recording_trace ? Foucault::FileLogger->new($logfile, "TRACE") : undef;
	my $accesslogger = Foucault::FileLogger->new($logfile, "ACCESS");

	$$this{infologger}   = $infologger;
	$$this{errorlogger}  = $errorlogger;
	$$this{tracelogger}  = $tracelogger;
	$$this{accesslogger} = $accesslogger;

	my $unmonitoredlogfile      = $conf->get_path_of_unmonitoredlogfile;
	my $unmonitoredlogger       = Foucault::JSONLogger->new( $unmonitoredlogfile );
	$$this{unmonitoredlogger}   = $unmonitoredlogger;

	my $anomalydetectfile       = $conf->get_path_of_anomalydetectfile;
	my $anomalydetectlogger     = Foucault::JSONLogger->new( $anomalydetectfile );
	$$this{anomalydetectlogger} = $anomalydetectlogger;

	my $trafficdetectfile       = $conf->get_path_of_trafficdetectfile;
	my $trafficdetectlogger     = Foucault::JSONLogger->new( $trafficdetectfile );
	$$this{trafficdetectlogger} = $trafficdetectlogger;
}

sub setup_component_loggers ($) {
	my ($this) = @_;

	my $infologger  = $$this{infologger};
	my $errorlogger = $$this{errorlogger};
	my $tracelogger = $$this{tracelogger};

	my $conf = $$this{CONF};
	$conf->infologger ($infologger);
	$conf->errorlogger($errorlogger);

	my $volatile = $$this{volatile};
	$volatile->infologger ($infologger);
	$volatile->errorlogger($errorlogger);

	my $monitor = $$this{MONITOR};
	$monitor->infologger ($infologger);
	$monitor->errorlogger($errorlogger);
	$monitor->tracelogger($tracelogger);

	my $filter = $$this{FILTER};
	$filter->infologger ($infologger);
	$filter->errorlogger($errorlogger);

	my $traffic_volume = $$this{traffic_volume};
	$traffic_volume->infologger ($infologger);
	$traffic_volume->errorlogger($errorlogger);

	my $wellknown = $$this{wellknown};
	$wellknown->infologger ($infologger);
	$wellknown->errorlogger($errorlogger);
}

sub setup_confs ($) {
	my ($this) = @_;
	my $conf = $$this{CONF};

	$conf->read_concatfilter_conf;
	$conf->read_anomalymonitor_conf;
	$conf->read_transactionfilter_conf;
	$conf->read_trafficmonitor_conf;
}

sub setup_components ($) {
	my ($this) = @_;
	my $conf           = $$this{CONF};
	my $monitor        = $$this{MONITOR};
	my $filter         = $$this{FILTER};
	my $volatile       = $$this{volatile};
	my $traffic_volume = $$this{traffic_volume};
	my $wellknown      = $$this{wellknown};

	# get commons
	my @timespans = $conf->get_trafficmonitor_timespans;

	# setup monitor
	my @rules = $conf->get_anomalymonitor_rules;
	$monitor->set_anomalymonitor_rules( @rules );
	foreach my $timespan ( @timespans ){
		my @rules = $conf->get_trafficmonitor_rules( $timespan );
		$monitor->set_trafficmonitor_rules( $timespan, @rules );
	}
	$monitor->set_wellknown( $wellknown );

	# setup filter
	my $concatbuffer = $volatile->get_concatbuffer;
	$filter->set_concatbuffer( $concatbuffer );
	my @rules = $conf->get_concatfilter_rules;
	$filter->set_concatfilter_rules( @rules );
	my @rules = $conf->get_transactionfilter_rules;
	$filter->set_transactionfilter_rules( @rules );

	# setup volatile
	my @viewpoints = $conf->get_trafficmonitor_viewpoints;
	$volatile->set_trafficmonitor_viewpoints( @viewpoints );

	# setup traffic volume
	$traffic_volume->set_timespans( @timespans );

	# setup wellknown
	my $wellknowndir = $conf->get_path_of_wellknowndir;
	$wellknown->set_path_of_wellknowndir( $wellknowndir );
	my @patterns = $conf->get_anomalymonitor_patterns;
	foreach my $pattern ( @patterns ){
		$wellknown->read_patternregexp_file_of( $pattern );
	}
}

sub setup_as_tool ($) {
	my ($this) = @_;

	# first setup
	$this->setup_first;
	$this->setup_component_loggers;
}

sub setup_as_daemon ($) {
	my ($this) = @_;

	# first setup
	$this->setup_first;
	$this->setup_component_loggers;

	# second setup
	$this->setup_confs;
	$this->setup_components;
	die unless $this->check_components;
	$this->setup_loggers;
	$this->setup_component_loggers;
}

####

sub check_components {
	my ($this) = @_;
	my $conf           = $$this{CONF};
	my $monitor        = $$this{MONITOR};
	my $filter         = $$this{FILTER};
	my $volatile       = $$this{volatile};
	my $traffic_volume = $$this{traffic_volume};

	my $ok = 1;
	$ok &&= $monitor->check;	
	$ok &&= $filter->check;	
	$ok &&= $volatile->check;	
	$ok &&= $traffic_volume->check;	
	return $ok;
}

sub load_status ($) {
	my ($this) = @_;
	my $conf           = $$this{CONF};
	my $volatile       = $$this{volatile};
	my $traffic_volume = $$this{traffic_volume};
	my $monitor        = $$this{MONITOR};

	$volatile->load_concatbuffer;
	$volatile->load_trafficstatus;

	my $timespan2added = {};
	my $timespan2removed = {};
	$traffic_volume->load( $timespan2added, $timespan2removed );
	foreach my $timespan ( $conf->get_trafficmonitor_timespans ){
		my $added   = $$timespan2added  {$timespan};
		my $removed = $$timespan2removed{$timespan};
		$monitor->add_trafficmonitor_rulecache   ($timespan, $added);
		$monitor->remove_trafficmonitor_rulecache($timespan, $removed);
	}
}

sub save_status ($) {
	my ($this) = @_;
	my $conf           = $$this{CONF};
	my $volatile       = $$this{volatile};
	my $traffic_volume = $$this{traffic_volume};

	$volatile->save_concatbuffer;
	$volatile->save_trafficstatus;
	$traffic_volume->save;
}

####

sub write_pidfile ($) {
	my ($this) = @_;
	my $f = $$this{CONF}->{FOUCAULT03D_CONF}->{pidfile};
	open my $h, '>', $f or die;
	print $h "$$\n";
	close $h;
	return;
}

sub read_pidfile ($) {
	my ($this) = @_;
	my $f = $$this{CONF}->{FOUCAULT03D_CONF}->{pidfile};
	open my $h, '<', $f or return undef;
	my $pid = <$h>;
	close $h;
	return undef unless kill 0, $pid;
	return $pid;
}

####

sub content2tag2messages ($$) {
	my ($this, $content) = @_;
	my $filter = $$this{FILTER};
	return $filter->content2tag2messages( $content );
}

sub is_allowing_client_ipaddr ($$) {
	my ($this, $client_ipaddr) = @_;
	my $conf = $$this{CONF};
	return $conf->is_allowing_client_ipaddr($client_ipaddr);
}

sub write_anomaly_events ($$) {
	my ($this, $events) = @_;
	my $logger = $$this{anomalydetectlogger};
	foreach my $event ( @$events ){
		$logger->write( $event );
	}
}

sub write_unmonitored_messages ($$) {
	my ($this, $messages) = @_;
	my $logger = $$this{unmonitoredlogger};
	foreach my $message ( @$messages ){
		$logger->write( $message );
	}
}

sub write_traffic_changes ($$) {
	my ($this, $changes) = @_;
	my $logger = $$this{trafficdetectlogger};

	foreach my $change ( @$changes ){
		$logger->write( $change );
	}
}

####

sub passthrough_all_concatfilters ($$$) {
	my ( $this, $tag2messages,  $out_tag2concatmessages ) = @_;
	my $filter = $$this{FILTER};
	$filter->passthrough_all_concatfilters( $tag2messages, $out_tag2concatmessages );
}

sub passthrough_all_transactionfilters ($$$$$) {
	my ( $this, $redirectedmessages, $events, $unmonitored, $out_trxid2times ) = @_;
	my $filter = $$this{FILTER};
	$filter->passthrough_all_transactionfilters( $redirectedmessages, $events, $unmonitored, $out_trxid2times );
}

sub monitor_anomalies_repeatedly ($$$$$) {
	my ( $this, $tag2cmessages, $out_redirectedmessages, $out_events, $out_unmonitored ) = @_;
	my $monitor = $$this{MONITOR};
	$monitor->monitor_all_anomalies_repeatedly( $tag2cmessages, $out_redirectedmessages, $out_events, $out_unmonitored );
}

sub add_transactions ($$) {
	my ($this, $trxid2times) = @_;
	my $status = $$this{traffic_volume};
	$status->add_transactions($trxid2times);
}

sub keep_traffics ($$$) {
	my ($this, $out_timespan2added, $out_timespan2removed) = @_;
	my $traffic = $$this{traffic_volume};
	$traffic->add_new_slice   ($out_timespan2added);
	$traffic->remove_old_slice($out_timespan2removed);
}

sub monitor_traffics ($$$$) {
	my ($this, $timespan2added, $timespan2removed, $out_events) = @_;
	my $conf    = $$this{CONF};
	my $traffic = $$this{traffic_volume};
	my $monitor = $$this{MONITOR};
	my $logger  = $$this{trafficdetectlogger};

	foreach my $timespan ( $conf->get_trafficmonitor_timespans ){
		my $volume  = $traffic->get_volume( $timespan );
		my $added   = $$timespan2added  {$timespan};
		my $removed = $$timespan2removed{$timespan};
		$monitor->add_trafficmonitor_rulecache   ($timespan, $added);
		$monitor->remove_trafficmonitor_rulecache($timespan, $removed);

		$monitor->monitor_traffic_by_threshold( $volume, $out_events );
		$monitor->monitor_traffic_by_interval ( $out_events );
	}
}

sub update_trafficstatus ($$$) {
	my ($this, $buffer, $out_changes) = @_;
	my $volatile = $$this{volatile};
	$volatile->update_trafficstatus($buffer, $out_changes);;
}

sub get_daemon_user ($) {
	my ($this) = @_;
	my $conf = $$this{CONF};
	return $conf->get_daemon_user;
}

sub get_daemon_listen_addrport ($) {
	my ($this) = @_;
	my $conf = $$this{CONF};
	return $conf->get_daemon_listen_addrport;
}

####

sub refresh_loggers ($) {
	my ($this) = @_;

	## switch anomaly/traffic detect file, log file
	$$this{infologger}  ->refresh if defined $$this{infologger};
	$$this{errorlogger} ->refresh if defined $$this{errorlogger};
	$$this{tracelogger} ->refresh if defined $$this{tracelogger};
	$$this{accesslogger}->refresh if defined $$this{accesslogger};

	$$this{anomalydetectlogger}->refresh if defined $$this{anomalydetectlogger};
	$$this{trafficdetectlogger}->refresh if defined $$this{trafficdetectlogger};
	$$this{unmonitoredlogger}  ->refresh if defined $$this{unmonitoredlogger};
}

sub keep_filter ($) {
	my ($this) = @_;
	my $filter   = $$this{FILTER};

	$filter->keep_concatbuffer;
}

sub take_statistics_of_cache ($) {
	my ($this) = @_;
	my $filter  = $$this{FILTER};
	my $monitor = $$this{MONITOR};

	return (
		$filter->take_statistics_of_cache,
		$monitor->take_statistics_of_cache,
	);
}

sub reload_as_parent ($) {
	my ($this) = @_;
	my $conf = $$this{CONF};

	$conf->reload;
	$this->setup_components;
	die unless $this->check_components;
	$this->setup_loggers;
	$this->setup_component_loggers;
}

sub finalize ($) {
	my ($this) = @_;
	my $volatile = $$this{volatile};

        $volatile->save_concatbuffer;
}

####

1;

