#

package Foucault::Configuration;

use strict;
use English;
use Socket;
use IO::Handle;

use Foucault::Common;
use Foucault::WellKnown;

####

sub new ($$) {
	my ($class, $toolhome) = @_;
	$toolhome = "." unless defined $toolhome;
	return bless {
		'TOOLHOME' => $toolhome,

		'foucault03d_conf_path'       => "$toolhome/conf/foucault03d.conf",
		#'foucault03d_conf_path'       => "$toolhome/conf/foucault03d_new.conf",
		'anomalymonitor_conf_path'    => "$toolhome/conf/anomalymonitor.conf",
		'concatfilter_conf_path'      => "$toolhome/conf/concatfilter.conf",
		'trafficmonitor_conf_path'    => "$toolhome/conf/trafficmonitor.conf",
		'transactionfilter_conf_path' => "$toolhome/conf/transactionfilter.conf",
		'FOUCAULT03D_CONF'       => {},
		'ANOMALYMONITOR_CONF'    => {},
		'CONCATFILTER_CONF'      => {},
		'TRAFFICMONITOR_CONF'    => {},
		'transactionfilter_message_rules' => {},
		'transactionfilter_event_rules'   => {},
		'trafficmonitor_timespans' => [],
		'trafficmonitor_viewpoints' => [],

		'report_conf_path' => "$toolhome/conf/report.conf",
		'report_conf'      => undef,

		'infologger'  => undef,
		'errorlogger' => undef,
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

#### file I/O functions

sub read_regexpfile ($$) {
	my ( $this, $f ) = @_;
	open my $h, '<', $f or do {
		$this->infolog("read_regexpfile: $f: cannot read.");
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
		$this->infolog("read_regexpfile: $f: cannot compile.");
		return undef, undef;
	}
	return $regexp_compiled, $mtime;
}

sub read_foucault03d_conf ($;$) {
	my ($this, $conffile) = @_;
	$$this{foucault03d_conf_path} = $conffile if     defined $conffile;
	$conffile = $$this{foucault03d_conf_path} unless defined $conffile;
	my $toolhome = $$this{TOOLHOME};

	my %conf = (
		'listen_address' => '0.0.0.0',
		'listen_port'	=> 46847,
		'daemon_user'	=> '-',
		'allow' 	=> "0.0.0.0/0",
		'TRACE' 	=> 0,
		'INFO'  	=> 0,
		'DEBUG' 	=> 0,
		'logfile'		=> "$toolhome/log/foucault03d.log.%y-%m-%d",
		'unmonitoredlogfile'	=> "$toolhome/log/unmonitored.%y-%m-%d",
		'anomalydetectfile'	=> "$toolhome/log/anomaly.%y-%m-%d",
		'trafficdetectfile'	=> "$toolhome/log/traffic.%y-%m-%d",
		'trafficltsvfile'	=> "$toolhome/log/traffic.ltsv",
		'trafficdir'		=> "$toolhome/status",
		'concatdir'		=> "$toolhome/status",
		'pidfile'		=> "$toolhome/run/foucault03d.pid",
		'wellknowndir'		=> "$toolhome/conf",
	);

	open my $h, '<', $conffile or do {
		die "cannot open $conffile: $OS_ERROR, stopped";
	};
	while (<$h>) {
		next if m"^\s*(#|$)";
		die "$conffile:$.: illegal format, stopped" unless m"^(\w+)=(.*)$";
		die "$conffile:$.: unknown parameter, stopped" unless exists $conf{$1};
		$conf{$1} = $2;
	}
	close $h or do {
		die "close failed for $conffile: $OS_ERROR, stopped";
	};

	$conf{ALLOWLIST} = [ compile_subnet_list $conf{allow} ];

	$$this{TRACE} = $conf{TRACE};
	$$this{INFO}  = $conf{INFO};
	$$this{DEBUG} = $conf{DEBUG};
	$$this{FOUCAULT03D_CONF} = \%conf;
	return 1;
}

sub read_foucault03d_conf_as_reload ($) {
	my ($this) = @_;
	my $conf = $$this{FOUCAULT03D_CONF};

	my %backup_conf = (
		'listen_address' => undef,
		'listen_port'	 => undef,
		'daemon_user'	 => undef,
		'trafficdir'     => undef,
		'concatdir'      => undef,
		'pidfile'        => undef,
		'wellknowndir'   => undef,
	);

	while( my ($k, $v) = each %backup_conf ){
		$backup_conf{$k} = $$conf{$k};
	}
	$this->read_foucault03d_conf;
	while( my ($k, $v) = each %backup_conf ){
		$$conf{$k} = $backup_conf{$k};
	}
}

sub read_concatfilter_conf ($;$) {
	my ($this, $conffile) = @_;
	$$this{concatfilter_conf_path} = $conffile if     defined $conffile;
	$conffile = $$this{concatfilter_conf_path} unless defined $conffile;

	my @conf;
	my $rule;
	open my $h, '<', $conffile or do {
		die "cannot open $conffile: $OS_ERROR, stopped";
	};
	while (<$h>) {
		next if m"^\s*(#|$)";
		if    ( m"^\s*concat_rule\s*$" ){
			$rule = {
				'name' => "$conffile:$.",
				'type' => 'pattern-first',
				'limit_line' => 100,
				'limit_time' => 10*60,
			};
			push @conf, $rule;
		}elsif( m"^\s*target\s+(\S.*)$" ){
			push @{$$rule{targets}}, qr"^($1)$";
		}elsif( m"^\s*pattern\s+(\S.*)$" ){
			push @{$$rule{patterns}}, qr"^($1)$";
		}elsif( m"^\s*type\s+(\S.*)$" ){
			$$rule{type} = $1;
		}else{
			$this->errorlog("$conffile:$.: illegal format, ignored.");
		}
	}
	close $h or do {
		die "close failed for $conffile: $OS_ERROR, stopped";
	};
	$$this{CONCATFILTER_CONF} = \@conf;
	return 1;
}

sub read_anomalymonitor_conf ($;$) {
	my ($this, $conffile) = @_;
	$$this{anomalymonitor_conf_path} = $conffile if     defined $conffile;
	$conffile = $$this{anomalymonitor_conf_path} unless defined $conffile;

	my @conf;
	my $rule;
	my $redirect;
	open my $h, '<', $conffile or do {
		die "cannot open $conffile: $OS_ERROR, stopped";
	};
	while (<$h>) {
		next if m"^\s*(#|$)";
		if    ( m"^\s*anomalymonitor_rule\s*$" ){
			$rule = {
				'name'           => "$conffile:$.",
				'targets'        => undef,
				'pattern'        => undef,
				'redirects'      => undef,
			};
			push @conf, $rule;
		}elsif( m"^\s*target\s+(\S.*)$" ){
			my $re;
			eval { $re = qr"^($1)$"; };
			if( $@ ){ die "$conffile:$.: $@, stopped"; }
			push @{$$rule{targets}}, $re;
		}elsif( m"^\s*pattern\s+(\S.*)$" ){
			$$rule{pattern}      = $1;
		}elsif( m"^\s*redirect\s+(\S.*)$" ){
			$redirect = {
				'name'    => "$conffile:$.",
				'event'   => $1,
				'tag'     => undef,
				'message' => undef,
				'tag_without_expansion'     => undef,
				'message_without_expansion' => undef,
			};
			push @{$$rule{redirects}}, $redirect;
		}elsif( m"^\s*tag\s+(\S.*)$" ){
			my $tag = $1;
			my %empty;
			$$redirect{tag} = $tag;
			my $expanded = expand_named_placeholders $tag, %empty;
			$$redirect{tag_without_expansion} = $tag eq $expanded ? undef : $expanded;

		}elsif( m"^\s*message\s+(\S.*)$" ){
			my $message = $1;
			my %empty;
			$$redirect{message} = $message;
			my $expanded = expand_named_placeholders $message, %empty;
			$$redirect{message_without_expansion} = $message eq $expanded ? undef : $expanded;
		}else{
			$this->errorlog("$conffile:$.: illegal format, ignored.");
		}
	}
	close $h or do {
		die "close failed for $conffile: $OS_ERROR, stopped";
	};
	$$this{ANOMALYMONITOR_CONF} = \@conf;
	return 1;
}

sub read_transactionfilter_conf ($;$) {
	my ($this, $conffile) = @_;
	$$this{transactionfilter_conf_path} = $conffile if     defined $conffile;
	$conffile = $$this{transactionfilter_conf_path} unless defined $conffile;
	my @message_rules;
	my @event_rules;
	my $rule;
	open my $h, '<', $conffile or do {
		die "cannot open $conffile: $OS_ERROR, stopped";
	};
	while (<$h>) {
		next if m"^\s*(#|$)";
		if    ( m"^\s*(transaction_rule|transaction_rule_for_message)\s*$" ){
			$rule = {
				'name' => "$conffile:$.",
				'input_if_tag_matches'     => [],
				'input_if_message_matches' => [],
			};
			push @message_rules, $rule;

		}elsif( m"^\s*transaction_rule_for_event\s*$" ){
			$rule = {
				'name' => "$conffile:$.",
				'input_if_tag_matches'     => [],
				'input_if_message_matches' => [],
				'input_if_event_matches'   => [],
				'input_if_pattern_matches' => [],
			};
			push @event_rules, $rule;

		}elsif( m"^\s*(input|tag_pattern|input_if_tag_matches)\s+(\S.*)$" ){
			my $re;
			eval { $re = qr"^($2)$"; };
			if( $@ ){ die "$conffile:$.: $@, stopped"; }
			push @{$$rule{input_if_tag_matches}}, $re;

		}elsif( m"^\s*(message_pattern|input_if_message_matches)\s+(\S.*)$" ){
			my $re;
			eval { $re = qr"^($2)$"; };
			if( $@ ){ die "$conffile:$.: $@, stopped"; }
			push @{$$rule{input_if_message_matches}}, $re;

		}elsif( m"^\s*input_if_event_matches\s+(\S.*)$" ){
			my $re;
			eval { $re = qr"^($1)$"; };
			if( $@ ){ die "$conffile:$.: $@, stopped"; }
			push @{$$rule{input_if_event_matches}}, $re;

		}elsif( m"^\s*input_if_pattern_matches\s+(\S.*)$" ){
			my $re;
			eval { $re = qr"^($1)$"; };
			if( $@ ){ die "$conffile:$.: $@, stopped"; }
			push @{$$rule{input_if_pattern_matches}}, $re;

		}elsif( m"^\s*output\s+(\S.*)$" ){
			$$rule{output} = $1;

		}else{
			$this->errorlog("$conffile:$.: illegal format, ignored.");
		}
	}
	close $h or do {
		die "close failed for $conffile: $OS_ERROR, stopped";
	};
	$$this{transactionfilter_message_rules} = \@message_rules;
	$$this{transactionfilter_event_rules}   = \@event_rules;
	return 1;
}

sub read_trafficmonitor_conf ($;$) {
	my ($this, $conffile) = @_;
	$$this{trafficmonitor_conf_path} = $conffile if     defined $conffile;
	$conffile = $$this{trafficmonitor_conf_path} unless defined $conffile;
	my %conf;
	my $timespan = 30 * 60;
	my $rule;
	my $targets;
	my %viewpoints;
	open my $h, '<', $conffile or do {
		die "cannot open $conffile: $OS_ERROR, stopped";
	};
	while (<$h>) {
		next if m"^\s*(#|$)";
		if    ( m"^\s*timespan\s+(\d+)$" ){
			$timespan = int($1) * 60;
			$targets = [];
		}elsif( m"^\s*trafficmonitor_rule\s*$" ){
			$targets = [];
		}elsif( m"^\s*target\s+(\S.*)$" ){
			my $re;
			eval { $re = qr"^($1)$"; };
			if( $@ ){ die "$conffile:$.: $@, stopped"; }
			push @$targets, $re;
		}elsif( m"^\s*boundary\s+(\S+)\s+\[(\d*),(\d*)\]\s*$" ){
			$rule = {
				'detectorid' => "$conffile:$.",
				'timespan'   => $timespan,
				'targets'    => $targets,
				'viewpoint'  => $1,
				'lower'      => $2 ne '' ? $2 : undef,
				'upper'      => $3 ne '' ? $3 : undef,
			};
			push @{ $conf{$timespan} }, $rule;
			$viewpoints{$1} = 1;
		}else{
			$this->errorlog("$conffile:$.: illegal format, ignored.");
		}
	}
	close $h or do {
		die "close failed for $conffile: $OS_ERROR, stopped";
	};
	$$this{TRAFFICMONITOR_CONF} = \%conf;
	$$this{trafficmonitor_timespans}  = [ sort { $a <=> $b } keys %conf ];
	$$this{trafficmonitor_viewpoints} = [ sort { $a cmp $b } keys %viewpoints ];
	return 1;
}

sub read_report_conf ($;$) {
	my ($this, $conffile) = @_;
	$$this{report_conf_path} = $conffile if     defined $conffile;
	$conffile = $$this{report_conf_path} unless defined $conffile;

	my @attrs;
	my @alerts;
	my @flash_reports;
	my @daily_reports;
	my %param;

	my $section;
	my $subsection;
	my @errors;
	open my $h, '<', $conffile or do {
		die "cannot open $conffile: $OS_ERROR, stopped";
	};
	while (<$h>) {
		next if m"^\s*(#|$)";
		chomp;

		if( m"^(\w+)=(\S.*)$" ){
			$param{$1} = $2;

		##
		}elsif( m"^\s*define_attribute$" ){
			$section = {
				from_tags => [],
			};
			push @attrs, $section;

		}elsif( m"^\s*define_alert\s+(\w+)\s*$" ){
			$section = {
				name	=> $1,
				maxsize     => 1000,
				min_interval => 30,
			};
			push @alerts, $section;

		##
		}elsif( m"^\s*captures_anomalylogs\s*$" ){
			$subsection = {
			};
			push @{$$section{from_anomalylogs}}, $subsection;

		}elsif( m"^\s*captures_unmonitoredlogs\s*$" ){
			$subsection = {
			};
			push @{$$section{from_unmonitoredlogs}}, $subsection;

		}elsif( m"^\s*captures_trafficlogs\s*$" ){
			$subsection = {
			};
			push @{$$section{from_trafficlogs}}, $subsection;

		##
		}elsif( m"^\s*(?:captures_from_tag)\s+(\S.*)$" ){
			push @{$$section{from_tags}}, qr"^$1$";

		##
		}elsif( m"^\s*(?:marked_as|matching_mark)\s+(\S.*)$" ){
			push @{$$subsection{marks}}, $1;
			
		}elsif( m"^\s*(?:not_marked_as|unmatching_mark)\s+(\S.*)$" ){
			push @{$$subsection{nomarks}}, $1;

		}elsif( m"^\s*(?:tagged_as|matching_tag)\s+(\S.*)$" ){
			push @{$$subsection{tag_regexps}}, qr"^$1$";

		}elsif( m"^\s*(?:named_as|matching_name|matching_trafficname)\s+(\S.*)$" ){
			push @{$$subsection{trafficname_regexps}}, qr"^$1$";

		}elsif( m"^\s*matching_event\s+(\S.*)$" ){
			push @{$$subsection{event_regexps}}, qr"^$1$";

		}elsif( m"^\s*matching_monitorname\s+(\S.*)$" ){
			push @{$$subsection{monitorname_regexps}}, qr"^$1$";

		}elsif( m"^\s*matching_viewpoint\s+(\S.*)$" ){
			push @{$$subsection{viewpoint_regexps}}, qr"^$1$";

		}elsif( m"^\s*(?:passing_through|matching_route)\s+(\S.*)$" ){
			push @{$$subsection{route_regexps}}, qr"^$1$";

		}elsif( m"^\s*marks_logs_as\s+(\S.*)$" ){
			push @{$$section{mark_logs_as}}, $1;

		}elsif( m"^\s*define_flash_report\s+(\w+)\s*$" ){
			$section = {
				name	   => $1,
				maxsize	=> 1000,
				min_interval   => 30,
				sent_to	=> [],
				contains_alert => [],
			};
			push @flash_reports, $section;

		}elsif( m"^\s*define_daily_report\s+(\w+)\s*$" ){
			$section = {
				name	   => $1,
				max_size       => 1000,
				min_interval   => 30,
				sent_to	=> [],
				contains_alert => [],
			};
			push @daily_reports, $section;

		}elsif( m"^\s*contains_alert\s+(\S.*)$" ){
			push @{$$section{contains_alert}}, qr"^$1$";

		}elsif( m"^\s*sent_to\s+(\S+)$" ){
			push @{$$section{sent_to}}, $1;

		}elsif( m"^\s*max_size\s+(\d+)$" ){
			$$section{max_size} = 0+$1;

		}elsif( m"^\s*min_interval\s+(\d+)$" ){
			$$section{min_interval} = 0+$1;

		}else{
			push @errors, "$conffile:$.: illegal format.\n";
			next;
		}
	}
	close $h;

	if( @errors ){
		foreach my $error ( @errors ){
			print STDERR $error, "\n";
		}
		die;
	}

	$$this{report_conf} = {
		'eventgrouping_rules' => \@alerts,
		'attribute_rules'     => \@attrs,
	};
	#	flash_reports	=> [@flash_reports],
	#	daily_reports	=> [@daily_reports],
	#	param		=> {%param},
}

####

sub get_anomalymonitor_rules ($) {
	my ($this) = @_;
	return @{ $$this{ANOMALYMONITOR_CONF} };
}

sub get_anomalymonitor_patterns ($) {
	my ($this) = @_;
	my %r;
	foreach my $rule ( @{ $$this{ANOMALYMONITOR_CONF} } ){
		$r{ $$rule{pattern} } = 1;
	}
	return sort keys %r;
}

sub get_concatfilter_rules ($) {
	my ($this) = @_;
	return @{ $$this{CONCATFILTER_CONF} };
}

sub get_transactionfilter_rules ($) {
	my ($this) = @_;
	return (
		'message_rules' => $$this{transactionfilter_message_rules},
		'event_rules'   => $$this{transactionfilter_event_rules},
	);
}

sub get_trafficmonitor_viewpoints ($) {
	my ($this) = @_;
	return @{ $$this{trafficmonitor_viewpoints} };
}

sub get_trafficmonitor_timespans ($) {
	my ($this) = @_;
	return @{ $$this{trafficmonitor_timespans} };
}

sub get_trafficmonitor_rules ($$) {
	my ($this, $timespan) = @_;
	return @{ $$this{TRAFFICMONITOR_CONF}->{$timespan} };
}

sub get_report_rules ($) {
	my ($this) = @_;
	return $$this{report_conf};
}

####

sub is_allowing_client_ipaddr ($$) {
	my ($this, $client_ipaddr) = @_;
	return check_subnet_list $client_ipaddr, $$this{FOUCAULT03D_CONF}->{ALLOWLIST};
}

####

sub is_recording_info ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{INFO};
}

sub is_recording_trace ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{TRACE};
}

sub get_path_of_pidfile ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{pidfile};
}

sub get_path_of_logfile ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{logfile};
}

sub get_path_of_unmonitoredlogfile ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{unmonitoredlogfile};
}

sub get_path_of_anomalydetectfile ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{anomalydetectfile};
}

sub get_path_of_trafficdetectfile ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{trafficdetectfile};
}

sub get_path_of_trafficltsvfile ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{trafficltsvfile};
}

sub get_path_of_trafficdir ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{trafficdir};
}

sub get_path_of_concatdir ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{concatdir};
}

sub get_path_of_wellknowndir ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{wellknowndir};
}

sub get_path_of_concatfilter_conf ($) {
	my ($this) = @_;
	return $$this{concatfilter_conf_path};
}

sub get_path_of_transactionfilter_conf ($) {
	my ($this) = @_;
	return $$this{transactionfilter_conf_path};
}

sub get_path_of_anomalymonitor_conf ($) {
	my ($this) = @_;
	return $$this{anomalymonitor_conf_path};
}

sub get_path_of_trafficmonitor_conf ($) {
	my ($this) = @_;
	return $$this{trafficmonitor_conf_path};
}

sub get_path_of_report_conf ($) {
	my ($this) = @_;
	return $$this{report_conf_path};
}

sub get_daemon_listen_addrport ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{listen_address}, $$this{FOUCAULT03D_CONF}->{listen_port};
}

sub get_daemon_user ($) {
	my ($this) = @_;
	return $$this{FOUCAULT03D_CONF}->{daemon_user};
}

####

sub reload ($) {
	my ($this) = @_;

	$this->read_foucault03d_conf_as_reload;
	$this->read_concatfilter_conf;
	$this->read_anomalymonitor_conf;
	$this->read_transactionfilter_conf;
	$this->read_trafficmonitor_conf;
}

####

1;

