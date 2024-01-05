#

package Foucault::Diagnosis;

use strict;
use English;

use Foucault::Common;

####

sub new ($) {
	my ($class) = @_;
	return bless {
		'infologger'  => undef,
		'errorlogger' => undef,
		'attribute_rules'     => undef,
		'eventgrouping_rules' => undef,
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

####

sub set_report_rules ($$) {
	my ($this, $rules) = @_;
	$$this{attrbute_rules}      = $$rules{attribute_rules};
	$$this{eventgrouping_rules} = $$rules{eventgrouping_rules};
}

####

sub match_mark ($$$) {
	my ($marks, $targets, $if_undefined) = @_;
	return $if_undefined unless defined $targets;
	return $if_undefined unless @$targets;
	foreach my $target ( @$targets ){
		return 1 if $$marks{$target};
	}
	return undef;
}

sub get_attributes_of ($$) {
	my ($this, $event) = @_;
	my $rules = $$this{attribute_rules};
	my $tag = $$event{tag};

	my %r;
	foreach my $rule ( @$rules ){
		my $from_tags = $$rule{from_tags};

		foreach my $regexp ( @$from_tags ){
			next unless $tag =~ m"$regexp";
			while( my ($k, $v) = each %+ ){
				$r{$k} = $v;
			}
		}
	}

	return %r;
}

sub get_eventgroupnames_of ($$) {
	my ($this, $event) = @_;
	my $rules = $$this{eventgrouping_rules};
	my $pattern   = $$event{pattern};
	my $tag       = $$event{tag};
	my $eventname = $$event{event};
	my $marks = {};
	my @r;
	foreach my $rule ( @$rules ){
		my $name          = $$rule{name};
		my $mark_logs_as  = $$rule{mark_logs_as} // [];
		my $capture_rules = $$rule{from_anomalylogs};
		foreach my $capture_rule ( @$capture_rules ){

			my $targets = $$capture_rule{marks};
			next unless match_mark $marks, $targets, 1;
			my $targets = $$capture_rule{nomarks};
			next if match_mark $marks, $targets, undef;

			my $monitorname_regexps = $$capture_rule{monitorname_regexps};
			next unless match_regexps $pattern, $monitorname_regexps, 1;
			my $tag_regexps         = $$capture_rule{tag_regexps};
			next unless match_regexps $tag, $tag_regexps, 1;
			my $event_regexps       = $$capture_rule{event_regexps};
			next unless match_regexps $eventname, $event_regexps, 1;

			foreach my $m ( @$mark_logs_as ){
				$$marks{$m} = 1;
			}
			push @r, $name;
			last;
		}
	}
	return @r;
}

####

1;

