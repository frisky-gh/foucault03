#

package Foucault::Filter;

use strict;
use Foucault::Common;

our $REGMARK;

####

sub new ($) {
	my ($class) = @_;
	return bless {
		'infologger'   => undef,
		'errorlogger'  => undef,

		'concatfilter_rules'          => [],
		'concatfilter_rulecache'      => {},
		'concatbuffer'                => {},
		'concatmessages'              => {},
		'transactionfilter_message_rulecache' => {},
		'transactionfilter_event_rulecache'   => {},
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
	my ($this, $format, @args) = @_;
	$$this{infologger}  ->write( $format, @args ) if defined $$this{infologger};
}

sub errorlog ($$;@) {
	my ($this, $format, @args) = @_;
	$$this{errorlogger} ->write( $format, @args ) if defined $$this{errorlogger};;
}

#### initialize functions

sub set_concatbuffer ($$) {
	my ($this, $buffer) = @_;
	$$this{concatbuffer} = $buffer;
}

sub set_concatfilter_rules ($@) {
	my ($this, @rules) = @_;
	@{ $$this{concatfilter_rules} } = @rules;
	$$this{concatfilter_rulecache} = {};
}

sub set_transactionfilter_rules ($@) {
	my ($this, %all_rules) = @_;
	@{ $$this{transactionfilter_message_rules} } = @{ $all_rules{message_rules} };
	@{ $$this{transactionfilter_event_rules} }   = @{ $all_rules{event_rules} };
	$$this{transactionfilter_message_rulecache}  = {};
	$$this{transactionfilter_event_rulecache}    = {};
}

####

sub content2tag2messages ($$) {
	my ($this, $content) = @_;

	my $decoder = JSON::XS->new;
	my $tag2messages = {};
	foreach my $i ( split m"\n", $content ){
		next if $i eq "";
		my $j = $i;
		utf8::decode($i);
		my $log;
		eval {
			$log = $decoder->decode( $i );
		};
		unless( defined $log ){
			$$this->infolog("action_monitor: cannot JSON::XS::decode: log=\"%s\"", $j);
			if( $@ ){
				$$this->infolog("action_monitor: illegal format log \"%s\"", $@);
			}
			next;
		}
		my $tag = $$log{tag};
		my $message = $$log{message};
		next if $message eq "";
		utf8::encode($message);
		push @{$$tag2messages{$tag}}, $message;
	}
	return $tag2messages;
}

#### concat filter functions

sub get_concatfilter_rule ($$) {
	my ($this, $tag) = @_;
	my $cache = $$this{concatfilter_rulecache};

	if( exists $$cache{$tag} ){ return @{$$cache{$tag}}; }

	foreach my $rule ( @{ $$this{concatfilter_rules} } ){
		my $name     = $$rule{name};
		my $targets  = $$rule{targets};
		my $type     = $$rule{type};
		my $limit_line = $$rule{limit_line};
		my $limit_time = $$rule{limit_time};
		my $patterns = $$rule{patterns};
		foreach my $target ( @$targets ){
			next unless $tag =~ m"$target";

			$this->infolog("get_concatfilter_rule: $tag => $name");

			@{$$cache{$tag}} = ($name, $type, $limit_line, $limit_time, $patterns);
			return @{$$cache{$tag}};
		}
	}
	@{$$cache{$tag}} = (undef, undef, undef, undef, undef);
	return undef, undef, undef, undef, undef;
}

sub passthrough_concatfilter ($$$$) {
	my ($this, $tag, $messages, $cmessages) = @_;

	my ($name, $type, $limit_line, $limit_time, $patterns) = $this->get_concatfilter_rule($tag);
	unless( defined $name ){
		foreach my $m (@$messages){
			push @$cmessages, $m;
		}
		return;
	}

	if( $type eq "pattern-first" ){
		my $now = time;
		my $concatbufferunit = $$this{concatbuffer}->{$tag};
		unless( defined $concatbufferunit ){
			$concatbufferunit = {
				'datetime' => $now,
				'fracture' => [],
			};
			$$this{concatbuffer}->{$tag} = $concatbufferunit;
		}

		$$concatbufferunit{datetime} = $now;
		my $fracture = $$concatbufferunit{fracture};

		foreach my $m (@$messages){
			next if $m eq '';

			my $hit = undef;
			if( @$fracture > $limit_line ){
				$hit = 1;
			}else{
				foreach my $pattern ( @$patterns ){
					next unless $m =~ m"$pattern";
					$hit = 1;
					last;
				}
			}

			unless( $hit ){
				push @$fracture, $m;
			}elsif( @$fracture ){
				my $cm = join "\x1f", @$fracture;
				push @$cmessages, $cm;
				@$fracture = ($m);
			}else{
				@$fracture = ($m);
			}
		}
	}else{
		foreach my $m (@$messages){
			push @$cmessages, $m;
		}
	}
}

sub passthrough_all_concatfilters ($$$) {
	my ($this, $tag2messages, $tag2cmessages) = @_;
	while( my ($tag, $messages) = each %$tag2messages ){
		my $num = @$messages;
		## concat filter
		my $cmessages = [];
		$this->passthrough_concatfilter( $tag, $messages, $cmessages );
		push @{$$tag2cmessages{$tag}}, @$cmessages;
	}

        my $concatmessages = $$this{concatmessages};
	if( %$concatmessages ){
		while( my ($tag, $cmessages) = each %$concatmessages ){
			push @{$$tag2cmessages{$tag}}, @$cmessages;
		}
        	%$concatmessages = ();
	}
}

sub keep_concatbuffer ($) {
	my ($this) = @_;
        my $now = time;
        my $concatbuffer   = $$this{concatbuffer};
        my $concatmessages = $$this{concatmessages};

        foreach my $tag ( keys %$concatbuffer ){
        	my $unit = $$concatbuffer{$tag};
                my $datetime = $$unit{datetime};
		my $fracture = $$unit{fracture};
                my ($name, $type, $limit_line, $limit_time, $patterns) = $this->get_concatfilter_rule($tag);
                next unless $datetime + $limit_time < $now;
		next unless @$fracture;

                push @{ $$concatmessages{$tag} }, @$fracture;
		delete $$concatbuffer{$tag};
        }
}

####

sub pass_messages_through_transactionfilter ($$$$) {
	my ($this, $tag, $cmessages, $out_trxid2times) = @_;

	my @rules = $this->get_transactionfilter_message_rule($tag);
	return unless @rules;

	foreach my $message ( @$cmessages ){
		foreach my $rule ( @rules ){
			my ($name, $output, $if_message_matches, $captured) = @$rule;

			my ($hit, %captured_from_message) = capture_by_regexps $message, $if_message_matches, 1;
			next unless $hit;

			my %captured = ( %$captured, %captured_from_message );
			my $trxid = expand_named_placeholders $output, %captured;
			$$out_trxid2times{$trxid}++;
		}
	}
}

sub pass_event_through_transactionfilter ($$$$$$) {
	my ($this, $event, $pattern, $tag, $message, $out_trxid2times) = @_;

	my @rules = $this->get_transactionfilter_event_rule($event, $pattern, $tag);
	return unless @rules;

	foreach my $rule ( @rules ){
		my ($name, $output, $if_message_matches, $captured) = @$rule;

		my ($hit, %captured_from_message) = capture_by_regexps $message, $if_message_matches, 1;
		next unless $hit;

		my %captured = ( %$captured, %captured_from_message );
		my $trxid = expand_named_placeholders $output, %captured;
		$$out_trxid2times{$trxid}++;
	}
}

sub passthrough_all_transactionfilters ($$$$$) {
	my ($this, $tag2cmessages, $events, $unmonitored, $out_trxid2times) = @_;
	while( my ($tag, $cmessages) = each %$tag2cmessages ){
		$this->pass_messages_through_transactionfilter( $tag, $cmessages, $out_trxid2times );
	}
	foreach my $event ( @$events ){
		my $eventname = $$event{event};
		my $pattern   = $$event{pattern};
		my $tag       = $$event{tag};
		my $message   = $$event{message};
		$this->pass_event_through_transactionfilter( $eventname, $pattern, $tag, $message, $out_trxid2times );
	}
	foreach my $event ( @$unmonitored ){
		my $eventname = $$event{event};
		my $pattern   = $$event{pattern};
		my $tag       = $$event{tag};
		my $message   = $$event{message};
		$this->pass_event_through_transactionfilter( $eventname, $pattern, $tag, $message, $out_trxid2times );
	}
}

sub get_transactionfilter_message_rule ($$) {
	my ($this, $tag) = @_;
	my $cache = $$this{transactionfilter_message_rulecache};

	if( exists $$cache{$tag} ){ return @{$$cache{$tag}}; }

	my $rules = $$this{transactionfilter_message_rules};
	my @result;
	foreach my $rule ( @$rules ){
		my $name   = $$rule{name};
		my $output = $$rule{output};
		my $if_tag_matches     = $$rule{input_if_tag_matches};
		my $if_message_matches = $$rule{input_if_message_matches};

		my ($hit, %captured_from_tag) = capture_by_regexps $tag, $if_tag_matches, 1;
		next unless $hit;
		$this->infolog("get_transactionfilter_message_rule: $tag => $name => $output");
		my %captured = ( %captured_from_tag );
		while( my ($k, $v) = each %captured ){
			$this->infolog("get_transactionfilter_message_rule:     captured: %s => %s", $k, $v);
		}

		push @result, [$name, $output, $if_message_matches, \%captured];
	}
	$$cache{$tag} = \@result;
	return @result;
}

sub get_transactionfilter_event_rule ($$$$) {
	my ($this, $event, $pattern, $tag) = @_;
	my $cache = $$this{transactionfilter_event_rulecache};

	if( exists $$cache{$event,$pattern,$tag} ){ return @{$$cache{$event,$pattern,$tag}}; }

	my $rules = $$this{transactionfilter_event_rules};
	my @result;
	foreach my $rule ( @$rules ){
		my $name   = $$rule{name};
		my $output = $$rule{output};
		my $if_event_matches   = $$rule{input_if_event_matches};
		my $if_pattern_matches = $$rule{input_if_pattern_matches};
		my $if_tag_matches     = $$rule{input_if_tag_matches};
		my $if_message_matches = $$rule{input_if_message_matches};

		my ($hit, %captured_from_event)   = capture_by_regexps $event,   $if_event_matches,   1;
		next unless $hit;
		my ($hit, %captured_from_pattern) = capture_by_regexps $pattern, $if_pattern_matches, 1;
		next unless $hit;
		my ($hit, %captured_from_tag)     = capture_by_regexps $tag,     $if_tag_matches,     1;
		next unless $hit;
		$this->infolog("get_transactionfilter_event_rule: $event,$pattern,$tag => $name => $output");
		my %captured = ( %captured_from_event, %captured_from_pattern, %captured_from_tag );
		while( my ($k, $v) = each %captured ){
			$this->infolog("get_transactionfilter_event_rule:     captured: %s => %s", $k, $v);
		}

		push @result, [$name, $output, $if_message_matches, \%captured];
	}
	$$cache{$event,$pattern,$tag} = \@result;
	return @result;
}

####

sub check ($) {
	my ($this) = @_;
	return 1;
}

sub take_statistics_of_cache ($) {
	my ($this) = @_;
	
	my $concatfilter_rulecache = $$this{concatfilter_rulecache};
	my $concatbuffer = $$this{concatbuffer};
	my $transactionfilter_message_rulecache = $$this{transactionfilter_message_rulecache};
	my $transactionfilter_event_rulecache   = $$this{transactionfilter_event_rulecache};

	my $concatfilter_rulecache_keys;
	my $concatfilter_rulecache_items;
	while( my ($k, $v) = each %$concatfilter_rulecache ){
		$concatfilter_rulecache_keys++;
		$concatfilter_rulecache_items += @$v;
	}
	my $concatbuffer_keys;
	my $concatbuffer_volume;
	while( my ($k, $v) = each %$concatbuffer ){
		$concatbuffer_keys++;
		my $fracture = $$v{fracture};
		foreach my $i ( @$fracture ){
			$concatbuffer_volume += length $i;
		}
	}
	my $transactionfilter_message_rulecache_keys;
	my $transactionfilter_message_rulecache_items;
	while( my ($k, $v) = each %$transactionfilter_message_rulecache ){
		$transactionfilter_message_rulecache_keys++;
		$transactionfilter_message_rulecache_items += @$v;
	}
	my $transactionfilter_event_rulecache_keys;
	my $transactionfilter_event_rulecache_items;
	while( my ($k, $v) = each %$transactionfilter_event_rulecache ){
		$transactionfilter_event_rulecache_keys++;
		$transactionfilter_event_rulecache_items += @$v;
	}

	return (
		'concatfilter_rulecache_keys'  => $concatfilter_rulecache_keys,
		'concatfilter_rulecache_items' => $concatfilter_rulecache_items,
		'concatbuffer_keys'  => $concatbuffer_keys,
		'concatbuffer_volume' => $concatbuffer_volume,
		'transactionfilter_message_rulecache_keys'  => $transactionfilter_message_rulecache_keys,
		'transactionfilter_message_rulecache_items' => $transactionfilter_message_rulecache_items,
		'transactionfilter_event_rulecache_keys'    => $transactionfilter_event_rulecache_keys,
		'transactionfilter_event_rulecache_items'   => $transactionfilter_event_rulecache_items,
	);
}

####

1;

#

