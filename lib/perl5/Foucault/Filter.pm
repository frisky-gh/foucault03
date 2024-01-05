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
		'tracsactionfilter_rulecache' => {},
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
	my ($this, @rules) = @_;
	@{ $$this{transactionfilter_rules} } = @rules;
	$$this{transactionfilter_rulecache} = {};
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
	while( my ($tag, $cmessages) = each %$concatmessages ){
		push @{$$tag2cmessages{$tag}}, @$cmessages;
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

sub passthrough_transactionfilter ($$$$) {
	my ($this, $tag, $cmessages, $out_trxid2times) = @_;

#$this->infolog( "DEBUG08: tag: %s", $tag );
	my @rules = $this->get_transactionfilter_rule($tag);
	unless( @rules ){
		return if $$this{UNMONITOREDCACHE}->{$tag};
		$this->infolog("process_transaction_filter: unmonitored $tag");
		$$this{UNMONITOREDCACHE}->{$tag} = 1;
		return;
	}

#$this->infolog( "DEBUG09: tag: %s", $tag );
	foreach my $m ( @$cmessages ){
		foreach my $rule ( @rules ){
			my ($name, $output, $message_patterns, $captures) = @$rule;
			#$this->infolog( "DEBUG10: $tag => $m" );

			my %captures = %$captures;
			foreach my $message_pattern ( @$message_patterns ){
				$m =~ $message_pattern or next;
				while( my ($k, $v) = each %+ ){
					$captures{$k} = $v;
				}
			}
			my $t = expand_named_placeholders $output, %captures;
			#$this->infolog( "DEBUG11: $output => $t" );
			$$out_trxid2times{$t}++;
		}
	}
}

sub passthrough_all_transactionfilters ($$$) {
	my ($this, $tag2cmessages, $out_trxid2times) = @_;
	while( my ($tag, $cmessages) = each %$tag2cmessages ){
		$this->passthrough_transactionfilter( $tag, $cmessages, $out_trxid2times );
	}
}

sub get_transactionfilter_rule ($$) {
	my ($this, $tag) = @_;
	my $cache = $$this{tracsactionfilter_rulecache};

	if( exists $$cache{$tag} ){ return @{$$cache{$tag}}; }

	my $rules = $$this{transactionfilter_rules};
	my @result;
	foreach my $rule ( @$rules ){
		my $name   = $$rule{name};
		my $inputs = $$rule{inputs};
		my $output = $$rule{output};
		my $tag_patterns     = $$rule{tag_patterns};
		my $message_patterns = $$rule{message_patterns};
		foreach my $input ( @$inputs ){
			next unless $tag =~ m"$input";

			$this->infolog("get_transactionfilter_rule: $tag => $name => $output");
			my $captures = {};
			foreach my $tag_pattern ( @$tag_patterns ){
				$tag =~ m"$tag_pattern" or next;
				while( my ($k, $v) = each %+ ){
					$$captures{$k} = $v;
					$this->infolog("get_transactionfilter_rule:     capture: <$k> => $v");
				}
			}
			push @result, [$name, $output, $message_patterns, $captures];
		}
	}
	$$cache{$tag} = \@result;
	return @result;
}

####

sub check ($) {
	my ($this) = @_;
	return 1;
}

####

1;

#

