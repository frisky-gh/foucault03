#

sub get_concatfilter_rule ($$) {
	my ($this, $tag) = @_;
	my $cache = $$this{concatfilter_rulecache};

	if( exists $$cache{$tag} ){ return @{$$cache{$tag}}; }

	my $conf = $$this{CONCATFILTER_CONF};
	foreach my $rule ( @$conf ){
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

sub get_transactionfilter_rule ($$) {
	my ($this, $tag) = @_;
	my $cache = $$this{tracsactionfilter_rulecache};

	if( exists $$cache{$tag} ){ return @{$$cache{$tag}}; }

	my $conf = $$this{TRANSACTIONFILTER_CONF};
	my @result;
	foreach my $rule ( @$conf ){
		my $name   = $$rule{name};
		my $inputs = $$rule{inputs};
		my $output = $$rule{output};
		my $tag_patterns     = $$rule{tag_patterns};
		my $message_patterns = $$rule{message_patterns};
		foreach my $input ( @$inputs ){
			next unless $tag =~ m"$input";

			$this->infolog("get_transactionfilter_rules: $tag => $name => $output");
			my $captures = {};
			foreach my $tag_pattern ( @$tag_patterns ){
				$tag =~ m"$tag_pattern" or next;
				while( my ($k, $v) = each %+ ){
					$$captures{$k} = $v;
					$this->infolog("get_transactionfilter_rules: tag_pattern: $k => $v");
				}
			}
			push @result, [$name, $output, $message_patterns, $captures];
		}
	}
	$$cache{$tag} = \@result;
	return @result;
}

