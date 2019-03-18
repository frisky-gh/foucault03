Foucault03
====

Foucault03 is a anomaly log monitoring system.

## Requirement

* Perl (> 5.20)
* Ansible

## Description

Foucault03 system monitors logs treated by fluentd and tagged "multilinelog.**".
The system detects anomaly logs defined by pre-generated patterns.
Patterns are builded from sample logs and build rules.
If you hope to monitor /var/log/messages, you may use /var/log/messages
for a sample log as is.

Build rules may specify variable words in the logs by regexp, like following:
* `\d+\.\d+\.\d+\.\d+` (IP address)
* `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\x20[\x200-9][0-9]\x20[\x200-9][0-9]:[0-9][0-9]:[0-9][0-9]` (timestamp)

## Instllation

1. `git clone https://github.com/frisky-gh/foucault03.git`
2. `cd foucault03`
3. `sudo setup.sh`
4. `vi conf/fluentd.conf`
5. `./bin/foucaultctl build_fluentd_conf`
6. `./bin/foucaultctl build_patterns`
7. `/etc/init.d/td-agent restart`

## Synopsis

`foucaultctl <SUBCOMMAND>`

SUBCOMMAND is one of following:
<dl>
<dt> build_fluentd_conf
<dd>  Build a conf file for fluentd.
<dt> build_patterns
<dd>  Build all pattern files which related to updated rules or sample file.
<dt> list_unmonitoredlog
<dd>  List up all unmonitoredlogs.
<dt> capture_unmonitoredlog
<dd>  Caputure unmonitoredlogs into capturedlogs.
<dt> capture_anomalylog
<dd>  Caputure anomalylogs into capturedlogs.
<dt> show_capturedlog
<dd>  Show all caputuredlogs.
<dt> strip_capturedlog
<dd>  Strip redundant capturedlogs.
<dt> import_capturedlog
<dd>  Append all capturedlogs into samples. 
<dt> strip_samples
<dd>  Strip redundant samples.
</dl>

## Files

<dl>
<dt> conf/fluentd.conf
<dd>  Configuration file for fluentd.
<dt> conf/fluentd.tt
<dd>  Template file for a fluentd.conf.
<dt> conf/deliver.conf
<dd>  Configuration file for report deliveries.
<dt> conf/deliver_flash.tt
<dd>  Template file for a flash report of anomaly log by mail.
<dt> conf/deliver_daily.tt
<dd>  
<dt> conf/fluentd/fluentd_foucault03.conf
<dd>  fluentd configuration file. It's included by /etc/td-agent/td-agent.conf.
<dt> conf/patterns/*.rules
<dd>  Build rules file. You may customize it to adjust to your VMs.
<dt> conf/patterns/*.sample
<dd>  Sample log file. You may put log file you want to target. Its size is hoped to be less than < 1MB.
<dt> conf/patterns/*.pattern
<dd>  Pattern file. It's builded from a sample log and build rules, by `foucaultctl build_patterns`.
<dt> anomalylog/*
<dd>  File of anomaly logs detected by foucault03.
<dt> unmonitoredlog/*
<dd>  File of logs that is not monitored.
<dt> capturedlog/*
<dd>  File of logs that is caputured from anomalylog or unmonitoredlog by 'capture_anomalylog' or 'capture_unmonitoredlog' subcommand.
<dt> deliveredevent/*
<dd>  File of events that is delivered to recipients.
<dt> undeliveredevent/*
<dd>  File of events file that is not delivered to any recipients.
</dl>

## Licence

[MIT](https://github.com/frisky-gh/panopticfilter/blob/master/LICENSE)

## Author

[frisky-gh](https://github.com/frisky-gh)

