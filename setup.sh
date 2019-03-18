#!/bin/bash
DIR=` dirname $0 `
TOOLHOME=` readlink -f "$DIR" `

if [ `id -u` -ne 0 ] ; then
	echo Execute by root.
	exit 1
fi

ansible-playbook -i localhost, -c local -e "TOOLHOME=$TOOLHOME" \
        $TOOLHOME/setup.yml
r=$?
if [ $r -ne 0 ] ; then
	echo Abort.
	exit $r
fi

chown td-agent:td-agent \
	spool status anomalylog capturedlog unmonitoredlog \
	deliveredevent undeliveredevent

find $TOOLHOME/conf -name '*.example' |
while read f ; do
	g="${f%.example}"
	test -f $g && continue
	sudo -u td-agent cp $f $g
done

