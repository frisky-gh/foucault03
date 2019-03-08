#!/bin/bash
DIR=` dirname $0 `
TOOLHOME=` readlink -f "$DIR" `

ansible-playbook -i localhost, -c local -e "TOOLHOME=$TOOLHOME" \
        $TOOLHOME/setup.yml

find $TOOLHOME/conf -name '*.example' |
while read f ; do
	g="${f%.example}"
	test -f $g && continue
	sudo -u td-agent cp $f $g
done

