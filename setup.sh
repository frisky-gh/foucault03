#!/bin/bash
SERVICEHOME=` readlink -f "${0%/*}" `
exec ansible-playbook -i localhost, -c local -e "SERVICEHOME=$SERVICEHOME" \
        ${0%/*}/setup.yml

