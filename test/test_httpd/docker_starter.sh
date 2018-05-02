#!/bin/bash
set -eo pipefail

RPMDIR="/RPMS/x86_64"

function install_rpm {
    target=$(ls ${RPMDIR}/${1}-[0-9]*.rpm | sort -nr | head -n 1)
    rpm -i $target
}

# Wait for the rpm to be generated
for((c=0;;c++)); do
    # Use $rv not $? because "set -e" is active
    rv=0
    ls ${RPMDIR}/mod_proxy_jwt_auth* || rv=$?
    if [ $rv -eq 0 ]; then
	   break
    fi

    if [ $c -ge 30 ]; then
	   echo "ERROR: mod_proxy_jwt_auth RPM not present after 30 seconds, exiting in error"
	   exit 1
    fi
    sleep 1
done

install_rpm "libjwt"
install_rpm "mod_proxy_jwt_auth"

exec /usr/sbin/httpd -f /test_files/httpd/httpd.conf -e info -DFOREGROUND
