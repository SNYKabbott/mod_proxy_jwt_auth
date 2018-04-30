#!/bin/bash
set -eo pipefail

RPMDIR="/RPMS/x86_64"

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

rpm -i ${RPMDIR}/libjwt-[0-9]*.rpm ${RPMDIR}/mod_proxy_jwt_auth-[0-9]*.rpm
exec /usr/sbin/httpd -f /test_files/httpd/httpd.conf -e info -DFOREGROUND
