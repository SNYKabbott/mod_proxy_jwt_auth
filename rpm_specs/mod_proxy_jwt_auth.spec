# WARNING: This spec file is intended to be called within Dockerfile.rpmbuild
Name:           mod_proxy_jwt_auth
Version:        %(cat /build/mod_proxy_jwt_auth/VERSION)
Release:        0
Summary:        Proxy JWT Auth module for the Apache web server
Group:          System Environment/Daemons
License:        Apache-2
URL:            TODO

BuildRequires: libtool pkgconfig autoconf gcc make libjwt cppcheck httpd-devel
Requires: libjwt

%description
Apache2 module which passes a Json Web Token as a Bearer authorization header to a proxied server, optionally mapping request environment variables to JWT claims.
This module in intended to allow Apache to authenticate itself to a backend application when acting as a reverse proxy.

%build
cd /build/mod_proxy_jwt_auth
grep 'APLOGNO([0-9]\+)' *.c | sed -e 's|.*APLOGNO(\([0-9]\+\)).*|\1|' | sort | uniq -c | grep -qv '^[[:space:]]\+1' && echo "Duplicate APLOGNO numbers detected" && /bin/false
cppcheck --enable=all ./ --error-exitcode=1
autoreconf -ivf
./configure
make

%install
mkdir -p %{buildroot}/usr/lib64/httpd/modules
cd /build/mod_proxy_jwt_auth
/usr/bin/apxs -i -S LIBEXECDIR=%{buildroot}/usr/lib64/httpd/modules -n 'proxy_jwt_auth' mod_proxy_jwt_auth.la

%files
/usr/lib64/httpd/modules/*
