# WARNING: This spec file is intended to be called within Dockerfile.rpmbuild
Name:           mod_request_env_jwt
Version:        %(cat /build/mod_request_env_jwt/VERSION)
Release:        0
Summary:        Request ENV JWT module for the Apache web server
Group:          System Environment/Daemons
License:        Apache-2
URL:            TODO

BuildRequires: libtool pkgconfig autoconf gcc make libjwt cppcheck httpd-devel
Requires: libjwt

%description
Request ENV JWT module for the Apache web server

%build
cd /build/mod_request_env_jwt
grep 'APLOGNO([0-9]\+)' mod_request_env_jwt.c | sed -e 's|.*APLOGNO(\([0-9]\+\)).*|\1|' | sort | uniq -c | grep -qv '^[[:space:]]\+1' && echo "Duplicate APLOGNO numbers detected" && /bin/false
cppcheck --enable=all ./ --error-exitcode=1
autoreconf -ivf
./configure
make

%install
mkdir -p %{buildroot}/usr/lib64/httpd/modules
cd /build/mod_request_env_jwt
/usr/bin/apxs -i -S LIBEXECDIR=%{buildroot}/usr/lib64/httpd/modules -n 'request_env_jwt' mod_request_env_jwt.la

%files
/usr/lib64/httpd/modules/*
