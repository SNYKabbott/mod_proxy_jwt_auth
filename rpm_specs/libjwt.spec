Name:           libjwt
Version:        1.8.0
Release:        0
Summary:        JWT C Library
Group:          Development/Libraries
License:        GNU Lesser General Public License v3.0
URL:            https://github.com/benmcollins/libjwt

# Allow source fetching: This is acceptable as the file is distributed over HTTPS
#%undefine _disable_source_fetch
Source:         https://github.com/benmcollins/libjwt/archive/v%{version}.tar.gz

BuildRequires: libtool pkgconfig autoconf gcc make openssl-devel jansson-devel

%description
JWT C Library

# Don't build the debug package
%define debug_package %{nil}

%prep
%setup

%build
autoreconf -i
mkdir -p %{buildroot}/usr
./configure --prefix=%{buildroot}/usr --libdir=%{buildroot}/usr/lib64
make

%install
make install
sed -e 's|%{buildroot}||g' -i %{buildroot}/usr/lib64/pkgconfig/libjwt.pc %{buildroot}/usr/lib64/libjwt.la

%files
/usr/include/*
/usr/lib64/libjwt*
/usr/lib64/pkgconfig/libjwt*
