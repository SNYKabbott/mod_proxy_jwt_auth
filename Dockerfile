FROM centos:7

RUN yum update -y

RUN curl -L 'https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm' > /tmp/epel.rpm && \
    rpm -i /tmp/epel.rpm
RUN yum install -y cppcheck

#
# DEV/WIP: Test Module
#
RUN yum install -y httpd httpd-devel libtool pkgconfig autoconf 

RUN yum install -y git libtool pkgconfig autoconf openssl-devel check jansson-devel
RUN yum install -y gcc-c++ make

RUN cd /tmp && \
    git clone https://github.com/benmcollins/libjwt && \
    cd libjwt && \
    git checkout tags/v1.8.0 && \
    autoreconf -i && \
    ./configure && \
    make && \
    make install

RUN cp /usr/local/lib/libjwt.* /usr/lib64 -a && \
    ldconfig

RUN yum install llvm-toolset-7-clang-tools-extra

COPY ./ /tmp/request_env_jwt
RUN cd /tmp/request_env_jwt && \
    cppcheck --enable=all ./ --error-exitcode=1 && \
    export PKG_CONFIG_PATH=/usr/lib/pkgconfig:/usr/local/lib/pkgconfig && \
    autoreconf -ivf && \
    ./configure

RUN cd /tmp/request_env_jwt && \
    make && \
    make install
