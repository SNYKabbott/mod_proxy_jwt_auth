FROM centos:7

RUN yum update -y

#RUN curl -L 'https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm' > /tmp/epel.rpm && \
#    rpm -i /tmp/epel.rpm && \
#    yum install -y python-pip && \
#    cd /config_engine && \
#    pip install -r requirements.txt && \
#    yum remove -y python-pip

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

COPY ./ /tmp/request_env_jwt
RUN cd /tmp/request_env_jwt && \
    export PKG_CONFIG_PATH=/usr/lib/pkgconfig:/usr/local/lib/pkgconfig && \
    autoreconf -ivf && \
    ./configure

RUN cd /tmp/request_env_jwt && \
    make && \
    make install
