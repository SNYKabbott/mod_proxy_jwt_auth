ACLOCAL_AMFLAGS = -I acinclude.d

noinst_LTLIBRARIES = libmodrequestenvjwt.la
noinst_DATA = mod_request_env_jwt.la

AM_CPPFLAGS = ${APACHE_CFLAGS} ${JWT_CFLAGS}
AM_LDFLAGS = ${JWT_LIBS} ${APR_LDFLAGS}

libmodrequestenvjwt_la_SOURCES = mod_request_env_jwt.c

AM_CFLAGS = -Wall -Werror

if NITPICK
# This is off by default as it find errors in Apache headers
AM_CFLAGS += -Wextra -Wundef -Wshadow -Wunsafe-loop-optimizations -Wconversion -Wmissing-format-attribute -Wredundant-decls
AM_CFLAGS += -Wmissing-noreturn -Wlogical-op -Wjump-misses-init -Wdouble-promotion -Wshadow
endif

if DEBUG
AM_CFLAGS += -DDEBUG
endif

install-exec-local:
	${APXS} -i -a -n 'request_env_jwt' mod_request_env_jwt.la

mod_request_env_jwt.la: libmodrequestenvjwt.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS}
