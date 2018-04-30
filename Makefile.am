ACLOCAL_AMFLAGS = -I acinclude.d

noinst_LTLIBRARIES = libmodproxyjwtauth.la
noinst_DATA = mod_proxy_jwt_auth.la

AM_CPPFLAGS = ${APACHE_CFLAGS} ${JWT_CFLAGS}
AM_LDFLAGS = ${JWT_LIBS} ${APR_LDFLAGS}

libmodproxyjwtauth_la_SOURCES = mod_proxy_jwt_auth.c

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
	${APXS} -i -a -n 'proxy_jwt_auth' mod_proxy_jwt_auth.la

mod_proxy_jwt_auth.la: libmodproxyjwtauth.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS}
