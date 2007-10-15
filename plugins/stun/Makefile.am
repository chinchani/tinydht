METASOURCES = AUTO

noinst_LTLIBRARIES = libstun.la

libstun_la_SOURCES = stun.c

noinst_HEADERS = stun.h

AM_CFLAGS = -W -Wall -g -pg -O0 \
	    -I$(top_srcdir)/. -I$(top_srcdir)/src -I$(top_srcdir)/plugins/stun \
            $(all_includes) 

