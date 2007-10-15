METASOURCES = AUTO

bin_PROGRAMS = tinydht
tinydht_SOURCES = tinydht.c \
		  dht_types.c pkt.c debug.c crypto.c dht.c \
		  key.c kbucket.c task.c node.c float.c

# the library search path.
noinst_HEADERS = tinydht.h \
		 pkt.h debug.h tinydht.h dht.h crypto.h key.h types.h \
		 kbucket.h queue.h task.h node.h dht_types.h float.h
tinydht_LDADD = $(top_builddir)/src/azureus/libazureus.la \
		$(top_builddir)/plugins/stun/libstun.la \
		-lm -lssl
tinydht_LDFLAGS = $(all_libraries) -pg -g 
tinydht_CFLAGS = -W -Wall -g -pg -O0 \
		 -I$(top_srcdir)/. -I$(top_srcdir)/src \
		 -I$(top_srcdir)/src/azureus \
		 -I$(top_srcdir)/plugins/stun \
		 $(all_includes) 

SUBDIRS = azureus
