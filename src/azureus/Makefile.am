METASOURCES = AUTO

noinst_LTLIBRARIES = libazureus.la

libazureus_la_SOURCES = azureus_rpc.c azureus_node.c azureus_db.c \
			azureus_dht.c  azureus.c azureus_rpc_utils.c \
			azureus_vivaldi.c 

noinst_HEADERS = azureus_rpc.h azureus_node.h azureus_db.h azureus_dht.h \
		 azureus.h azureus_rpc_utils.h azureus_vivaldi.h

AM_CFLAGS = -W -Wall -g -pg -O0 \
	    -I$(top_srcdir)/. -I$(top_srcdir)/src -I$(top_srcdir)/src/azureus \
	    $(all_includes)

