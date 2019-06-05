pkglib_LTLIBRARIES = omsqlite.la

omsqlite_la_SOURCES = omsqlite.c
omsqlite_la_CPPFLAGS = -I$(top_srcdir) $(SQLITE_CFLAGS) $(RSRT_CFLAGS)
omsqlite_la_LDFLAGS = -module -avoid-version
omsqlite_la_LIBADD = $(SQLITE_LIBS)

EXTRA_DIST = createDB.sql
