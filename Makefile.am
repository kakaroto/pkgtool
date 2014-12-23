# Makefile.am for pkgtool
#
# Licensed under LGPL 2.1. See file COPYING.

ERROR_CFLAGS = \
	$(PS3XPORT_CFLAGS) \
	-fno-strict-aliasing \
	-Wall \
	-Wextra \
	-Wundef \
	-Wnested-externs \
	-Wwrite-strings \
	-Wpointer-arith \
	-Wbad-function-cast \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wstrict-prototypes \
	-Wredundant-decls \
	-Wno-unused-parameter \
	-Wno-missing-field-initializers

AM_CFLAGS = \
	$(ERROR_CFLAGS)

bin_PROGRAMS = 	pkgtool

pkgtool_SOURCES =  types.h \
		tools.c \
		tools.h \
		keys.c \
		keys.h \
		aes.c \
		aes.h \
		sha1.c \
		sha1.h \
		pkgtool.c \
		pkg.c \
		paged_file.c
