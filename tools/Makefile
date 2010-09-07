#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (c) 1997-1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"

RM=rm
YACC.y=yacc
LFLAGS= -t -v
YFLAGS= -d -v
LEX=lex
MV=mv

CC=gcc
CFLAGS=-g -I.. -I. -I./port -I/usr/include/libelf -I../libstand -I../libstandctf -D_MDB -D__USE_LARGEFILE64 -D__USE_GNU -DNO_SYSINFO
CPPFLAGS=
LDFLAGS=-lm -lrt -ldl
CCNEEDED=

LINK.c=     $(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS)
LINK64.c=   $(CC) $(CFLAGS64) $(CPPFLAGS) $(LDFLAGS)
NORUNPATH=  -norunpath -nolib 
LINK.cc=    $(CCC) $(CCFLAGS) $(CPPFLAGS) $(NORUNPATH) \
	        $(LDFLAGS) $(CCNEEDED)
LINK64.cc=  $(CCC) $(CCFLAGS64) $(CPPFLAGS) $(NORUNPATH) \
	        $(LDFLAGS) $(CCNEEDED)

CFILES=$(wildcard *.c) 
OBJECTS=$(sort $(patsubst %.c, %.o, $(CFILES)) mdb_lex.o mdb_grammar.o)
TARGET=libcommdb.so

$(TARGET):mdb_lex.o $(OBJECTS)
	$(CC) -share -o $(TARGET) $(LDFLAGS) $(LIB) $(OBJECTS)

.c:
	$(LINK.c) -o $@ $< $(LDLIBS)

.y:
	$(YACC.y) $<
	$(LINK.c) -o $@ y.tab.c $(LDLIBS)
	$(RM) y.tab.c

mdb_lex.c: mdb_lex.l mdb_grammar.h
	$(LEX) $(LFLAGS) mdb_lex.l > $@ 

mdb_grammar.h mdb_grammar.c: mdb_grammar.y
	$(YACC) $(YFLAGS) mdb_grammar.y
	@$(MV) y.tab.h mdb_grammar.h
	@$(MV) y.tab.c mdb_grammar.c

clean:
	rm -rf *.o y.tab.h y.tab.c mdb_grammar.h mdb_grammar.c mdb_lex.c y.output
