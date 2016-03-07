# Copyright 2011 Ian Goldberg
#
# This file is part of Sphinx.
# 
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
# 
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.

CURVE25519_OBJ = curve25519_athlon.o \
	    curve25519_athlon_const.o \
	    curve25519_athlon_fromdouble.o \
	    curve25519_athlon_init.o \
	    curve25519_athlon_mainloop.o \
	    curve25519_athlon_mult.o \
	    curve25519_athlon_square.o \
	    curve25519_athlon_todouble.o

all: _curvedh.so curvedh.py
	cp $^ ..

_curvedh.so: curve25519.so curve25519.h curvedh.c curvedh_wrap.c curvedh.h
	gcc -fno-stack-protector -fpic -c curvedh.c curvedh_wrap.c -I/usr/include/python2.6
	ld -I/usr/include/python2.6 -shared curvedh_wrap.o curvedh.o $(CURVE25519_OBJ) -o _curvedh.so

curvedh.py curvedh_wrap.c: curvedh.i curvedh.h
	swig -python curvedh.i

clean: curveclean
	-rm -f _curvedh.so curvedh_wrap.c curvedh.py

# curve25519 Makefile.lib version 20050915
# D. J. Bernstein
# Public domain.

curve25519: curve25519.so curve25519.a curve25519.h

curveclean:
	-rm -f curve25519.so curve25519.a curve25519.h $(CURVE25519_OBJ)

curve25519.h: curve25519.impl \
curve25519.h.do
	sh -e curve25519.h.do > curve25519.h.new
	mv curve25519.h.new curve25519.h

curve25519.so: curve25519.impl \
curve25519.so.do \
curve25519_athlon.h \
curve25519_athlon.c \
curve25519_athlon_const.s \
curve25519_athlon_fromdouble.s \
curve25519_athlon_init.s \
curve25519_athlon_mainloop.s \
curve25519_athlon_mult.s \
curve25519_athlon_square.s \
curve25519_athlon_todouble.s
	sh -e curve25519.so.do $(CC)

curve25519.a: curve25519.impl \
curve25519.a.do \
curve25519_athlon.h \
curve25519_athlon.c \
curve25519_athlon_const.s \
curve25519_athlon_fromdouble.s \
curve25519_athlon_init.s \
curve25519_athlon_mainloop.s \
curve25519_athlon_mult.s \
curve25519_athlon_square.s \
curve25519_athlon_todouble.s
	sh -e curve25519.a.do $(CC) > curve25519.a.new
	mv curve25519.a.new curve25519.a

curve25519.impl: \
curve25519.impl.do \
x86cpuid.c \
curve25519.impl.check.c \
curve25519_athlon.h \
curve25519_athlon.c \
curve25519_athlon_const.s \
curve25519_athlon_fromdouble.s \
curve25519_athlon_init.s \
curve25519_athlon_mainloop.s \
curve25519_athlon_mult.s \
curve25519_athlon_square.s \
curve25519_athlon_todouble.s
	sh -e curve25519.impl.do $(CC) > curve25519.impl.new
	mv curve25519.impl.new curve25519.impl
