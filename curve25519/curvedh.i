/* Copyright 2011 Ian Goldberg
 *
 * This file is part of Sphinx.
 * 
 * Sphinx is free software: you can redistribute it and/or modify
 * it under the terms of version 3 of the GNU Lesser General Public
 * License as published by the Free Software Foundation.
 * 
 * Sphinx is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with Sphinx.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

%module curvedh
%{
#include "curvedh.h"
%}

%include "cstring.i"
%cstring_chunk_output(unsigned char *curve_out, 32);
%apply (char *STRING, int LENGTH) { (unsigned char *base_data, int base_len) };
%apply (char *STRING, int LENGTH) { (unsigned char *exp_data, int exp_len) };

void curvedh(unsigned char *curve_out, unsigned char *exp_data, int exp_len,
                unsigned char *base_data, int base_len);

void basepoint(unsigned char *curve_out);

void makesecret(unsigned char *curve_out, unsigned char *exp_data, int exp_len);
