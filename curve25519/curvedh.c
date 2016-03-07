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

#include <stdio.h>
#include <string.h>
#include "curvedh.h"
#include "curve25519.h"

#ifdef DEBUG
static void dump(char *label, unsigned char *data)
{
    int i;
    printf("%6s: ", label);
    for(i=0;i<32;++i) {
	printf("%02x", data[i]);
    }
    printf("\n");
}
#endif

void curvedh(unsigned char *curve_out, unsigned char *exp_data, int exp_len,
		unsigned char *base_data, int base_len)
{
    int i;

    /* In case we error out early, wipe to 0 */
    for(i=0;i<32;++i) { curve_out[i] = '\0'; }

    /* It would be nice to throw a Python exception here; not sure how */
    if (base_len != 32 || exp_len != 32) return;

#ifdef DEBUG
dump("base", base_data);
dump("exp", exp_data);
#endif
    curve25519(curve_out, exp_data, base_data);
#ifdef DEBUG
dump("out", curve_out);
#endif
}

/* Make the base point for the curve */
void basepoint(unsigned char *curve_out)
{

    int i;

    curve_out[0] = 9;
    for(i=1;i<32;++i) { curve_out[i] = '\0'; }
}

/* Make a secret key given 32 random bytes */
void makesecret(unsigned char *curve_out, unsigned char *exp_data, int exp_len)
{
    int i;

    /* In case we error out early, wipe to 0 */
    for(i=0;i<32;++i) { curve_out[i] = '\0'; }

    /* It would be nice to throw a Python exception here; not sure how */
    if (exp_len != 32) return;

    memmove(curve_out, exp_data, 32);
    curve_out[0] &= 248;
    curve_out[31] &= 127;
    curve_out[31] |= 64;
}

