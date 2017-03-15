/* libnettle+libhogweed glue for GNU Emacs.
   Copyright (C) 2017 Free Software Foundation, Inc.

This file is part of GNU Emacs.

GNU Emacs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

GNU Emacs is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Emacs.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef EMACS_NETTLE_DEFINED
#define EMACS_NETTLE_DEFINED

#ifdef HAVE_NETTLE

/* PGP protocol helpers. */
#include <nettle/pgp.h>

/* Public-key crypto. */
#include <nettle/rsa.h>
#include <nettle/dsa.h>
#include <nettle/ecc.h>
#include <nettle/pkcs1.h>

#include <nettle/nettle-meta.h>

/* Cipher modes. */

#include <nettle/cbc.h>
#include <nettle/ctr.h>
#include <nettle/gcm.h>

/* Keyed hash functions. */
#include <nettle/hmac.h>
#include <nettle/umac.h>

/* Key derivation functions. */

#include <nettle/pbkdf2.h>

/* Randomness functions. */

#include <nettle/yarrow.h>

#endif

#define NETTLE_STRING_EQUAL_UNIBYTE(LISP_STRING, C_STRING)\
   (! NILP (Fstring_equal (LISP_STRING, build_unibyte_string (C_STRING))))

extern void syms_of_nettle (void);

#endif
