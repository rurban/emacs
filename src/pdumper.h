/* Header file for the portable dumper.

Copyright (C) 2016 Free Software Foundation,
Inc.

This file is part of GNU Emacs.

GNU Emacs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

GNU Emacs is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Emacs.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef EMACS_PDUMPER_H
#define EMACS_PDUMPER_H

#include "lisp.h"

/* The portable dumper automatically preserves the Lisp heap and any C
   variables to which the Lisp heap points.  It doesn't know anything
   about other C variables.  The functions below allow code from other
   parts of Emacs to tell the portable dumper about other bits of
   information to preserve in dumped images.

   These memory-records are themselves preserved in the dump, so call
   the functions below only on the !initialized init path, just
   like staticpro.

   There are no special functions to preserve a global Lisp_Object.
   You should just staticpro these.  */

/* Indicate in source code that we're deliberately relying on pdumper
   not preserving the given value.  Compiles to nothing --- for humans
   only.  */
#define PDUMPER_IGNORE(thing) ((void) &(thing))

/* Remember the value of THING in dumped images.  THING must not
   contain any pointers or Lisp_Object variables: these values are not
   valid across dump and load.  */
#define PDUMPER_REMEMBER_SCALAR(thing)                  \
  pdumper_remember_scalar (&(thing), sizeof (thing))
void pdumper_remember_scalar (void *data, ptrdiff_t nbytes);

/* Remember the pointer at *PTR.  *PTR must be null or point to a Lisp
   object.  TYPE is the rough type of Lisp object to which *PTR
   points.  */
void pdumper_remember_lv_raw_ptr (void* ptr, enum Lisp_Type type);

/* Remember the pointer at *PTR.  *PTR must be null or point to
   something in the Emacs process image (e.g., a function).  */
void pdumper_remember_emacs_ptr (void *ptr);

typedef void (*pdumper_hook)(void);
void pdumper_do_now_and_after_load (pdumper_hook);

/* Macros useful in pdumper callback functions.  Assign a value if
   we're loading a dump and the value needs to be reset to its
   original value, and if we're initializing for the first time,
   assert that the value has the expected original value.  */

#define PDUMPER_RESET(variable, value)         \
  do {                                         \
    if (dumped_with_pdumper)                   \
      (variable) = (value);                    \
    else                                       \
      eassert ((variable) == (value));         \
  } while (0)

#define PDUMPER_RESET_LV(variable, value)         \
  do {                                            \
    if (dumped_with_pdumper)                      \
      (variable) = (value);                       \
    else                                          \
      eassert (EQ ((variable), (value)));         \
  } while (0)

/* Actually load a dump.  */

enum pdumper_load_result
  {
    PDUMPER_LOAD_SUCCESS,
    PDUMPER_NOT_LOADED /* Not returned: useful for callers */,
    PDUMPER_LOAD_FILE_NOT_FOUND,
    PDUMPER_LOAD_BAD_FILE_TYPE,
    PDUMPER_LOAD_OOM,
    PDUMPER_LOAD_VERSION_MISMATCH,
    PDUMPER_LOAD_ERROR,
  };

enum pdumper_load_result pdumper_load (const char *dump_filename);

_GL_ATTRIBUTE_CONST
bool pdumper_object_p (const void *obj);
#define PDUMPER_NO_OBJECT ((enum Lisp_Type) -1)
_GL_ATTRIBUTE_CONST
enum Lisp_Type pdumper_find_object_type (const void *obj);
_GL_ATTRIBUTE_CONST
bool pdumper_object_p_precise (const void *obj);

bool pdumper_marked_p (const void *obj);
void pdumper_set_marked (const void *obj);
void pdumper_clear_marks (void);

void syms_of_pdumper (void);



#endif
