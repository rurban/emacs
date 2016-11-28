#include <config.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "blockinput.h"
#include "buffer.h"
#include "charset.h"
#include "coding.h"
#include "frame.h"
#include "getpagesize.h"
#include "intervals.h"
#include "lisp.h"
#include "pdumper.h"
#include "window.h"
#include "fingerprint.h"

/* We require an architecture in which all pointers are the same size
   and have the same layout.  */
verify (sizeof (ptrdiff_t) == sizeof (void*));
verify (sizeof (void (*)(void)) == sizeof (void*));
verify (sizeof (ptrdiff_t) <= sizeof (Lisp_Object));
verify (sizeof (ptrdiff_t) <= sizeof (EMACS_INT));

bool pdumper_loading_dump;

static const char dump_magic[16] = {
  'D', 'U', 'M', 'P', 'E', 'D',
  'G', 'N', 'U',
  'E', 'M', 'A', 'C', 'S'
};

static pdumper_hook dump_hooks[24];
static int nr_dump_hooks = 0;

static struct
{
  void *mem;
  int sz;
} remembered_data[32];
static int nr_remembered_data = 0;

/* Maximum number of cons cells in a list to print in a contiguous
   chunk before going back to the normal dumping strategy.  */
static const ptrdiff_t max_cons_chain_depth = 256;

typedef int32_t dump_off_t;

enum dump_reloc_type
  {
    /* dump_ptr = dump_ptr + emacs_basis() */
    RELOC_DUMP_TO_EMACS_RAW_PTR,
    /* dump_ptr = dump_ptr + dump_base */
    RELOC_DUMP_TO_DUMP_RAW_PTR,
    /* dump_lv = make_lisp_ptr (
         dump_lv + dump_base,
         type - RELOC_DUMP_TO_DUMP_LV)
       (Special case for symbols: make_lisp_symbol)
       Must be second-last.  */
    RELOC_DUMP_TO_DUMP_LV,
    /* dump_lv = make_lisp_ptr (
         dump_lv + emacs_basis(),
         type - RELOC_DUMP_TO_DUMP_LV)
       (Special case for symbols: make_lisp_symbol.)
       Must be last.  */
    RELOC_DUMP_TO_EMACS_LV = RELOC_DUMP_TO_DUMP_LV + 8,
  };

enum emacs_reloc_type
  {
    /* Copy raw bytes from the dump into Emacs.  */
    RELOC_EMACS_COPY_FROM_DUMP,
    /* Set a piece of memory in Emacs to a value we store directly in
       this relocation.  The length field contains the number of bytes
       we actually copy into Emacs.  */
    RELOC_EMACS_IMMEDIATE,
    /* Set an aligned pointer-sized object in Emacs to a dump offset.  */
    RELOC_EMACS_DUMP_PTR_RAW,
    /* Set an aligned pointer-sized object in Emacs to point to
       something also in Emacs.  */
    RELOC_EMACS_EMACS_PTR_RAW,
    /* Set an aligned Lisp_Object in Emacs to point to a value in the
       dump.  Must be last.  */
    RELOC_EMACS_DUMP_LV,
  };

#define EMACS_RELOC_TYPE_BITS 3
#define EMACS_RELOC_LENGTH_BITS                         \
  (sizeof (dump_off_t) * 8 - EMACS_RELOC_TYPE_BITS)

struct emacs_reloc
{
  ENUM_BF (emacs_reloc_type) type : EMACS_RELOC_TYPE_BITS;
  dump_off_t length : EMACS_RELOC_LENGTH_BITS;
  dump_off_t emacs_offset;
  union
  {
    dump_off_t dump_offset;
    dump_off_t emacs_offset2;
    intmax_t immediate;
    int8_t immediate_i8;
    int16_t immediate_i16;
    int32_t immediate_i32;
  } u;
};

struct dump_table_locator
{
  dump_off_t offset;
  dump_off_t nr_entries;
};

struct dump_reloc
{
  // XXX: We have a ton of these.  Combine type and offset into one
  // 32-bit word.  Force alignment.
  enum dump_reloc_type type;
  dump_off_t offset;
};

/* Format of an Emacs portable dump file.  All offsets are relative to
   the beginning of the file.  An Emacs portable dump file is coupled
   to exactly the Emacs binary that produced it, so details of
   alignment and endianness are unimportant.

   An Emacs dump file contains the contents of the Lisp heap.
   On startup, Emacs can start faster by mapping a dump file into
   memory and using the objects contained inside it instead of
   performing initialization from scratch.

   The dump file can be loaded at arbitrary locations in memory, so it
   includes a table of relocations that let Emacs adjust the pointers
   embedded in the dump file to account for the location where it was
   actually loaded.

   Dump files can contain pointers to other objects in the dump file
   or to parts of the Emacs binary.  */
struct dump_header
{
  /* File type magic.  */
  char magic[sizeof (dump_magic)];

  /* Associated Emacs binary.  */
  uint8_t fingerprint[32];

  /* Relocation table for the dump file; each entry is a
     struct dump_reloc.  */
  struct dump_table_locator dump_relocs;

  /* "Relocation" table we abuse to hold information about the
     location and type of each lisp object in the dump.  We need for
     pdumper_object_type and ultimately for conservative GC.  */
  struct dump_table_locator object_starts;

  /* Relocation table for Emacs; each entry is a struct
     emacs_reloc.  */
  struct dump_table_locator emacs_relocs;

  /* Start of sub-region of hot region that we can discard after load
     completes.  The discardable region ends at hot_end.  */
  dump_off_t hot_discardable_start;

  /* End of the region that we expect to have many relocations.  */
  dump_off_t hot_end;

};

struct dump_tailq
{
  Lisp_Object head;
  Lisp_Object tail;
};

enum cold_op
  {
    COLD_OP_OBJECT,
    COLD_OP_STRING,
    COLD_OP_CHARSET,
    COLD_OP_BUFFER,
  };

/* Information we use while we dump.  Note that we're not the garbage
   collector and can operate under looser constraints: specifically,
   we allocate memory during the dumping process.  */
struct dump_context
{
  /* Header we'll write to the dump file when done.  */
  struct dump_header header;

  Lisp_Object old_purify_flag;
  Lisp_Object old_post_gc_hook;

  /* File descriptor for dumpfile; < 0 if closed.  */
  int fd;
  /* Name of dump file --- used for error reporting.  */
  Lisp_Object dump_filename;
  /* Current offset in dump file.  */
  ptrdiff_t offset;

  /* Starting offset of current object.  */
  ptrdiff_t obj_offset;
  /* Flags for writing the current object.  */
  int flags;
  /* Depth of cons-chain dumping.  */
  ptrdiff_t cons_chain_depth;

  ptrdiff_t end_heap;

  /* Hash mapping objects we've already dumped to their offsets.  */
  Lisp_Object objects_dumped;

  /* Hash mapping objects to where we got them.  Used for debugging.  */
  Lisp_Object referrers;
  Lisp_Object current_referrer;

#ifdef ENABLE_CHECKING
  bool have_current_referrer;
#endif

  /* Queue of objects to dump.  */
  struct dump_tailq dump_queue;
  /* Fixups in the dump file.  */
  Lisp_Object fixups;
  /* Queue of copied objects for special treatment.  */
  Lisp_Object copied_queue;
  /* Queue of cold objects to dump.  */
  Lisp_Object cold_queue;

  /* Relocations in the dump.  */
  Lisp_Object dump_relocs;
  /* Object starts.  */
  Lisp_Object object_starts;
  /* Relocations in Emacs.  */
  Lisp_Object emacs_relocs;
};



#define DUMP_OBJECT_INTERN (1<<0)
#define DUMP_OBJECT_RECORD_START (1<<1)
#define DUMP_OBJECT_DRY_RUN (1<<2)
#define DUMP_OBJECT_FORCE_WORD_ALIGNMENT (1<<3)
#define DUMP_OBJECT_PROHIBIT_ENQUEUE (1<<4)

static ptrdiff_t dump_object (struct dump_context *ctx, Lisp_Object object);
static ptrdiff_t dump_object_1 (struct dump_context *ctx,
                                Lisp_Object object,
                                int flags);

static void
dump_push (Lisp_Object *where, Lisp_Object newelt)
{
  *where = Fcons (newelt, *where);
}

static Lisp_Object
dump_pop (Lisp_Object *where)
{
  Lisp_Object ret = XCAR (*where);
  *where = XCDR (*where);
  return ret;
}

static bool
dump_tracking_referrers_p (struct dump_context *ctx)
{
  return !NILP (ctx->referrers);
}

static void
dump_set_have_current_referrer (struct dump_context *ctx, bool have)
{
#ifdef ENABLE_CHECKING
  ctx->have_current_referrer = have;
#endif
}

#ifdef ENABLE_CHECKING
/* Define as a macro so we can avoid evaluating OBJECT
   if we dont want referrer tracking.  */
# define DUMP_SET_REFERRER(ctx, object)                   \
  do {                                                   \
    struct dump_context *_ctx = (ctx);                   \
    eassert (!_ctx->have_current_referrer);              \
    dump_set_have_current_referrer (_ctx, true);         \
    if (dump_tracking_referrers_p (_ctx))                \
      ctx->current_referrer = (object);                  \
  } while (0);
#else
# define DUMP_SET_REFERRER(ctx, object)                   \
  do {                                                   \
    struct dump_context *_ctx = (ctx);                   \
    if (dump_tracking_referrers_p (_ctx))                \
      ctx->current_referrer = (object);                  \
  } while (0);
#endif

static void
dump_clear_referrer (struct dump_context *ctx)
{
#ifdef ENABLE_CHECKING
  eassert (ctx->have_current_referrer);
  dump_set_have_current_referrer (ctx, false);
#endif
  if (dump_tracking_referrers_p (ctx))
    ctx->current_referrer = Qnil;
}

static Lisp_Object
dump_ptr_referrer (const char *label, void *address)
{
  char buf[128];
  buf[0] = '\0';
  sprintf (buf, "%s @ %p", label, address);
  return build_string (buf);
}

static void
print_paths_to_root (struct dump_context *ctx, Lisp_Object object);

static void dump_remember_cold_op (struct dump_context *ctx,
                                   enum cold_op op,
                                   Lisp_Object arg);

_Noreturn
static void
error_unsupported_dump_object (struct dump_context *ctx,
                               Lisp_Object object,
                               const char* msg)
{
  if (dump_tracking_referrers_p (ctx))
    print_paths_to_root (ctx, object);
  error ("unsupported object type in dump: %s", msg);
}

static ptrdiff_t
emacs_basis (void)
{
  return (ptrdiff_t) &Vpurify_flag;
}

static ptrdiff_t
emacs_offset (const void *emacs_ptr)
{
  /* TODO: assert that emacs_ptr is actually in emacs */
  eassert (emacs_ptr != NULL);
  ptrdiff_t emacs_ptr_value = (ptrdiff_t) emacs_ptr;
  ptrdiff_t emacs_ptr_relative = emacs_ptr_value - emacs_basis ();
  return emacs_ptr_relative;
}

/* Return whether OBJECT is a symbol the storage of which is built
   into Emacs (and so is invariant across ASLR).  */
static bool
dump_builtin_symbol_p (Lisp_Object object)
{
  if (!SYMBOLP (object))
    return false;
  char* bp = (char*) lispsym;
  struct Lisp_Symbol *s = XSYMBOL (object);
  char* sp = (char*) s;
  return bp <= sp && sp < bp + sizeof (lispsym);
}

/* Return whether OBJECT has the same bit pattern in all Emacs
   invocations --- i.e., is invariant across a dump.  */
static bool
dump_object_self_representing_p (Lisp_Object object)
{
  return INTEGERP (object) || dump_builtin_symbol_p (object);
}

#define DEFINE_FROMLISP_FUNC(fn, type)          \
  static type                                   \
  fn (Lisp_Object value)                        \
  {                                             \
    type result;                                \
    CONS_TO_INTEGER (value, type, result);      \
    return result;                              \
  }

DEFINE_FROMLISP_FUNC (intmax_t_from_lisp, intmax_t);
DEFINE_FROMLISP_FUNC (ptrdiff_t_from_lisp, ptrdiff_t);
DEFINE_FROMLISP_FUNC (dump_off_from_lisp, dump_off_t);

static void
dump_tailq_init (struct dump_tailq *tailq)
{
  tailq->head = tailq->tail = Qnil;
}

static void
dump_tailq_append (struct dump_tailq *tailq, Lisp_Object value)
{
  Lisp_Object link = Fcons (value, Qnil);
  if (NILP (tailq->head))
    {
      eassert (NILP (tailq->tail));
      tailq->head = tailq->tail = link;
    }
  else
    {
      eassert (!NILP (tailq->tail));
      XSETCDR (tailq->tail, link);
      tailq->tail = link;
    }
}

static bool
dump_tailq_empty_p (struct dump_tailq *tailq)
{
  return NILP (tailq->head);
}

static Lisp_Object
dump_tailq_pop (struct dump_tailq *tailq)
{
  eassert (!dump_tailq_empty_p (tailq));
  Lisp_Object value = XCAR (tailq->head);
  tailq->head = XCDR (tailq->head);
  if (NILP (tailq->head))
    tailq->tail = Qnil;
  return value;
}

static void
dump_write (struct dump_context *ctx, const void *buf, ptrdiff_t nbyte)
{
  eassert (nbyte == 0 || buf != NULL);
  eassert (ctx->obj_offset == 0);
  eassert ((ctx->flags & DUMP_OBJECT_DRY_RUN) == 0);
  if (emacs_write (ctx->fd, buf, nbyte) < nbyte)
    report_file_error ("Could not write to dump file", ctx->dump_filename);
  ctx->offset += nbyte;
}

static void
dump_seek (struct dump_context *ctx, ptrdiff_t offset)
{
  eassert (ctx->obj_offset == 0);
  if (lseek (ctx->fd, offset, SEEK_SET) < 0)
    report_file_error ("Setting file position",
                       ctx->dump_filename);
  ctx->offset = offset;
}

static void
dump_write_zero (struct dump_context *ctx, ptrdiff_t nbytes)
{
  while (nbytes > 0)
    {
      ptrdiff_t zero = 0;
      ptrdiff_t to_write = sizeof (zero);
      if (to_write > nbytes)
        to_write = nbytes;
      dump_write (ctx, &zero, to_write);
      nbytes -= to_write;
    }
}

static void
dump_align_output (struct dump_context *ctx, ptrdiff_t alignment)
{
  if (ctx->offset % alignment != 0)
    dump_write_zero (ctx, alignment - (ctx->offset % alignment));
}

static ptrdiff_t
dump_object_start (struct dump_context *ctx,
                   int alignment,
                   void *out,
                   ptrdiff_t outsz)
{
  eassert (ctx->obj_offset == 0);
  if ((ctx->flags & DUMP_OBJECT_FORCE_WORD_ALIGNMENT) &&
      alignment > sizeof (void*))
    alignment = sizeof (void*);
  if ((ctx->flags & DUMP_OBJECT_DRY_RUN) == 0)
    dump_align_output (ctx, alignment);
  ctx->obj_offset = ctx->offset;
  memset (out, 0, outsz);
  return ctx->offset;
}

static ptrdiff_t
dump_object_finish (struct dump_context *ctx,
                    const void *out,
                    ptrdiff_t sz)
{
  ptrdiff_t offset = ctx->obj_offset;
  eassert (offset > 0);
  eassert (offset == ctx->offset); /* No intervening writes.  */
  ctx->obj_offset = 0;
  if ((ctx->flags & DUMP_OBJECT_DRY_RUN) == 0)
    dump_write (ctx, out, sz);
  return offset;
}

/* Return offset at which OBJECT has been dumped, or 0 if OBJECT has
   not been dumped.  */
static ptrdiff_t
dump_recall_object (struct dump_context *ctx, Lisp_Object object)
{
  Lisp_Object dumped = ctx->objects_dumped;
  return ptrdiff_t_from_lisp (Fgethash (object, dumped, make_number (0)));
}

static void
dump_remember_object (struct dump_context *ctx,
                      Lisp_Object object,
                      ptrdiff_t offset)
{
  Fputhash (object, INTEGER_TO_CONS (offset), ctx->objects_dumped);
}

static void
dump_note_reachable (struct dump_context *ctx, Lisp_Object object)
{
#ifdef ENABLE_CHECKING
  eassert (ctx->have_current_referrer);
#endif
  if (!dump_tracking_referrers_p (ctx))
    return;
  Lisp_Object referrer = ctx->current_referrer;
  Lisp_Object obj_referrers = Fgethash (object, ctx->referrers, Qnil);
  if (NILP (Fmemq (referrer, obj_referrers)))
    Fputhash (object, Fcons (referrer, obj_referrers), ctx->referrers);
}

/* If this object lives in the Emacs image and not on the heap, return
   a pointer to the object data.  Otherwise, return NULL.  */
static void*
dump_object_emacs_ptr (Lisp_Object lv)
{
  if (SUBRP (lv))
    return XSUBR (lv);
  if (dump_builtin_symbol_p (lv))
    return XSYMBOL (lv);
  return NULL;
}

static void
dump_enqueue_object (struct dump_context *ctx, Lisp_Object object)
{
  if ((!dump_object_self_representing_p (object) ||
       dump_object_emacs_ptr (object)) &&
      dump_recall_object (ctx, object) == 0)
    {
      eassert ((ctx->flags & DUMP_OBJECT_PROHIBIT_ENQUEUE) == 0);

      dump_remember_object (ctx, object, -1);
      if (BOOL_VECTOR_P (object) || FLOATP (object))
        dump_remember_cold_op (ctx, COLD_OP_OBJECT, object);
      else
        dump_tailq_append (&ctx->dump_queue, object);
    }
  dump_note_reachable (ctx, object);
}

static void
print_paths_to_root_1 (struct dump_context *ctx,
                       Lisp_Object object,
                       int level)
{
  Lisp_Object referrers = Fgethash (object, ctx->referrers, Qnil);
  while (!NILP (referrers))
    {
      Lisp_Object referrer = XCAR (referrers);
      referrers = XCDR (referrers);
      Lisp_Object repr = Fprin1_to_string (referrer, Qnil);
      for (int i = 0; i < level; ++i)
        fputc (' ', stderr);
      fprintf (stderr, "%s\n", SDATA (repr));
      print_paths_to_root_1 (ctx, referrer, level + 1);
    }
}

static void
print_paths_to_root (struct dump_context *ctx, Lisp_Object object)
{
  print_paths_to_root_1 (ctx, object, 0);
}

static void
dump_remember_cold_op (struct dump_context *ctx,
                       enum cold_op op,
                       Lisp_Object arg)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;
  dump_push (&ctx->cold_queue, Fcons (make_number (op), arg));
}

/* Add a dump relocation that points into Emacs.

   Add a relocation that updates the pointer stored at DUMP_OFFSET to
   point into the Emacs binary upon dump load.  The pointer-sized
   value at DUMP_OFFSET in the dump file should contain a number
   relative to emacs_basis().  */
static void
dump_reloc_dump_to_emacs_raw_ptr (struct dump_context *ctx,
                                  ptrdiff_t dump_offset)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;
  dump_push (&ctx->dump_relocs,
             list2 (INTEGER_TO_CONS (RELOC_DUMP_TO_EMACS_RAW_PTR),
                    INTEGER_TO_CONS (dump_offset)));
}

/* Add a dump relocation that points a Lisp_Object back at the dump.

   Add a relocation that updates the Lisp_Object at DUMP_OFFSET in the
   dump to point to another object in the dump.  The Lisp_Object-sized
   value at DUMP_OFFSET in the dump file should contain the offset of
   the target object relative to the start of the dump.  */
static void
dump_reloc_dump_to_dump_lv (struct dump_context *ctx,
                            ptrdiff_t dump_offset,
                            enum Lisp_Type type)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  ptrdiff_t reloc_type;
  switch (type)
    {
    case Lisp_Symbol:
    case Lisp_Misc:
    case Lisp_String:
    case Lisp_Vectorlike:
    case Lisp_Cons:
    case Lisp_Float:
      reloc_type = RELOC_DUMP_TO_DUMP_LV + type;
      break;
    default:
      emacs_abort ();
    }

  dump_push (&ctx->dump_relocs,
             list2 (INTEGER_TO_CONS (reloc_type),
                    INTEGER_TO_CONS (dump_offset)));
}

/* Add a dump relocation that points a raw pointer back at the dump.

   Add a relocation that updates the raw pointer at DUMP_OFFSET in the
   dump to point to another object in the dump.  The pointer-sized
   value at DUMP_OFFSET in the dump file should contain the offset of
   the target object relative to the start of the dump.  */
static void
dump_reloc_dump_to_dump_raw_ptr (struct dump_context *ctx,
                                 ptrdiff_t dump_offset)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  dump_push (&ctx->dump_relocs,
             list2 (INTEGER_TO_CONS (RELOC_DUMP_TO_DUMP_RAW_PTR),
                    INTEGER_TO_CONS (dump_offset)));
}

/* Add a dump relocation that points to a Lisp object in Emacs.

   Add a relocation that updates the Lisp_Object at DUMP_OFFSET in the
   dump to point to a lisp object in Emacs.  The Lisp_Object-sized
   value at DUMP_OFFSET in the dump file should contain the offset of
   the target object relative to emacs_basis().  TYPE is the type of
   Lisp value.  */
static void
dump_reloc_dump_to_emacs_lv (struct dump_context *ctx,
                             ptrdiff_t dump_offset,
                             enum Lisp_Type type)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  ptrdiff_t reloc_type;
  switch (type)
    {
    case Lisp_Misc:
    case Lisp_String:
    case Lisp_Vectorlike:
    case Lisp_Cons:
    case Lisp_Float:
      reloc_type = RELOC_DUMP_TO_EMACS_LV + type;
      break;
    default:
      emacs_abort ();
    }

  dump_push (&ctx->dump_relocs,
             list2 (INTEGER_TO_CONS (reloc_type),
                    INTEGER_TO_CONS (dump_offset)));
}

/* Add an Emacs relocation that copies arbitrary bytes from the dump.

   When the dump is loaded, Emacs copies SIZE bytes from OFFSET in
   dump to LOCATION in the Emacs data section.  This copying happens
   after other relocations, so it's all right to, say, copy a
   Lisp_Value (since by the time we copy the Lisp_Value, it'll have
   been adjusted to account for the location of the running Emacs and
   dump file).  */
static void
dump_emacs_reloc_copy_from_dump (struct dump_context *ctx,
                                 ptrdiff_t dump_offset,
                                 void* emacs_ptr,
                                 ptrdiff_t size)
{
  eassert (size >= 0);
  eassert (size < (1 << EMACS_RELOC_LENGTH_BITS));

  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  if (size == 0)
    return;

  dump_push (&ctx->emacs_relocs,
             list4 (make_number (RELOC_EMACS_COPY_FROM_DUMP),
                    INTEGER_TO_CONS (emacs_offset (emacs_ptr)),
                    INTEGER_TO_CONS (dump_offset),
                    INTEGER_TO_CONS (size)));
}

/* Add an Emacs relocation that sets values to arbitrary bytes.

   When the dump is loaded, Emacs copies SIZE bytes from the
   relocation itself to the adjusted location inside Emacs EMACS_PTR.
   SIZE is the number of bytes to copy.  See struct emacs_reloc for
   the maximum size that this mechanism can support.  The value comes
   from VALUE_PTR.
 */
static void
dump_emacs_reloc_immediate (struct dump_context *ctx,
                            const void *emacs_ptr,
                            const void *value_ptr,
                            ptrdiff_t size)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  intmax_t value = 0;
  eassert (size <= sizeof (value));
  memcpy (&value, value_ptr, size);
  dump_push (&ctx->emacs_relocs,
             list4 (make_number (RELOC_EMACS_IMMEDIATE),
                    INTEGER_TO_CONS (emacs_offset (emacs_ptr)),
                    INTEGER_TO_CONS (value),
                    INTEGER_TO_CONS (size)));
}

#define DEFINE_EMACS_IMMEDIATE_FN(fnname, type)                         \
  static void                                                           \
  fnname (struct dump_context *ctx,                                     \
          const type *emacs_ptr,                                        \
          type value)                                                   \
  {                                                                     \
    dump_emacs_reloc_immediate (                                        \
      ctx, emacs_ptr, &value, sizeof (value));                          \
  }

DEFINE_EMACS_IMMEDIATE_FN (dump_emacs_reloc_immediate_lv, Lisp_Object);
DEFINE_EMACS_IMMEDIATE_FN (dump_emacs_reloc_immediate_ptrdiff_t, ptrdiff_t);
DEFINE_EMACS_IMMEDIATE_FN (dump_emacs_reloc_immediate_emacs_int, EMACS_INT);
DEFINE_EMACS_IMMEDIATE_FN (dump_emacs_reloc_immediate_int, int);
DEFINE_EMACS_IMMEDIATE_FN (dump_emacs_reloc_immediate_bool, bool);

/* Add an emacs relocation that makes a raw pointer in Emacs point
   into the dump.  */
static void
dump_emacs_reloc_to_dump_ptr_raw (struct dump_context *ctx,
                                  const void* emacs_ptr,
                                  ptrdiff_t dump_offset)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  dump_push (&ctx->emacs_relocs,
             list3 (make_number (RELOC_EMACS_DUMP_PTR_RAW),
                    INTEGER_TO_CONS (emacs_offset (emacs_ptr)),
                    INTEGER_TO_CONS (dump_offset)));
}

/* Add an emacs relocation that points into the dump.

   When the dump is loaded, the Lisp_Object at EMACS_ROOT in Emacs to
   point to VALUE.  VALUE can be any Lisp value; this function
   automatically queues the value for dumping if necessary.  */
static void
dump_emacs_reloc_to_dump_lv (struct dump_context *ctx,
                             Lisp_Object *emacs_ptr,
                             Lisp_Object value)
{
  if (dump_object_self_representing_p (value))
    dump_emacs_reloc_immediate_lv (ctx, emacs_ptr, value);
  else
    {
      if ((ctx->flags & DUMP_OBJECT_DRY_RUN) == 0)
        dump_push (
          &ctx->emacs_relocs,
          list3 (INTEGER_TO_CONS (RELOC_EMACS_DUMP_LV + XTYPE (value)),
                 INTEGER_TO_CONS (emacs_offset (emacs_ptr)),
                 value));
      dump_enqueue_object (ctx, value);
    }
}

/* Add an emacs relocation that makes a raw pointer in Emacs point
   back into the Emacs image.  */
static void
dump_emacs_reloc_to_emacs_ptr_raw (struct dump_context *ctx,
                                   void* emacs_ptr,
                                   void *target_emacs_ptr)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  dump_push (&ctx->emacs_relocs,
             list3 (make_number (RELOC_EMACS_EMACS_PTR_RAW),
                    INTEGER_TO_CONS (emacs_offset (emacs_ptr)),
                    INTEGER_TO_CONS (emacs_offset (target_emacs_ptr))));
}

/* Add an Emacs relocation that makes a raw pointer in Emacs point to
   a different part of Emacs.  */

enum dump_fixup_type
  {
    DUMP_FIXUP_LISP_OBJECT,
    DUMP_FIXUP_LISP_OBJECT_RAW,
    DUMP_FIXUP_PTR_DUMP_RAW,
  };

enum dump_lv_fixup_type
  {
    LV_FIXUP_LISP_OBJECT,
    LV_FIXUP_RAW_POINTER,
  };

/* Make something in the dump point to a lisp object.

   CTX is a dump context.  DUMP_OFFSET is the location in the dump to
   fix.  VALUE is the object to which the location in the dump
   should point.

   If FIXUP_SUBTYPE is LV_FIXUP_LISP_OBJECT, we expect a Lisp_Object
   at DUMP_OFFSET.  If it's LV_FIXUP_RAW_POINTER, we expect a pointer.
 */
static void
dump_remember_fixup_lv (struct dump_context *ctx,
                        ptrdiff_t dump_offset,
                        Lisp_Object value,
                        enum dump_lv_fixup_type fixup_subtype)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  dump_push (&ctx->fixups,
             list3 (
               make_number (fixup_subtype == LV_FIXUP_LISP_OBJECT
                            ? DUMP_FIXUP_LISP_OBJECT
                            : DUMP_FIXUP_LISP_OBJECT_RAW),
               INTEGER_TO_CONS (dump_offset),
               value));
}

/* Remember to fix up the dump file such that the pointer-sized value
   at DUMP_OFFSET points to NEW_DUMP_OFFSET in the dump file and to
   its absolute address at runtime.  */
static void
dump_remember_fixup_ptr_raw (struct dump_context *ctx,
                             ptrdiff_t dump_offset,
                             ptrdiff_t new_dump_offset)
{
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  dump_push (&ctx->fixups,
             list3 (
               make_number (DUMP_FIXUP_PTR_DUMP_RAW),
               INTEGER_TO_CONS (dump_offset),
               INTEGER_TO_CONS (new_dump_offset)));
}

static void
dump_root_visitor (Lisp_Object *root_ptr, enum gc_root_type type, void *data)
{
  struct dump_context *ctx = data;
  Lisp_Object value = *root_ptr;
  if (type == GC_ROOT_C_SYMBOL)
    {
      eassert (dump_builtin_symbol_p (value));
      /* Remember to dump the object itself later along with all the
         rest of the copied-to-Emacs objects.  */
      DUMP_SET_REFERRER (ctx, build_string ("built-in symbol list"));
      dump_enqueue_object (ctx, value);
      dump_clear_referrer (ctx);
    }
  else
    {
      DUMP_SET_REFERRER (ctx, dump_ptr_referrer ("emacs root", root_ptr));
      dump_emacs_reloc_to_dump_lv (ctx, root_ptr, *root_ptr);
      dump_clear_referrer (ctx);
    }
}

/* Kick off the dump process by queuing up the static GC roots.  */
static void
dump_roots (struct dump_context *ctx)
{
  struct gc_root_visitor visitor;
  memset (&visitor, 0, sizeof (visitor));
  visitor.visit = dump_root_visitor;
  visitor.data = ctx;
  visit_static_gc_roots (visitor);
}

static ptrdiff_t
field_relpos (const void *in_start, const void *in_field)
{
  ptrdiff_t in_start_val = (ptrdiff_t) in_start;
  ptrdiff_t in_field_val = (ptrdiff_t) in_field;
  eassert (in_start_val <= in_field_val);
  ptrdiff_t relpos = in_field_val - in_start_val;
  eassert (relpos < 1024); /* Sanity check.  */
  return relpos;
}

static void
cpyptr (void *out, const void *in)
{
  memcpy (out, in, sizeof (void *));
}

/* Convenience macro for regular assignment.  */
#define DUMP_FIELD_COPY(out, in, name) \
  do {                                 \
    (out)->name = (in)->name;          \
  } while (0)

static void
dump_field_lv_or_rawptr (struct dump_context *ctx,
                         void *out,
                         const void *in_start,
                         const void *in_field,
                         /* opt */ const enum Lisp_Type *raw_ptr_type)
{
  eassert (ctx->obj_offset > 0);

  Lisp_Object value;
  ptrdiff_t relpos = field_relpos (in_start, in_field);
  void *out_field = (char *) out + relpos;
  if (raw_ptr_type == NULL)
    {
      memcpy (&value, in_field, sizeof (value));
      if (dump_object_self_representing_p (value))
        {
          memcpy (out_field, &value, sizeof (value));
          return;
        }
    }
  else
    {
      void *ptrval;
      cpyptr (&ptrval, in_field);
      if (ptrval == NULL)
        return; /* Nothing to do.  */
      switch (*raw_ptr_type)
        {
        case Lisp_Symbol:
          value = make_lisp_symbol (ptrval);
          break;
        case Lisp_Misc:
        case Lisp_String:
        case Lisp_Vectorlike:
        case Lisp_Cons:
        case Lisp_Float:
          value = make_lisp_ptr (ptrval, *raw_ptr_type);
          break;
        default:
          emacs_abort ();
        }
    }

  /* Now value is the Lisp_Object to which we want to point whether or
     not the field is a raw pointer (in which case we just synthesized
     the Lisp_Object outselves) or a Lisp_Object (in which case we
     just copied the thing).  Add a fixup or relocation.  */

  ptrdiff_t out_value;
  ptrdiff_t out_field_offset = ctx->obj_offset + relpos;
  ptrdiff_t target_offset = dump_recall_object (ctx, value);
  if (target_offset > 0)
    {
      /* We've already dumped the referenced object, so we can emit
         the value and a relocation directly instead of indirecting
         through a fixup.  */
      out_value = target_offset;
      if (raw_ptr_type)
        dump_reloc_dump_to_dump_raw_ptr (ctx, out_field_offset);
      else
        dump_reloc_dump_to_dump_lv (ctx, out_field_offset, XTYPE (value));
    }
  else
    {
      /* We don't know about the target object yet, so add a fixup.
         When we process the fixup, we'll have dumped the target
         object.  */
      out_value = (ptrdiff_t) 0xDEADF00D;
      dump_remember_fixup_lv (ctx,
                              out_field_offset,
                              value,
                              ( raw_ptr_type
                                ? LV_FIXUP_RAW_POINTER
                                : LV_FIXUP_LISP_OBJECT ));
      if (target_offset == 0)
        dump_enqueue_object (ctx, value);
    }

  memcpy (out_field, &out_value, sizeof (out_value));
}

/* Set a pointer field on an output object during dump.

   CTX is the dump context.  OFFSET is the offset at which the current
   object starts.  OUT is a pointer to the dump output object.
   IN_START is the start of the current Emacs object.  IN_FIELD is a
   pointer to the field in that object.  TYPE is the type of pointer
   to which IN_FIELD points.
 */
static void
dump_field_lv_rawptr (struct dump_context *ctx,
                      void *out,
                      const void *in_start,
                      const void *in_field,
                      enum Lisp_Type type)
{
  dump_field_lv_or_rawptr (ctx, out, in_start, in_field, &type);
}

/* Set a Lisp_Object field on an output object during dump.

   CTX is a dump context.  OFFSET is the offset at which the current
   object starts.  OUT is a pointer to the dump output object.
   IN_START is the start of the current Emacs object.  IN_FIELD is a
   pointer to a Lisp_Object field in that object.

   Arrange for the dump to contain fixups and relocations such that,
   at load time, the given field of the output object contains a valid
   Lisp_Object pointing to the same notional object that *IN_FIELD
   contains now.

   See idomatic usage below.  */
static void
dump_field_lv (struct dump_context *ctx,
               void *out,
               const void *in_start,
               const Lisp_Object *in_field)
{
  dump_field_lv_or_rawptr (ctx, out, in_start, in_field, NULL);
}

/* Note that we're going to add a manual fixup for the given field
   later.  */
static void
dump_field_fixup_later (struct dump_context *ctx,
                        void *out,
                        const void *in_start,
                        const void *in_field)
{
  // TODO: more error checking
  (void) field_relpos (in_start, in_field);
}

/* Mark an output object field, which is as wide as a poiner, as being
   fixed up to point to a specific offset in the dump.  */
static void
dump_field_ptr_to_dump_offset (struct dump_context *ctx,
                               void *out,
                               const void *in_start,
                               const void *in_field,
                               ptrdiff_t target_dump_offset)
{
  eassert (ctx->obj_offset > 0);
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  ptrdiff_t relpos = field_relpos (in_start, in_field);
  dump_reloc_dump_to_dump_raw_ptr (ctx, ctx->obj_offset + relpos);
  ptrdiff_t outval = target_dump_offset;
  memcpy ((char*) out + relpos, &outval, sizeof (outval));
}

/* Mark a field as pointing to a place inside Emacs.

   CTX is the dump context.  OUT points to the out-object for the
   current dump function.  IN_START points to the start of the object
   being dumped.  IN_FIELD points to the field inside the object being
   dumped that we're dumping.  The contents of this field (which
   should be as wide as a pointer) are the Emacs pointer to dump.

 */
static void
dump_field_emacs_ptr (struct dump_context *ctx,
                      void *out,
                      const void *in_start,
                      const void *in_field)
{
  eassert (ctx->obj_offset > 0);
  if (ctx->flags & DUMP_OBJECT_DRY_RUN)
    return;

  ptrdiff_t abs_emacs_ptr;
  cpyptr (&abs_emacs_ptr, in_field);
  ptrdiff_t rel_emacs_ptr = abs_emacs_ptr - emacs_basis ();
  ptrdiff_t relpos = field_relpos (in_start, in_field);
  cpyptr ((char*) out + relpos, &rel_emacs_ptr);
  dump_reloc_dump_to_emacs_raw_ptr (ctx, ctx->obj_offset + relpos);
}

static ptrdiff_t
dump_cons (struct dump_context *ctx, const struct Lisp_Cons *cons)
{
  struct Lisp_Cons out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  dump_field_lv (ctx, &out, cons, &cons->car);
  dump_field_lv (ctx, &out, cons, &cons->u.cdr);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_interval_tree (struct dump_context *ctx,
                    INTERVAL tree,
                    ptrdiff_t parent_offset)
{
  // TODO: output tree breadth-first?
  struct interval out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, tree, total_length);
  DUMP_FIELD_COPY (&out, tree, position);
  if (tree->left)
    dump_field_fixup_later (ctx, &out, tree, &tree->left);
  if (tree->right)
    dump_field_fixup_later (ctx, &out, tree, &tree->right);
  if (!tree->up_obj)
    {
      eassert (parent_offset != 0);
      dump_field_ptr_to_dump_offset (
        ctx, &out,
        tree, &tree->up.interval,
        parent_offset);
    }
  else
    dump_field_lv (ctx, &out, tree, &tree->up.obj);
  DUMP_FIELD_COPY (&out, tree, up_obj);
  eassert (tree->gcmarkbit == 0);
  DUMP_FIELD_COPY (&out, tree, write_protect);
  DUMP_FIELD_COPY (&out, tree, visible);
  DUMP_FIELD_COPY (&out, tree, front_sticky);
  DUMP_FIELD_COPY (&out, tree, rear_sticky);
  dump_field_lv (ctx, &out, tree, &tree->plist);
  ptrdiff_t offset = dump_object_finish (ctx, &out, sizeof (out));
  if (tree->left)
      dump_remember_fixup_ptr_raw (
        ctx,
        offset + offsetof (struct interval, left),
        dump_interval_tree (ctx, tree->left, offset));
  if (tree->right)
      dump_remember_fixup_ptr_raw (
        ctx,
        offset + offsetof (struct interval, right),
        dump_interval_tree (ctx, tree->right, offset));
  return offset;
}

static ptrdiff_t
dump_string (struct dump_context *ctx, const struct Lisp_String *string)
{
  /* If we have text properties, write them _after_ the string so that
     at runtime, the prefetcher and cache will DTRT. (We access the
     string before its properties.).

     There's special code to dump string data contiguously later on.
     we seldom write to string data and never relocate it, so lumping
     it together at the end of the dump saves on COW faults.

     If, however, the string's size_byte field is -1, the string data
     is actually a pointer to Emacs data segment, so we can do even
     better by emitting a relocation instead of bothering to copy the
     string data.  */
  struct Lisp_String out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, string, size);
  DUMP_FIELD_COPY (&out, string, size_byte);
  if (string->intervals)
    dump_field_fixup_later (ctx, &out, string, &string->intervals);

  if (string->size_byte == -2)
    /* String literal in Emacs rodata.  */
    dump_field_emacs_ptr (ctx, &out, string, &string->data);
  else
    {
      dump_field_fixup_later (ctx, &out, string, &string->data);
      dump_remember_cold_op (ctx,
                             COLD_OP_STRING,
                             make_lisp_ptr ((void*) string, Lisp_String));
    }

  ptrdiff_t offset = dump_object_finish (ctx, &out, sizeof (out));
  if (string->intervals)
    dump_remember_fixup_ptr_raw (
      ctx,
      offset + offsetof (struct Lisp_String, intervals),
      dump_interval_tree (ctx, string->intervals, 0));

  return offset;
}

static ptrdiff_t
dump_marker (struct dump_context *ctx, const struct Lisp_Marker *marker)
{
  struct Lisp_Marker out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, marker, type);
  eassert (marker->gcmarkbit == 0);
  (void) marker->spacer; /* Do not write padding.  */
  DUMP_FIELD_COPY (&out, marker, need_adjustment);
  DUMP_FIELD_COPY (&out, marker, insertion_type);
  if (marker->buffer)
    {
      dump_field_lv_rawptr (
        ctx, &out,
        marker, &marker->buffer,
        Lisp_Vectorlike);
      dump_field_lv_rawptr (
        ctx, &out,
        marker, &marker->next,
        Lisp_Misc);
      DUMP_FIELD_COPY (&out, marker, charpos);
      DUMP_FIELD_COPY (&out, marker, bytepos);
    }
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_overlay (struct dump_context *ctx, const struct Lisp_Overlay *overlay)
{
  struct Lisp_Overlay out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, overlay, type);
  eassert (overlay->gcmarkbit == 0);
  (void) overlay->spacer; /* Do not write padding.  */
  dump_field_lv_rawptr (ctx, &out, overlay, &overlay->next, Lisp_Misc);
  dump_field_lv (ctx, &out, overlay, &overlay->start);
  dump_field_lv (ctx, &out, overlay, &overlay->end);
  dump_field_lv (ctx, &out, overlay, &overlay->plist);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_save_value (struct dump_context *ctx,
                 const struct Lisp_Save_Value *ptr)
{
  struct Lisp_Save_Value out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, ptr, type);
  eassert(ptr->gcmarkbit == 0);
  (void) ptr->spacer; /* Do not write padding.  */
  DUMP_FIELD_COPY (&out, ptr, save_type);
  for (int i = 0; i < SAVE_VALUE_SLOTS; i++)
    {
      switch (save_type (&out, i))
        {
        case SAVE_UNUSED:
          break;
        case SAVE_INTEGER:
          DUMP_FIELD_COPY (&out, ptr, data[i].integer);
          break;
        case SAVE_FUNCPOINTER:
          dump_field_emacs_ptr (ctx, &out, ptr, &ptr->data[i].funcpointer);
          break;
        case SAVE_OBJECT:
          dump_field_lv (ctx, &out, ptr, &ptr->data[i].object);
          break;
        case SAVE_POINTER:
          error_unsupported_dump_object(
            ctx, make_lisp_ptr ((void *) ptr, Lisp_Misc), "SAVE_POINTER");
        default:
          emacs_abort ();
        }
    }
  return dump_object_finish (ctx, &out, sizeof (out));
}

static void
dump_field_finalizer_ref (struct dump_context *ctx,
                          void *out,
                          const struct Lisp_Finalizer *finalizer,
                          struct Lisp_Finalizer *const *field)
{
  if (*field == &finalizers || *field == &doomed_finalizers)
    dump_field_emacs_ptr (ctx, out, finalizer, field);
  else
    dump_field_lv_rawptr (ctx, out, finalizer, field, Lisp_Misc);
}

static ptrdiff_t
dump_finalizer (struct dump_context *ctx,
                const struct Lisp_Finalizer *finalizer)
{
  struct Lisp_Finalizer out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, finalizer, base.type);
  eassert (finalizer->base.gcmarkbit == 0);
  (void) finalizer->base.spacer; /* Do not write padding.  */
  dump_field_finalizer_ref (ctx, &out, finalizer, &finalizer->prev);
  dump_field_finalizer_ref (ctx, &out, finalizer, &finalizer->next);
  dump_field_lv (ctx, &out, finalizer, &finalizer->function);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_misc_any (struct dump_context *ctx, struct Lisp_Misc_Any *misc_any)
{
  ptrdiff_t result;

  switch (misc_any->type)
    {
    case Lisp_Misc_Marker:
      result = dump_marker (ctx, (struct Lisp_Marker *) misc_any);
      break;

    case Lisp_Misc_Overlay:
      result = dump_overlay (ctx, (struct Lisp_Overlay *) misc_any);
      break;

    case Lisp_Misc_Save_Value:
      result = dump_save_value (ctx, (struct Lisp_Save_Value *) misc_any);
      break;

    case Lisp_Misc_Finalizer:
      result = dump_finalizer (ctx, (struct Lisp_Finalizer *) misc_any);
      break;

#ifdef HAVE_MODULES
    case Lisp_Misc_User_Ptr:
      error_unsupported_dump_object(
        ctx,
        make_lisp_ptr (misc_any, Lisp_Misc),
        "module user ptr");
      break;
#endif

    default:
    case Lisp_Misc_Float: /* Not used */
      emacs_abort ();
    }

  return result;
}

static ptrdiff_t
dump_float (struct dump_context *ctx, const struct Lisp_Float *lfloat)
{
  struct Lisp_Float out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, lfloat, u.data);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_fwd_int (struct dump_context *ctx, const struct Lisp_Intfwd *intfwd)
{
  dump_emacs_reloc_immediate_emacs_int (ctx, intfwd->intvar, *intfwd->intvar);
  struct Lisp_Intfwd out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, intfwd, type);
  dump_field_emacs_ptr (ctx, &out, intfwd, &intfwd->intvar);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_fwd_bool (struct dump_context *ctx, const struct Lisp_Boolfwd *boolfwd)
{
  dump_emacs_reloc_immediate_bool (ctx, boolfwd->boolvar, *boolfwd->boolvar);
  struct Lisp_Boolfwd out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, boolfwd, type);
  dump_field_emacs_ptr (ctx, &out, boolfwd, &boolfwd->boolvar);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_fwd_obj (struct dump_context *ctx, const struct Lisp_Objfwd *objfwd)
{
  dump_emacs_reloc_to_dump_lv (ctx, objfwd->objvar, *objfwd->objvar);
  struct Lisp_Objfwd out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, objfwd, type);
  dump_field_emacs_ptr (ctx, &out, objfwd, &objfwd->objvar);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_fwd_buffer_obj (struct dump_context *ctx,
                     const struct Lisp_Buffer_Objfwd *buffer_objfwd)
{
  struct Lisp_Buffer_Objfwd out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, buffer_objfwd, type);
  DUMP_FIELD_COPY (&out, buffer_objfwd, offset);
  dump_field_lv (ctx, &out, buffer_objfwd, &buffer_objfwd->predicate);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_fwd_kboard_obj (struct dump_context *ctx,
                     const struct Lisp_Kboard_Objfwd *kboard_objfwd)
{
  struct Lisp_Kboard_Objfwd out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, kboard_objfwd, type);
  DUMP_FIELD_COPY (&out, kboard_objfwd, offset);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_fwd (struct dump_context *ctx, union Lisp_Fwd *fwd)
{
  ptrdiff_t offset;

  switch (XFWDTYPE (fwd))
    {
    case Lisp_Fwd_Int:
      offset = dump_fwd_int (ctx, &fwd->u_intfwd);
      break;
    case Lisp_Fwd_Bool:
      offset = dump_fwd_bool (ctx, &fwd->u_boolfwd);
      break;
    case Lisp_Fwd_Obj:
      offset = dump_fwd_obj (ctx, &fwd->u_objfwd);
      break;
    case Lisp_Fwd_Buffer_Obj:
      offset = dump_fwd_buffer_obj (ctx, &fwd->u_buffer_objfwd);
      break;
    case Lisp_Fwd_Kboard_Obj:
      offset = dump_fwd_kboard_obj (ctx, &fwd->u_kboard_objfwd);
      break;
    default:
      emacs_abort ();
    }

  return offset;
}

static ptrdiff_t
dump_blv (struct dump_context *ctx,
          const struct Lisp_Buffer_Local_Value *blv)
{
  struct Lisp_Buffer_Local_Value out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, blv, local_if_set);
  /*DUMP_FIELD_COPY (&out, blv, frame_local);*/
  DUMP_FIELD_COPY (&out, blv, found);
  if (blv->fwd)
    dump_field_fixup_later (ctx, &out, blv, &blv->fwd);
  dump_field_lv (ctx, &out, blv, &blv->where);
  dump_field_lv (ctx, &out, blv, &blv->defcell);
  dump_field_lv (ctx, &out, blv, &blv->valcell);
  ptrdiff_t offset = dump_object_finish (ctx, &out, sizeof (out));
  if (blv->fwd)
    dump_remember_fixup_ptr_raw (
      ctx,
      offset + offsetof (struct Lisp_Buffer_Local_Value, fwd),
      dump_fwd (ctx, blv->fwd));
  return offset;
}

static ptrdiff_t
dump_symbol (struct dump_context *ctx, const struct Lisp_Symbol *symbol)
{
  struct Lisp_Symbol out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  eassert (symbol->gcmarkbit == 0);
  DUMP_FIELD_COPY (&out, symbol, redirect);
  DUMP_FIELD_COPY (&out, symbol, trapped_write);
  DUMP_FIELD_COPY (&out, symbol, interned);
  DUMP_FIELD_COPY (&out, symbol, declared_special);
  DUMP_FIELD_COPY (&out, symbol, pinned);
  dump_field_lv (ctx, &out, symbol, &symbol->name);
  switch (symbol->redirect)
    {
    case SYMBOL_PLAINVAL:
      dump_field_lv (ctx, &out, symbol, &symbol->val.value);
      break;
    case SYMBOL_VARALIAS:
      dump_field_lv_rawptr (ctx, &out, symbol,
                            &symbol->val.alias, Lisp_Symbol);
      break;
    case SYMBOL_LOCALIZED:
      dump_field_fixup_later (ctx, &out, symbol, &symbol->val.blv);
      break;
    case SYMBOL_FORWARDED:
      dump_field_fixup_later (ctx, &out, symbol, &symbol->val.fwd);
      break;
    default:
      emacs_abort ();
    }
  dump_field_lv (ctx, &out, symbol, &symbol->function);
  dump_field_lv (ctx, &out, symbol, &symbol->plist);
  dump_field_lv_rawptr (ctx, &out, symbol, &symbol->next, Lisp_Symbol);

  // XXX: linearize symbol chains

  ptrdiff_t offset = dump_object_finish (ctx, &out, sizeof (out));

  switch (symbol->redirect)
    {
    case SYMBOL_LOCALIZED:
      dump_remember_fixup_ptr_raw (
        ctx,
        offset + offsetof (struct Lisp_Symbol, val.blv),
        dump_blv (ctx, symbol->val.blv));
      break;
    case SYMBOL_FORWARDED:
      dump_remember_fixup_ptr_raw (
        ctx,
        offset + offsetof (struct Lisp_Symbol, val.fwd),
        dump_fwd (ctx, symbol->val.fwd));
      break;
    default:
      break;
    }
  return offset;
}

static ptrdiff_t
dump_vectorlike_generic (
  struct dump_context *ctx,
  const struct vectorlike_header *header)
{
  const struct Lisp_Vector *v = (const struct Lisp_Vector *) header;
  ptrdiff_t size = header->size;
  enum pvec_type pvectype = PSEUDOVECTOR_TYPE (header);
  ptrdiff_t offset;

  if (size & PSEUDOVECTOR_FLAG)
    {
      /* Assert that the pseudovector contains only Lisp values ---
         but see the PVEC_SUB_CHAR_TABLE special case below.  */
      eassert (((size & PSEUDOVECTOR_REST_MASK)
                >> PSEUDOVECTOR_REST_BITS) == 0);
      size &= PSEUDOVECTOR_SIZE_MASK;
    }

  dump_align_output (ctx, GCALIGNMENT);
  ptrdiff_t prefix_start_offset = ctx->offset;

  ptrdiff_t skip;
  if (pvectype == PVEC_SUB_CHAR_TABLE)
    {
      /* PVEC_SUB_CHAR_TABLE has a special case because it's a
         variable-length vector (unlike other pseudovectors) and has
         its non-Lisp data _before_ the variable-length Lisp part.  */
      const struct Lisp_Sub_Char_Table *sct =
        (const struct Lisp_Sub_Char_Table *) header;
      struct Lisp_Sub_Char_Table out;
      dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
      DUMP_FIELD_COPY (&out, sct, header.size);
      DUMP_FIELD_COPY (&out, sct, depth);
      DUMP_FIELD_COPY (&out, sct, min_char);
      offset = dump_object_finish (ctx, &out, sizeof (out));
      skip = SUB_CHAR_TABLE_OFFSET;
    }
  else
    {
      struct vectorlike_header out;
      dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
      DUMP_FIELD_COPY (&out, header, size);
      offset = dump_object_finish (ctx, &out, sizeof (out));
      skip = 0;
    }

  ptrdiff_t prefix_size = ctx->offset - prefix_start_offset;
  eassert (prefix_size > 0);
  ptrdiff_t skip_start = (char*) &v->contents[skip] - (char*) v;
  eassert (skip_start >= prefix_size);
  dump_write_zero (ctx, skip_start - prefix_size);
  for (ptrdiff_t i = skip; i < size; ++i)
    {
      Lisp_Object out;
      const Lisp_Object *vslot = &v->contents[i];
      eassert (ctx->offset % sizeof (out) == 0);
      dump_object_start (ctx, 1, &out, sizeof (out));
      dump_field_lv (ctx, &out, vslot, vslot);
      dump_object_finish (ctx, &out, sizeof (out));
    }

  return offset;
}

static void
dump_object_start_pseudovector (
  struct dump_context *ctx,
  struct vectorlike_header *out_hdr,
  ptrdiff_t out_size,
  const struct vectorlike_header *in_hdr)
{
  const struct Lisp_Vector *in = (const struct Lisp_Vector *) in_hdr;
  struct Lisp_Vector *out = (struct Lisp_Vector *) out_hdr;

  eassert (vector_nbytes ((struct Lisp_Vector *) in) == out_size);

  dump_object_start (ctx, GCALIGNMENT, out, out_size);
  DUMP_FIELD_COPY (out, in, header);
  ptrdiff_t size = in->header.size;
  eassert (size & PSEUDOVECTOR_FLAG);
  size &= PSEUDOVECTOR_SIZE_MASK;
  for (ptrdiff_t i = 0; i < size; ++i)
    dump_field_lv (ctx, out, in, &in->contents[i]);
}

/* Determine whether the hash table's hash order is stable
   across dump and load.  If it is, we don't have to trigger
   a rehash on access.  */
static bool
dump_hash_table_stable_p (struct Lisp_Hash_Table *hash)
{
  bool is_eql = hash->test.hashfn == hashfn_eql;
  bool is_equal = hash->test.hashfn == hashfn_equal;
  ptrdiff_t size = HASH_TABLE_SIZE (hash);
  for (ptrdiff_t i = 0; i < size; ++i)
    if (!NILP (HASH_HASH (hash, i)))
      {
        Lisp_Object key =  HASH_KEY (hash, i);
        if (!(dump_builtin_symbol_p (key) ||
              INTEGERP (key) ||
              (is_equal && STRINGP (key)) ||
              ((is_equal || is_eql) && FLOATP (key))))
          return false;
      }

  return true;
}

static ptrdiff_t
dump_hash_table (struct dump_context *ctx,
                 const struct Lisp_Hash_Table *hash_in)
{
  struct Lisp_Hash_Table hash_munged = *hash_in;
  struct Lisp_Hash_Table *hash = &hash_munged;

  /* Remember to rehash this hash table on first access.  After a
     dump reload, the hash table values will have changed, so we'll
     need to rebuild the index.

     TODO: for EQ and EQL hash tables, it should be possible to rehash
     here using the preferred load address of the dump, eliminating
     the need to rehash-on-access if we can load the dump where we
     want.  */
  if (hash->count > 0 && !dump_hash_table_stable_p (hash))
    hash->count = -hash->count;

  struct Lisp_Hash_Table out;
  dump_object_start_pseudovector (
    ctx, &out.header, sizeof (out), &hash->header);
  DUMP_FIELD_COPY (&out, hash, count);
  dump_field_lv (ctx, &out, hash, &hash->key_and_value);
  dump_field_lv (ctx, &out, hash, &hash->test.name);
  dump_field_lv (ctx, &out, hash, &hash->test.user_hash_function);
  dump_field_lv (ctx, &out, hash, &hash->test.user_cmp_function);
  dump_field_emacs_ptr (ctx, &out, hash, &hash->test.cmpfn);
  dump_field_emacs_ptr (ctx, &out, hash, &hash->test.hashfn);
  dump_field_lv_rawptr (ctx, &out, hash, &hash->next_weak, Lisp_Vectorlike);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static ptrdiff_t
dump_buffer (struct dump_context *ctx, const struct buffer *in_buffer)
{
  struct buffer munged_buffer = *in_buffer;
  struct buffer *buffer = &munged_buffer;

  /* Clear some buffer state for correctness upon load.  */
  if (buffer->base_buffer == NULL)
    buffer->window_count = 0;
  else
    eassert (buffer->window_count == -1);
  buffer->last_selected_window_ = Qnil;
  buffer->display_count_ = make_number (0);
  buffer->clip_changed = 0;
  buffer->last_window_start = -1;
  buffer->point_before_scroll_ = Qnil;

  ptrdiff_t base_offset = 0;
  if (buffer->base_buffer)
    {
      eassert (buffer->base_buffer->base_buffer == NULL);
      base_offset = dump_object (
        ctx,
        make_lisp_ptr (buffer->base_buffer, Lisp_Vectorlike));
    }

  eassert ((base_offset == 0 && buffer->text == &in_buffer->own_text) ||
           (base_offset > 0 && buffer->text != &in_buffer->own_text));

  struct buffer out;
  dump_object_start_pseudovector (
    ctx, &out.header, sizeof (out), &buffer->header);
  if (base_offset == 0)
    base_offset = ctx->obj_offset;
  eassert (base_offset > 0);
  if (buffer->base_buffer == NULL)
    {
      eassert (base_offset == ctx->obj_offset);

      if (BUFFER_LIVE_P (buffer))
        {
          dump_field_fixup_later (ctx, &out, buffer, &buffer->own_text.beg);
          dump_remember_cold_op (
            ctx,
            COLD_OP_BUFFER,
            make_lisp_ptr ((void*) in_buffer, Lisp_Vectorlike));
        }
      else
        eassert (buffer->own_text.beg == NULL);

      DUMP_FIELD_COPY (&out, buffer, own_text.gpt);
      DUMP_FIELD_COPY (&out, buffer, own_text.z);
      DUMP_FIELD_COPY (&out, buffer, own_text.gpt_byte);
      DUMP_FIELD_COPY (&out, buffer, own_text.z_byte);
      DUMP_FIELD_COPY (&out, buffer, own_text.gap_size);
      DUMP_FIELD_COPY (&out, buffer, own_text.modiff);
      DUMP_FIELD_COPY (&out, buffer, own_text.chars_modiff);
      DUMP_FIELD_COPY (&out, buffer, own_text.save_modiff);
      DUMP_FIELD_COPY (&out, buffer, own_text.overlay_modiff);
      DUMP_FIELD_COPY (&out, buffer, own_text.compact);
      DUMP_FIELD_COPY (&out, buffer, own_text.beg_unchanged);
      DUMP_FIELD_COPY (&out, buffer, own_text.end_unchanged);
      DUMP_FIELD_COPY (&out, buffer, own_text.unchanged_modified);
      DUMP_FIELD_COPY (&out, buffer, own_text.overlay_unchanged_modified);
      if (buffer->own_text.intervals)
        dump_field_fixup_later (ctx, &out, buffer, &buffer->own_text.intervals);
      dump_field_lv_rawptr (ctx, &out, buffer, &buffer->own_text.markers,
                            Lisp_Misc);
      DUMP_FIELD_COPY (&out, buffer, own_text.inhibit_shrinking);
      DUMP_FIELD_COPY (&out, buffer, own_text.redisplay);
    }

  eassert (ctx->obj_offset > 0);
  dump_remember_fixup_ptr_raw (
    ctx,
    ctx->obj_offset + offsetof (struct buffer, text),
    base_offset + offsetof (struct buffer, own_text));

  dump_field_lv_rawptr (ctx, &out, buffer, &buffer->next, Lisp_Vectorlike);
  DUMP_FIELD_COPY (&out, buffer, pt);
  DUMP_FIELD_COPY (&out, buffer, pt_byte);
  DUMP_FIELD_COPY (&out, buffer, begv);
  DUMP_FIELD_COPY (&out, buffer, begv_byte);
  DUMP_FIELD_COPY (&out, buffer, zv);
  DUMP_FIELD_COPY (&out, buffer, zv_byte);

  if (buffer->base_buffer)
    {
      eassert (ctx->obj_offset != base_offset);
      dump_field_ptr_to_dump_offset (
        ctx, &out, buffer, &buffer->base_buffer,
        base_offset);
    }

  DUMP_FIELD_COPY (&out, buffer, indirections);
  DUMP_FIELD_COPY (&out, buffer, window_count);

  memcpy (&out.local_flags,
          &buffer->local_flags,
          sizeof (out.local_flags));
  DUMP_FIELD_COPY (&out, buffer, modtime);
  DUMP_FIELD_COPY (&out, buffer, modtime_size);
  DUMP_FIELD_COPY (&out, buffer, auto_save_modified);
  DUMP_FIELD_COPY (&out, buffer, display_error_modiff);
  DUMP_FIELD_COPY (&out, buffer, auto_save_failure_time);
  DUMP_FIELD_COPY (&out, buffer, last_window_start);

  /* Not worth serializing these caches.  TODO: really? */
  out.newline_cache = NULL;
  out.width_run_cache = NULL;
  out.bidi_paragraph_cache = NULL;

  DUMP_FIELD_COPY (&out, buffer, prevent_redisplay_optimizations_p);
  DUMP_FIELD_COPY (&out, buffer, clip_changed);

  dump_field_lv_rawptr (ctx, &out, buffer, &buffer->overlays_before,
                        Lisp_Misc);

  dump_field_lv_rawptr (ctx, &out, buffer, &buffer->overlays_after,
                        Lisp_Misc);

  DUMP_FIELD_COPY (&out, buffer, overlay_center);
  dump_field_lv (ctx, &out, buffer, &buffer->undo_list_);
  ptrdiff_t offset = dump_object_finish (ctx, &out, sizeof (out));
  if (!buffer->base_buffer && buffer->own_text.intervals)
    dump_remember_fixup_ptr_raw (
      ctx,
      offset + offsetof (struct buffer, own_text.intervals),
      dump_interval_tree (ctx, buffer->own_text.intervals, 0));

  return offset;
}

static ptrdiff_t
dump_bool_vector (struct dump_context *ctx, const struct Lisp_Vector *v)
{
  /* No relocation needed, so we don't need dump_object_start.  */
  dump_align_output (ctx, GCALIGNMENT);
  eassert (ctx->offset >= ctx->header.hot_end);
  ptrdiff_t offset = ctx->offset;
  ptrdiff_t nbytes = vector_nbytes ((struct Lisp_Vector *) v);
  dump_write (ctx, v, nbytes);
  return offset;
}

static ptrdiff_t
dump_subr (struct dump_context *ctx, const struct Lisp_Subr *subr)
{
  struct Lisp_Subr out;
  dump_object_start (ctx, GCALIGNMENT, &out, sizeof (out));
  DUMP_FIELD_COPY (&out, subr, header.size);
  dump_field_emacs_ptr (ctx, &out, subr, &subr->function.a0);
  DUMP_FIELD_COPY (&out, subr, min_args);
  DUMP_FIELD_COPY (&out, subr, max_args);
  dump_field_emacs_ptr (ctx, &out, subr, &subr->symbol_name);
  dump_field_emacs_ptr (ctx, &out, subr, &subr->intspec);
  DUMP_FIELD_COPY (&out, subr, doc);
  return dump_object_finish (ctx, &out, sizeof (out));
}

static void
fill_pseudovec (struct vectorlike_header *header, Lisp_Object item)
{
  struct Lisp_Vector *v = (struct Lisp_Vector *) header;
  eassert (v->header.size & PSEUDOVECTOR_FLAG);
  ptrdiff_t size = v->header.size & PSEUDOVECTOR_SIZE_MASK;
  for (ptrdiff_t idx = 0; idx < size; idx++)
    v->contents[idx] = item;
}

static ptrdiff_t
dump_nilled_pseudovec (struct dump_context *ctx,
                       const struct vectorlike_header *in)
{
  ptrdiff_t nbytes = vector_nbytes ((struct Lisp_Vector *) in);
  struct vectorlike_header *in_nilled = alloca (nbytes);
  memset (in_nilled, 0, nbytes);
  in_nilled->size = in->size;
  fill_pseudovec (in_nilled, Qnil);
  struct vectorlike_header *out = alloca (nbytes);
  memset (out, 0, nbytes);
  dump_object_start_pseudovector (ctx, out, nbytes, in_nilled);
  return dump_object_finish (ctx, out, nbytes);
}

static ptrdiff_t
dump_vectorlike (struct dump_context *ctx, const struct Lisp_Vector *v)
{
  ptrdiff_t offset;
  Lisp_Object lv = make_lisp_ptr ((void *) v, Lisp_Vectorlike);
  switch (PSEUDOVECTOR_TYPE (&v->header))
    {
    case PVEC_FONT:
      /* There are three kinds of font objects that all use PVEC_FONT,
         distinguished by their size.  Font specs and entities are
         harmless data carriers that we can dump like other Lisp
         objects.  Fonts themselves are window-system-specific and
         need to be recreated on each startup.  */
      if ((v->header.size & PSEUDOVECTOR_SIZE_MASK) != FONT_SPEC_MAX &&
          (v->header.size & PSEUDOVECTOR_SIZE_MASK) != FONT_ENTITY_MAX)
        error_unsupported_dump_object(ctx, lv, "font");
      /* Fall through */
    case PVEC_NORMAL_VECTOR:
    case PVEC_COMPILED:
    case PVEC_CHAR_TABLE:
    case PVEC_SUB_CHAR_TABLE:
      offset = dump_vectorlike_generic (ctx, &v->header);
      break;
    case PVEC_BOOL_VECTOR:
      offset = dump_bool_vector(ctx, v);
      break;
    case PVEC_HASH_TABLE:
      offset = dump_hash_table (ctx, (struct Lisp_Hash_Table *) v);
      break;
    case PVEC_BUFFER:
      offset = dump_buffer (ctx, (struct buffer *) v);
      break;
    case PVEC_SUBR:
      offset = dump_subr(ctx, (const struct Lisp_Subr *) v);
      break;
    case PVEC_FRAME:
    case PVEC_WINDOW:
    case PVEC_PROCESS:
    case PVEC_TERMINAL:
      offset = dump_nilled_pseudovec (ctx, &v->header);
      break;
    case PVEC_WINDOW_CONFIGURATION:
      error_unsupported_dump_object(ctx, lv, "window configuration");
    case PVEC_OTHER:
      error_unsupported_dump_object(ctx, lv, "other?!");
    case PVEC_XWIDGET:
      error_unsupported_dump_object(ctx, lv, "xwidget");
    case PVEC_XWIDGET_VIEW:
      error_unsupported_dump_object(ctx, lv, "xwidget view");
    default:
      error_unsupported_dump_object(ctx, lv, "weird pseudovector");
    }

  return offset;
}

/* Add an object to the dump.  */
static ptrdiff_t
dump_object_1 (struct dump_context *ctx, Lisp_Object object, int flags)
{
#ifdef ENABLE_CHECKING
  eassert (!EQ (object, Vdead));
#endif

  if (flags & DUMP_OBJECT_DRY_RUN)
    flags &= ~(DUMP_OBJECT_INTERN | DUMP_OBJECT_RECORD_START);

  int saved_flags = ctx->flags;
  flags |= ctx->flags;
  ctx->flags = flags;

  ptrdiff_t offset = dump_recall_object (ctx, object);
  if (flags & DUMP_OBJECT_INTERN)
    eassert (!dump_object_self_representing_p (object));

  if (offset <= 0)
    {
      DUMP_SET_REFERRER (ctx, object);
      switch (XTYPE (object))
        {
        case Lisp_String:
          offset = dump_string (ctx, XSTRING (object));
          break;
        case Lisp_Vectorlike:
          offset = dump_vectorlike (ctx, XVECTOR (object));
          break;
        case Lisp_Symbol:
          offset = dump_symbol (ctx, XSYMBOL (object));
          break;
        case Lisp_Misc:
          offset = dump_misc_any (ctx, XMISCANY (object));
          break;
        case Lisp_Cons:
          offset = dump_cons (ctx, XCONS (object));
          break;
        case Lisp_Float:
          offset = dump_float (ctx, XFLOAT (object));
          break;
        case_Lisp_Int:
          eassert (!"should not be dumping int: is self-representing");
        default:
          emacs_abort ();
        }
      eassert (offset > 0);
      if (flags & DUMP_OBJECT_INTERN)
        dump_remember_object (ctx, object, offset);
      if (flags & DUMP_OBJECT_RECORD_START)
          dump_push (&ctx->object_starts,
                     list2 (INTEGER_TO_CONS (XTYPE (object)),
                            INTEGER_TO_CONS (offset)));

      dump_clear_referrer (ctx);

      /* If we dumped a cons cell, we put its car and cdr on the dump
         queue; we'll eventually get around to dumping them.  That's
         fine from a correctness perspective, but but Lisp has lots of
         lists, and code likes to traverse lists.  Make sure the cons
         cells for reasonable-sized lists are dumped next to each
         other.  */
      if (CONSP (object) &&
          CONSP (XCDR (object)) &&
          flags == (DUMP_OBJECT_INTERN | DUMP_OBJECT_RECORD_START) &&
          ctx->cons_chain_depth < max_cons_chain_depth)
        {
          ctx->cons_chain_depth += 1;
          dump_object (ctx, XCDR (object));
          ctx->cons_chain_depth -= 1;
        }
    }

  ctx->flags = saved_flags;
  return offset;
}

static ptrdiff_t
dump_object (struct dump_context *ctx, Lisp_Object object)
{
  ptrdiff_t result;
  if (dump_object_emacs_ptr (object) != NULL)
    {
      result = dump_recall_object (ctx, object);
      eassert (result < 0);
      if (result > -2)
        {
          dump_object_1 (ctx, object, DUMP_OBJECT_DRY_RUN);
          dump_push (&ctx->copied_queue, object);
          result = -2;
          dump_remember_object (ctx, object, result);
        }
    }
  else
    result = dump_object_1 (
      ctx,
      object,
      DUMP_OBJECT_INTERN | DUMP_OBJECT_RECORD_START);
  return result;
}

static ptrdiff_t
dump_charset (struct dump_context *ctx, int cs_i)
{
  const struct charset *cs = charset_table + cs_i;
  struct charset out;
  dump_object_start (ctx, sizeof (int), &out, sizeof (out));
  DUMP_FIELD_COPY (&out, cs, id);
  DUMP_FIELD_COPY (&out, cs, hash_index);
  DUMP_FIELD_COPY (&out, cs, dimension);
  memcpy (out.code_space, &cs->code_space, sizeof (cs->code_space));
  if (cs->code_space_mask)
    dump_field_fixup_later (ctx, &out, cs, &cs->code_space_mask);
  DUMP_FIELD_COPY (&out, cs, code_linear_p);
  DUMP_FIELD_COPY (&out, cs, iso_chars_96);
  DUMP_FIELD_COPY (&out, cs, ascii_compatible_p);
  DUMP_FIELD_COPY (&out, cs, supplementary_p);
  DUMP_FIELD_COPY (&out, cs, compact_codes_p);
  DUMP_FIELD_COPY (&out, cs, unified_p);
  DUMP_FIELD_COPY (&out, cs, iso_final);
  DUMP_FIELD_COPY (&out, cs, iso_revision);
  DUMP_FIELD_COPY (&out, cs, emacs_mule_id);
  DUMP_FIELD_COPY (&out, cs, method);
  DUMP_FIELD_COPY (&out, cs, min_code);
  DUMP_FIELD_COPY (&out, cs, max_code);
  DUMP_FIELD_COPY (&out, cs, char_index_offset);
  DUMP_FIELD_COPY (&out, cs, min_char);
  DUMP_FIELD_COPY (&out, cs, max_char);
  DUMP_FIELD_COPY (&out, cs, invalid_code);
  memcpy (out.fast_map, &cs->fast_map, sizeof (cs->fast_map));
  DUMP_FIELD_COPY (&out, cs, code_offset);
  ptrdiff_t offset = dump_object_finish (ctx, &out, sizeof (out));
  if (cs->code_space_mask)
    dump_remember_cold_op (ctx, COLD_OP_CHARSET,
                           Fcons (INTEGER_TO_CONS (cs_i),
                                  INTEGER_TO_CONS (offset)));
  return offset;
}

static ptrdiff_t
dump_charset_table (struct dump_context *ctx)
{
  dump_align_output (ctx, GCALIGNMENT);
  ptrdiff_t offset = ctx->offset;
  for (int i = 0; i < charset_table_used; ++i)
    dump_charset (ctx, i);
  dump_emacs_reloc_to_dump_ptr_raw (ctx, &charset_table, offset);
  dump_emacs_reloc_immediate_int (
    ctx, &charset_table_used, charset_table_used);
  dump_emacs_reloc_immediate_emacs_int (
    ctx, &charset_table_size, charset_table_used);
  return offset;
}

static void
dump_finalizer_list_head_ptr (struct dump_context *ctx,
                              struct Lisp_Finalizer **ptr)
{
  struct Lisp_Finalizer *value = *ptr;
  if (value != &finalizers && value != &doomed_finalizers)
    dump_emacs_reloc_to_dump_ptr_raw (
      ctx, ptr,
      dump_object (ctx, make_lisp_ptr (value, Lisp_Misc)));
}

static void
dump_metadata_for_pdumper (struct dump_context *ctx)
{
  for (int i = 0; i < nr_dump_hooks; ++i)
    dump_emacs_reloc_to_emacs_ptr_raw (ctx, &dump_hooks[i], dump_hooks[i]);
  dump_emacs_reloc_immediate_int (ctx, &nr_dump_hooks, nr_dump_hooks);

  for (int i = 0; i < nr_remembered_data; ++i)
    {
      dump_emacs_reloc_to_emacs_ptr_raw (
        ctx,
        &remembered_data[i].mem,
        remembered_data[i].mem);
      dump_emacs_reloc_immediate_int (
        ctx,
        &remembered_data[i].sz,
        remembered_data[i].sz);
    }
  dump_emacs_reloc_immediate_int (
    ctx,
    &nr_remembered_data,
    nr_remembered_data);
}

static void
dump_copied_objects (struct dump_context *ctx)
{
  /* Sort the objects into the order in which they'll appear in Emacs.  */
  Lisp_Object copied_queue =
    Fsort (Fnreverse (ctx->copied_queue),
           Qdump_emacs_portable__sort_predicate_copied);
  ctx->copied_queue = Qnil;

  /* Dump the objects and generate a copy relocation for each.  We'll
     merge adjacent copy relocations upon output.  */
  while (!NILP (copied_queue))
    {
      Lisp_Object copied = dump_pop (&copied_queue);
      void *optr = dump_object_emacs_ptr (copied);
      eassert (optr != NULL);
      ptrdiff_t offset = dump_object_1 (
        ctx,
        copied,
        ( DUMP_OBJECT_FORCE_WORD_ALIGNMENT
          | DUMP_OBJECT_PROHIBIT_ENQUEUE));
      ptrdiff_t size = ctx->offset - offset;
      dump_emacs_reloc_copy_from_dump (ctx, offset, optr, size);
    }
}

static void
dump_cold_string (struct dump_context *ctx, Lisp_Object string)
{
  /* Dump string contents.  */
  ptrdiff_t string_offset = dump_recall_object (ctx, string);
  eassert (string_offset > 0);
  ptrdiff_t total_size = SBYTES (string) + 1;
  eassert (total_size > 0);
  dump_remember_fixup_ptr_raw (
    ctx,
    string_offset + offsetof (struct Lisp_String, data),
    ctx->offset);
  dump_write (ctx, XSTRING (string)->data, total_size);
}

static void
dump_cold_charset (struct dump_context *ctx, Lisp_Object data)
{
  /* Dump charset lookup tables.  */
  int cs_i = XFASTINT (XCAR (data));
  ptrdiff_t cs_dump_offset = ptrdiff_t_from_lisp (XCDR (data));
  dump_remember_fixup_ptr_raw (
    ctx,
    cs_dump_offset + offsetof (struct charset, code_space_mask),
    ctx->offset);
  struct charset *cs = charset_table + cs_i;
  dump_write (ctx, cs->code_space_mask, 256);
}

static void
dump_cold_buffer (struct dump_context *ctx, Lisp_Object data)
{
  /* Dump buffer text.  */
  ptrdiff_t buffer_offset = dump_recall_object (ctx, data);
  eassert (buffer_offset > 0);
  struct buffer *b = XBUFFER (data);
  eassert (b->text == &b->own_text);
  /* Zero the gap so we don't dump uninitialized bytes.  */
  memset (BUF_GPT_ADDR (b), 0, BUF_GAP_SIZE (b));
  /* See buffer.c for this calculation.  */
  ptrdiff_t nbytes = BUF_Z_BYTE (b) - BUF_BEG_BYTE (b) + BUF_GAP_SIZE (b) + 1;
  dump_remember_fixup_ptr_raw (
    ctx,
    buffer_offset + offsetof (struct buffer, own_text.beg),
    ctx->offset);
  dump_write (ctx, b->own_text.beg, nbytes);
}

static void
dump_cold_data (struct dump_context *ctx)
{
  if (!NILP (ctx->cold_queue))
    {
      Lisp_Object cold_queue = Fnreverse (ctx->cold_queue);
      ctx->cold_queue = Qnil;
      while (!NILP (cold_queue))
        {
          Lisp_Object item = dump_pop (&cold_queue);
          enum cold_op op = XFASTINT (XCAR (item));
          Lisp_Object data = XCDR (item);
          switch (op)
            {
            case COLD_OP_STRING:
              dump_cold_string (ctx, data);
              break;
            case COLD_OP_CHARSET:
              dump_cold_charset (ctx, data);
              break;
            case COLD_OP_BUFFER:
              dump_cold_buffer (ctx, data);
              break;
            case COLD_OP_OBJECT:
              /* Objects that we can put in the cold section
                 must not refer to other objects.  */
              eassert (dump_tailq_empty_p (&ctx->dump_queue));
              dump_object (ctx, data);
              eassert (dump_tailq_empty_p (&ctx->dump_queue));
              break;
            default:
              emacs_abort ();
            }
        }
    }
}

static void
read_raw_ptr_and_lv (const void *mem,
                     enum Lisp_Type type,
                     void **out_ptr,
                     Lisp_Object *out_lv)
{
  memcpy (out_ptr, mem, sizeof (*out_ptr));
  if (*out_ptr != NULL)
    {
      switch (type)
        {
        case Lisp_Symbol:
          *out_lv = make_lisp_symbol (*out_ptr);
          break;
        case Lisp_Misc:
        case Lisp_String:
        case Lisp_Vectorlike:
        case Lisp_Cons:
        case Lisp_Float:
          *out_lv = make_lisp_ptr (*out_ptr, type);
          break;
        default:
          emacs_abort ();
        }
    }
}

/* Enqueue for dumping objects referenced by static non-Lisp_Object
   pointers inside Emacs.  */
static void
dump_user_remembered_data_hot (struct dump_context *ctx)
{
  for (int i = 0; i < nr_remembered_data; ++i)
    {
      void *mem = remembered_data[i].mem;
      int sz = remembered_data[i].sz;
      if (sz <= 0)
        {
          enum Lisp_Type type = -sz;
          void *value;
          Lisp_Object lv;
          read_raw_ptr_and_lv (mem, type, &value, &lv);
          if (value != NULL)
            {
              DUMP_SET_REFERRER (ctx, dump_ptr_referrer ("user data", mem));
              dump_enqueue_object (ctx, lv);
              dump_clear_referrer (ctx);
            }
        }
    }
}

/* Dump user-specified non-relocated data.  */
static void
dump_user_remembered_data_cold (struct dump_context *ctx)
{
  for (int i = 0; i < nr_remembered_data; ++i)
    {
      void *mem = remembered_data[i].mem;
      int sz = remembered_data[i].sz;
      if (sz > 0)
        {
          /* Scalar: try to inline the value into the relocation if
             it's small enough; if it's bigger than we can fit in a
             relocation, we have to copy the data into the dump proper
             and issue a copy relocation.  */
          if (sz <= sizeof (intmax_t))
            dump_emacs_reloc_immediate (ctx, mem, mem, sz);
          else
            {
              dump_emacs_reloc_copy_from_dump (ctx, ctx->offset, mem, sz);
              dump_write (ctx, mem, sz);
            }
        }
      else
        {
          /* *mem is a raw pointer to a Lisp object of some sort.
             The object to which it points should have already been
             dumped by dump_user_remembered_data_hot.  */
          void *value;
          Lisp_Object lv;
          enum Lisp_Type type = -sz;
          read_raw_ptr_and_lv (mem, type, &value, &lv);
          if (value == NULL)
            /* We can't just ignore NULL: the variable might have
               transitioned from non-NULL to NULL, and we want to
               record this fact.  */
            dump_emacs_reloc_immediate_ptrdiff_t (ctx, mem, 0);
          else
            {
              if (dump_object_emacs_ptr (lv) != NULL)
                {
                  /* We have situation like this:

                     static Lisp_Symbol *foo;
                     ...
                     foo = XSYMBOL(Qt);
                     ...
                     pdumper_remember_lv_raw_ptr (&foo, Lisp_Symbol);

                     Built-in symbols like Qt aren't in the dump!
                     They're actually in Emacs proper.  We need a
                     special case to point this value back at Emacs
                     instead of to something in the dump that
                     isn't there.

                     An analogous situation applies to subrs, since
                     Lisp_Subr structures always live in Emacs, not
                     the dump.

                  */
                  dump_emacs_reloc_to_emacs_ptr_raw (
                    ctx, mem, dump_object_emacs_ptr (lv));
                }
              else
                {
                  eassert (!dump_object_self_representing_p (lv));
                  ptrdiff_t dump_offset = dump_recall_object (ctx, lv);
                  if (dump_offset <= 0)
                    error ("raw-pointer object not dumped?!");
                  dump_emacs_reloc_to_dump_ptr_raw (ctx, mem, dump_offset);
                }
            }
        }
    }
}

static void
dump_unwind_cleanup (void *data)
{
  // XXX: omit relocations that duplicate BSS?
  // XXX: prevent ralloc moving
  // XXX: dumb mode for GC
  struct dump_context *ctx = data;
  if (ctx->fd >= 0)
    emacs_close (ctx->fd);
  Vpurify_flag = ctx->old_purify_flag;
  unblock_input ();
}

static Lisp_Object
make_eq_hash_table (void)
{
  return CALLN (Fmake_hash_table, QCtest, Qeq);
}

static void
dump_do_fixup (struct dump_context *ctx, Lisp_Object fixup)
{
  enum dump_fixup_type type = XFASTINT (XCAR (fixup));
  fixup = XCDR (fixup);
  ptrdiff_t dump_fixup_offset = ptrdiff_t_from_lisp (XCAR (fixup));
  fixup = XCDR (fixup);
  Lisp_Object arg = XCAR (fixup);
  eassert (NILP (XCDR (fixup)));
  dump_seek (ctx, dump_fixup_offset);
  ptrdiff_t target_offset;
  bool do_write = true;
  switch (type)
    {
    case DUMP_FIXUP_LISP_OBJECT:
    case DUMP_FIXUP_LISP_OBJECT_RAW:
      /* Dump wants a pointer to a Lisp object.
         If DUMP_FIXUP_LISP_OBJECT_RAW, we should stick a C pointer in
         the dump; otherwise, a Lisp_Object.  */
      if (SUBRP (arg))
        {
          target_offset = emacs_offset (XSUBR (arg));
          if (type == DUMP_FIXUP_LISP_OBJECT)
            dump_reloc_dump_to_emacs_lv (ctx, ctx->offset, XTYPE (arg));
          else
            dump_reloc_dump_to_emacs_raw_ptr (ctx, ctx->offset);
        }
      else if (dump_builtin_symbol_p (arg))
        {
          eassert (dump_object_self_representing_p (arg));
          /* These symbols are part of Emacs, so point there.  If we
             want a Lisp_Object, we're set.  If we want a raw pointer,
             we need to emit a relocation.  */
          if (type == DUMP_FIXUP_LISP_OBJECT)
            {
              do_write = false;
              dump_write (ctx, &arg, sizeof (arg));
            }
          else
            {
              target_offset = emacs_offset (XSYMBOL (arg));
              dump_reloc_dump_to_emacs_raw_ptr (ctx, ctx->offset);
            }
        }
      else
        {
          eassert (dump_object_emacs_ptr (arg) == NULL);
          target_offset = dump_recall_object (ctx, arg);
          if (target_offset <= 0)
            error ("fixup object not dumped");
          if (type == DUMP_FIXUP_LISP_OBJECT)
            dump_reloc_dump_to_dump_lv (ctx, ctx->offset, XTYPE (arg));
          else
            dump_reloc_dump_to_dump_raw_ptr (ctx, ctx->offset);
        }
      break;
    case DUMP_FIXUP_PTR_DUMP_RAW:
      /* Dump wants a raw pointer to something that's not a lisp
         object.  It knows the exact location it wants, so just
         believe it.  */
      target_offset = ptrdiff_t_from_lisp (arg);
      dump_reloc_dump_to_dump_raw_ptr (ctx, ctx->offset);
      break;
    default:
      emacs_abort ();
    }
  if (do_write)
    dump_write (ctx, &target_offset, sizeof (target_offset));
}

static ptrdiff_t
dump_check_dump_off (struct dump_context *ctx, ptrdiff_t dump_offset)
{
  eassert (dump_offset > 0);
  if (ctx)
    eassert (dump_offset < ctx->end_heap);
  return dump_offset;
}

static void
dump_check_emacs_off (ptrdiff_t emacs_off)
{
  eassert (labs (emacs_off) <= 30*1024*1024);
}

static void
dump_emit_dump_reloc (struct dump_context *ctx, Lisp_Object lreloc)
{
  struct dump_reloc reloc;
  dump_object_start (ctx, 1, &reloc, sizeof (reloc));
  reloc.type = XFASTINT (dump_pop (&lreloc));
  eassert (reloc.type <= RELOC_DUMP_TO_EMACS_LV + Lisp_Float);
  reloc.offset = dump_off_from_lisp (dump_pop (&lreloc));
  dump_check_dump_off (ctx, reloc.offset);
  eassert (reloc.offset % 4 == 0); // Alignment
  eassert (NILP (lreloc));
  dump_object_finish (ctx, &reloc, sizeof (reloc));
}

static struct emacs_reloc
decode_emacs_reloc (struct dump_context *ctx, Lisp_Object lreloc)
{
  struct emacs_reloc reloc;
  memset (&reloc, 0, sizeof (reloc));
  int type = XFASTINT (dump_pop (&lreloc));
  reloc.emacs_offset = dump_off_from_lisp (dump_pop (&lreloc));
  dump_check_emacs_off (reloc.emacs_offset);
  switch (type)
    {
    case RELOC_EMACS_COPY_FROM_DUMP:
      {
        reloc.type = type;
        eassert (reloc.type == type);
        reloc.u.dump_offset = dump_off_from_lisp (dump_pop (&lreloc));
        dump_check_dump_off (ctx, reloc.u.dump_offset);
        dump_off_t length = dump_off_from_lisp (dump_pop (&lreloc));
        reloc.length = length;
        if (reloc.length != length)
          error ("relocation copy length too large");
      }
      break;
    case RELOC_EMACS_IMMEDIATE:
      {
        reloc.type = type;
        eassert (reloc.type == type);
        intmax_t value = intmax_t_from_lisp (dump_pop (&lreloc));
        ptrdiff_t size = ptrdiff_t_from_lisp (dump_pop (&lreloc));
        reloc.u.immediate = value;
        reloc.length = size;
        eassert (reloc.length == size);
      }
      break;
    default:
      {
        eassert (RELOC_EMACS_DUMP_LV <= type);
        eassert (type <= RELOC_EMACS_DUMP_LV + Lisp_Float);
        reloc.type = RELOC_EMACS_DUMP_LV;
        eassert (reloc.type == RELOC_EMACS_DUMP_LV);
        reloc.length = type - RELOC_EMACS_DUMP_LV;
        eassert (reloc.length == type - RELOC_EMACS_DUMP_LV);
        Lisp_Object target_value = dump_pop (&lreloc);
        /* If the object is self-representing,
           dump_emacs_reloc_to_dump_lv didn't do its job.
           dump_emacs_reloc_to_dump_lv should have added a
           RELOC_EMACS_IMMEDIATE relocation instead.  */
        eassert (!dump_object_self_representing_p (target_value));
        reloc.u.dump_offset = dump_recall_object (ctx, target_value);
        if (reloc.u.dump_offset <= 0)
          {
            Lisp_Object repr = Fprin1_to_string (target_value, Qnil);
            error ("relocation target was not dumped: %s", SDATA (repr));
          }
        dump_check_dump_off (ctx, reloc.u.dump_offset);
      }
      break;
    case RELOC_EMACS_EMACS_PTR_RAW:
      reloc.type = type;
      eassert (reloc.type == type);
      reloc.u.emacs_offset2 = dump_off_from_lisp (dump_pop (&lreloc));
      dump_check_emacs_off (reloc.u.emacs_offset2);
      break;
    case RELOC_EMACS_DUMP_PTR_RAW:
      reloc.type = type;
      eassert (reloc.type == type);
      reloc.u.dump_offset = dump_off_from_lisp (dump_pop (&lreloc));
      dump_check_dump_off (ctx, reloc.u.dump_offset);
      break;
    }

  eassert (NILP (lreloc));
  return reloc;
}

static void
dump_emit_emacs_reloc (struct dump_context *ctx, Lisp_Object lreloc)
{
  struct emacs_reloc reloc;
  dump_object_start (ctx, 1, &reloc, sizeof (reloc));
  reloc = decode_emacs_reloc (ctx, lreloc);
  dump_object_finish (ctx, &reloc, sizeof (reloc));
}

static Lisp_Object
dump_merge_emacs_relocs (Lisp_Object lreloc_a, Lisp_Object lreloc_b)
{
  /* Combine copy relocations together if they're copying from
     adjacent chunks to adjacent chunks.  */

  if (XFASTINT (XCAR (lreloc_a)) != RELOC_EMACS_COPY_FROM_DUMP ||
      XFASTINT (XCAR (lreloc_b)) != RELOC_EMACS_COPY_FROM_DUMP)
    return Qnil;

  struct emacs_reloc reloc_a = decode_emacs_reloc (NULL, lreloc_a);
  struct emacs_reloc reloc_b = decode_emacs_reloc (NULL, lreloc_b);

  eassert (reloc_a.type == RELOC_EMACS_COPY_FROM_DUMP);
  eassert (reloc_b.type == RELOC_EMACS_COPY_FROM_DUMP);

  if (reloc_a.emacs_offset + reloc_a.length != reloc_b.emacs_offset)
    return Qnil;

  if (reloc_a.u.dump_offset + reloc_a.length != reloc_b.u.dump_offset)
    return Qnil;

  ptrdiff_t new_length = reloc_a.length + reloc_b.length;
  reloc_a.length = new_length;
  if (reloc_a.length != new_length)
    return Qnil; /* Overflow */

  return list4 (make_number (RELOC_EMACS_COPY_FROM_DUMP),
                INTEGER_TO_CONS (reloc_a.emacs_offset),
                INTEGER_TO_CONS (reloc_a.u.dump_offset),
                INTEGER_TO_CONS (reloc_a.length));
}

static void
drain_reloc_list (struct dump_context *ctx,
                  void (*handler)(struct dump_context *, Lisp_Object),
                  Lisp_Object (*merger)(Lisp_Object a, Lisp_Object b),
                  Lisp_Object *reloc_list,
                  struct dump_table_locator *out_locator)
{
  Lisp_Object relocs = Fsort (Fnreverse (*reloc_list),
                              Qdump_emacs_portable__sort_predicate);
  *reloc_list = Qnil;
  dump_align_output (ctx, sizeof (dump_off_t));
  struct dump_table_locator locator;
  memset (&locator, 0, sizeof (locator));
  locator.offset = ctx->offset;
  for (; !NILP (relocs); locator.nr_entries += 1)
    {
      Lisp_Object reloc = dump_pop (&relocs);
      Lisp_Object merged;
      while (merger != NULL &&
             !NILP (relocs) &&
             ((merged = merger (reloc, XCAR (relocs))), !NILP (merged)))
        {
          reloc = merged;
          relocs = XCDR (relocs);
        }
      handler (ctx, reloc);
    }
  *out_locator = locator;
}

static void
dump_do_fixups (struct dump_context *ctx)
{
  ptrdiff_t saved_offset = ctx->offset;
  Lisp_Object fixups = Fsort (Fnreverse (ctx->fixups),
                              Qdump_emacs_portable__sort_predicate);
  ctx->fixups = Qnil;
  while (!NILP (fixups))
    dump_do_fixup (ctx, dump_pop (&fixups));
  dump_seek (ctx, saved_offset);
}

DEFUN ("dump-emacs-portable",
       Fdump_emacs_portable, Sdump_emacs_portable,
       1, 2, 0,
       doc: /* Dump current state of Emacs into dump file FILENAME.
If TRACK-REFERRERS is non-nil, keep additional debugging information
that can help track down the provenance of unsupported object
types.  */)
     (Lisp_Object filename, Lisp_Object track_referrers)
{
  eassert (initialized);

  if (will_dump_with_unexec)
    error ("This Emacs instance was started under the assumption "
           "that it would be dumped with unexec, not the portable "
           "dumper.  Dumping with the portable dumper may produce "
           "unexpected results.");

  ptrdiff_t count = SPECPDL_INDEX ();

  /* Bind `command-line-processed' to nil before dumping,
     so that the dumped Emacs will process its command line
     and set up to work with X windows if appropriate.  */
  Lisp_Object symbol = intern ("command-line-processed");
  specbind (symbol, Qnil);

  CHECK_STRING (filename);
  filename = Fexpand_file_name (filename, Qnil);
  filename = ENCODE_FILE (filename);

  struct dump_context ctx_buf;
  struct dump_context *ctx = &ctx_buf;
  memset (ctx, 0, sizeof (*ctx));
  ctx->fd = -1;

  ctx->objects_dumped = make_eq_hash_table ();
  dump_tailq_init (&ctx->dump_queue);
  ctx->fixups = Qnil;
  ctx->copied_queue = Qnil;
  ctx->cold_queue = Qnil;
  ctx->dump_relocs = Qnil;
  ctx->object_starts = Qnil;
  ctx->emacs_relocs = Qnil;

  ctx->current_referrer = Qnil;
  if (!NILP (track_referrers))
    ctx->referrers = make_eq_hash_table ();

  ctx->dump_filename = filename;

  record_unwind_protect_ptr (dump_unwind_cleanup, ctx);
  block_input ();

  ctx->old_purify_flag = Vpurify_flag;
  Vpurify_flag = Qnil;

  /* Make sure various weird things are less likely to happen.  */
  ctx->old_post_gc_hook = Vpost_gc_hook;
  Vpost_gc_hook = Qnil;

  ctx->fd = emacs_open (SSDATA (filename), O_RDWR | O_TRUNC | O_CREAT, 0666);
  if (ctx->fd < 0)
    report_file_error ("Opening dump output", filename);
  verify (sizeof (ctx->header.magic) == sizeof (dump_magic));
  memcpy (&ctx->header.magic, dump_magic, sizeof (dump_magic));
  ctx->header.magic[0] = '!'; /* Note that dump is incomplete.  */

  verify (sizeof (fingerprint) == sizeof (ctx->header.fingerprint));
  memcpy (ctx->header.fingerprint, fingerprint, sizeof (fingerprint));

  dump_write (ctx, &ctx->header, sizeof (ctx->header));

  /* Start the dump process by processing the static roots and
     queuing up the objects to which they refer.   */
  dump_roots (ctx);

  dump_charset_table (ctx);
  dump_finalizer_list_head_ptr (ctx, &finalizers.prev);
  dump_finalizer_list_head_ptr (ctx, &finalizers.next);
  dump_finalizer_list_head_ptr (ctx, &doomed_finalizers.prev);
  dump_finalizer_list_head_ptr (ctx, &doomed_finalizers.next);
  dump_user_remembered_data_hot (ctx);

  /* We've already remembered all of the GC roots themselves, but we
     have to manually save the list of GC roots.  */
  dump_metadata_for_pdumper (ctx);
  for (int i = 0; i < staticidx; ++i)
    dump_emacs_reloc_to_emacs_ptr_raw (ctx, &staticvec[i], staticvec[i]);
  dump_emacs_reloc_immediate_int (ctx, &staticidx, staticidx);

  /* Dump until while we keep finding objects to dump.  */
  while (!dump_tailq_empty_p (&ctx->dump_queue))
    dump_object (ctx, dump_tailq_pop (&ctx->dump_queue));

  eassert (dump_tailq_empty_p (&ctx->dump_queue));
  ctx->header.hot_discardable_start = ctx->offset;

  dump_copied_objects (ctx);
  eassert (dump_tailq_empty_p (&ctx->dump_queue));
  eassert (NILP (ctx->copied_queue));

  dump_align_output (ctx, getpagesize ());
  ctx->header.hot_end = ctx->offset;
  dump_cold_data (ctx);
   /* dump_user_remembered_data_cold needs to be after dump_cold_data
      in case dump_cold_data dumps a lisp object to which C code
      points.  dump_user_remembered_data_cold assumes that all lisp
      objects have been dumped.  */
  dump_user_remembered_data_cold (ctx);
  ctx->end_heap = ctx->offset;
  dump_do_fixups (ctx);
  drain_reloc_list (
    ctx, dump_emit_dump_reloc, NULL,
    &ctx->dump_relocs,
    &ctx->header.dump_relocs);
  drain_reloc_list (
    ctx, dump_emit_dump_reloc, NULL,
    &ctx->object_starts,
    &ctx->header.object_starts);
  drain_reloc_list (
    ctx, dump_emit_emacs_reloc, dump_merge_emacs_relocs,
    &ctx->emacs_relocs,
    &ctx->header.emacs_relocs);

  eassert (dump_tailq_empty_p (&ctx->dump_queue));
  eassert (NILP (ctx->fixups));
  eassert (NILP (ctx->dump_relocs));
  eassert (NILP (ctx->emacs_relocs));

  ctx->header.magic[0] = dump_magic[0]; /* Note dump is complete.  */
  dump_seek (ctx, 0);
  dump_write (ctx, &ctx->header, sizeof (ctx->header));

  return unbind_to (count, Qnil);

  // XXX: consider getting rid of hooks and just rely
  // on explicit calls?

  // XXX: nullify frame_and_buffer_state

  // XXX: inline stuff in pdumper.h

  // XXX: preferred base address

  // XXX: make offset math non-fwrapv-safe

  // XXX: output symbol chains consecutively
}

DEFUN ("dump-emacs-portable--sort-predicate",
       Fdump_emacs_portable__sort_predicate,
       Sdump_emacs_portable__sort_predicate,
       2, 2, 0,
       doc: /* Internal relocation sorting function.  */)
     (Lisp_Object a, Lisp_Object b)
{
  ptrdiff_t a_offset = ptrdiff_t_from_lisp (XCAR (XCDR (a)));
  ptrdiff_t b_offset = ptrdiff_t_from_lisp (XCAR (XCDR (b)));
  return a_offset < b_offset ? Qt : Qnil;
}

DEFUN ("dump-emacs-portable--sort-predicate-copied",
       Fdump_emacs_portable__sort_predicate_copied,
       Sdump_emacs_portable__sort_predicate_copied,
       2, 2, 0,
       doc: /* Internal relocation sorting function.  */)
     (Lisp_Object a, Lisp_Object b)
{
  eassert (dump_object_emacs_ptr (a));
  eassert (dump_object_emacs_ptr (b));
  return dump_object_emacs_ptr (a) < dump_object_emacs_ptr (b) ? Qt : Qnil;
}

void
pdumper_do_now_and_after_load (pdumper_hook hook)
{
  if (nr_dump_hooks == ARRAYELTS (dump_hooks))
    fatal ("out of dump hooks: make dump_hooks[] bigger");
  dump_hooks[nr_dump_hooks++] = hook;
  hook ();
}

static void
pdumper_remember_user_data_1 (void *mem, int nbytes)
{
  if (nr_remembered_data == ARRAYELTS (remembered_data))
    fatal ("out of remembered data slots: make remembered_data[] bigger");
  remembered_data[nr_remembered_data].mem = mem;
  remembered_data[nr_remembered_data].sz = nbytes;
  nr_remembered_data += 1;
}

void
pdumper_remember_scalar (void *mem, ptrdiff_t nbytes)
{
  eassert (0 <= nbytes && nbytes <= INT_MAX);
  if (nbytes > 0)
    pdumper_remember_user_data_1 (mem, nbytes);
}

void
pdumper_remember_lv_raw_ptr (void* ptr, enum Lisp_Type type)
{
  pdumper_remember_user_data_1 (ptr, -type);
}



struct loaded_dump
{
  char *start;
  char *end;
  struct dump_header header;
  unsigned *mark_bits;
};

struct loaded_dump loaded_dump;

/* Search for a relocation given a relocation target.

   DUMP is the dump metadata structure.  TABLE is the relocation table
   to search.  KEY is the dump offset to find.  Return the greatest
   relocation RELOC such that RELOC.offset <= KEY or NULL if no such
   relocation exists.  */
static const struct dump_reloc *
dump_find_relocation (struct loaded_dump *dump,
                      const struct dump_table_locator *table,
                      dump_off_t key)
{
  const struct dump_reloc *left = (void *)(dump->start + table->offset);
  const struct dump_reloc *right = left + table->nr_entries;
  const struct dump_reloc *found = NULL;

  while (left < right)
    {
      const struct dump_reloc *mid = left + (right - left) / 2;
      if (mid->offset <= key)
        {
          found = mid;
          left = mid + 1;
          if (left >= right || left->offset > key)
            break;
        }
      else
        right = mid;
   }

  return found;
}

static bool
dump_loaded_p (void)
{
  return loaded_dump.start != NULL;
}

/* Return whether the OBJ points somewhere into the loaded dump image.
   Works even when we have no dump loaded --- in this case, it just
   returns false.  */
bool
pdumper_object_p (const void *obj)
{
  const char *p = obj;
  return loaded_dump.start <= p && p < loaded_dump.end;
}

/* Return whether OBJ points exactly to the start of some object in
   the loaded dump image.  It is a programming error to call this
   routine for an OBJ for which pdumper_object_p would return
   false.  */
bool
pdumper_object_p_precise (const void *obj)
{
  return pdumper_find_object_type (obj) != PDUMPER_NO_OBJECT;
}

/* Return the type of the dumped object that starts at OBJ.  It is a
   programming error to call this routine for an OBJ for which
   pdumper_object_p would return false.  */
enum Lisp_Type
pdumper_find_object_type (const void *obj)
{
  eassert (pdumper_object_p (obj));
  ptrdiff_t offset = (char *) obj - (char *)loaded_dump.start;
  if (offset % GCALIGNMENT != 0)
    return PDUMPER_NO_OBJECT;
  const struct dump_reloc *reloc =
    dump_find_relocation (&loaded_dump,
                          &loaded_dump.header.object_starts,
                          offset);
  return (reloc != NULL && reloc->offset == offset)
    ? reloc->type
    : PDUMPER_NO_OBJECT;
}

static ptrdiff_t
dump_mark_bits_nbytes (ptrdiff_t max_offset)
{
  ptrdiff_t bits_needed = (max_offset + GCALIGNMENT - 1) / GCALIGNMENT;
  ptrdiff_t bytes_needed = (bits_needed + CHAR_BIT - 1) / CHAR_BIT;
  return ROUNDUP (bytes_needed, sizeof (unsigned));
}

bool
pdumper_marked_p (const void *obj)
{
  eassert (pdumper_object_p (obj));
  ptrdiff_t offset = (char *) obj - loaded_dump.start;
  eassert (offset % GCALIGNMENT == 0);
  eassert (offset < loaded_dump.header.hot_discardable_start);
  ptrdiff_t bitno = offset / GCALIGNMENT;
  ptrdiff_t slotno = bitno / (CHAR_BIT * sizeof (unsigned));
  unsigned *slot = &loaded_dump.mark_bits[slotno];
  return *slot & (1U << (bitno % (CHAR_BIT * sizeof (unsigned))));
}

void
pdumper_set_marked (const void *obj)
{
  eassert (pdumper_object_p (obj));
  ptrdiff_t offset = (char *) obj - loaded_dump.start;
  eassert (offset % GCALIGNMENT == 0);
  eassert (offset < loaded_dump.header.hot_discardable_start);
  ptrdiff_t bitno = offset / GCALIGNMENT;
  ptrdiff_t slotno = bitno / (CHAR_BIT * sizeof (unsigned));
  unsigned *slot = &loaded_dump.mark_bits[slotno];
  *slot |= (1U << (bitno % (CHAR_BIT * sizeof (unsigned))));
}

void
pdumper_clear_marks (void)
{
  memset (loaded_dump.mark_bits, 0,
          dump_mark_bits_nbytes (loaded_dump.header.hot_discardable_start));
}

static ssize_t
pdumper_read (int fd, void *buf, size_t bytes_to_read)
{
  eassert (bytes_to_read <= SSIZE_MAX);
  size_t bytes_read = 0;
  while (bytes_read < bytes_to_read)
    {
      ssize_t chunk =
        read (fd, (char*) buf + bytes_read, bytes_to_read - bytes_read);
      if (chunk < 0)
        return chunk;
      if (chunk == 0)
        break;
      bytes_read += chunk;
    }

  return bytes_read;
}

static void *
dump_ptr (struct loaded_dump *dump, ptrdiff_t offset)
{
  eassert (dump->start + offset < dump->end);
  return dump->start + offset;
}

static void *
emacs_ptr (ptrdiff_t offset)
{
  // TODO: assert somehow that offset is actually inside Emacs
  return (void *) (emacs_basis () + offset);
}

static void
dump_do_dump_relocation (struct loaded_dump *dump,
                         struct dump_reloc reloc)
{
  ptrdiff_t *dump_ptr_ptr = dump_ptr (dump, reloc.offset);
  ptrdiff_t dump_ptr = *dump_ptr_ptr;
  ptrdiff_t dump_base = (ptrdiff_t) dump->start;

  /* For -O0 debugging: optimizer realizes this variable is dead and
     optimizes it away.  */
  ptrdiff_t orig_dump_ptr = dump_ptr;
  (void) orig_dump_ptr;

  switch (reloc.type)
    {
    case RELOC_DUMP_TO_EMACS_RAW_PTR:
      dump_ptr = dump_ptr + emacs_basis ();
      *dump_ptr_ptr = dump_ptr;
      break;
    case RELOC_DUMP_TO_DUMP_RAW_PTR:
      dump_ptr = dump_ptr + dump_base;
      *dump_ptr_ptr = dump_ptr;
      break;
    default:
      {
        enum Lisp_Type lisp_type;
        if (RELOC_DUMP_TO_DUMP_LV <= reloc.type &&
            reloc.type < RELOC_DUMP_TO_EMACS_LV)
          {
            lisp_type = reloc.type - RELOC_DUMP_TO_DUMP_LV;
            dump_ptr = dump_ptr + dump_base;
          }
        else
          {
            eassert (RELOC_DUMP_TO_EMACS_LV <= reloc.type);
            eassert (reloc.type < RELOC_DUMP_TO_EMACS_LV + 8);
            lisp_type = reloc.type - RELOC_DUMP_TO_EMACS_LV;
            dump_ptr = dump_ptr + emacs_basis ();
          }

        Lisp_Object lv;
        if (lisp_type == Lisp_Symbol)
          lv = make_lisp_symbol ((void *) dump_ptr);
        else
          lv = make_lisp_ptr ((void *) dump_ptr, lisp_type);

        * (Lisp_Object *) dump_ptr_ptr = lv;
        break;
      }
    }

  // XXX: raw_ptr or ptr_raw. Pick one.
}

static void
dump_do_dump_relocations (struct loaded_dump *dump)
{
  struct dump_header *header = &dump->header;
  struct dump_reloc *r = dump_ptr (dump, header->dump_relocs.offset);
  dump_off_t nr_entries = header->dump_relocs.nr_entries;
  for (dump_off_t i = 0; i < nr_entries; ++i)
    dump_do_dump_relocation (dump, r[i]);
}

static void
dump_do_emacs_relocation (struct loaded_dump *dump,
                          struct emacs_reloc reloc)
{
  ptrdiff_t dump_base = (ptrdiff_t) dump->start;
  ptrdiff_t pval;
  Lisp_Object lv;

  switch (reloc.type)
    {
    case RELOC_EMACS_COPY_FROM_DUMP:
      eassume (reloc.length > 0);
      memcpy (emacs_ptr (reloc.emacs_offset),
              dump_ptr (dump, reloc.u.dump_offset),
              reloc.length);
      break;
    case RELOC_EMACS_IMMEDIATE:
      eassume (reloc.length > 0);
      eassume (reloc.length <= sizeof (reloc.u.immediate));
      memcpy (emacs_ptr (reloc.emacs_offset),
              &reloc.u.immediate,
              reloc.length);
      break;
    case RELOC_EMACS_DUMP_PTR_RAW:
      pval = reloc.u.dump_offset + dump_base;
      memcpy (emacs_ptr (reloc.emacs_offset), &pval, sizeof (pval));
      break;
    case RELOC_EMACS_EMACS_PTR_RAW:
      pval = reloc.u.emacs_offset2 + emacs_basis ();
      memcpy (emacs_ptr (reloc.emacs_offset), &pval, sizeof (pval));
      break;
    case RELOC_EMACS_DUMP_LV:
      eassume (reloc.length <= Lisp_Float);
      if (reloc.length == Lisp_Symbol)
        lv = make_lisp_symbol (dump_ptr (dump, reloc.u.dump_offset));
      else
        lv = make_lisp_ptr (dump_ptr (dump, reloc.u.dump_offset),
                            reloc.length);
      memcpy (emacs_ptr (reloc.emacs_offset), &lv, sizeof (lv));
      break;
    default:
      fatal ("unrecognied relocation type %d", (int) reloc.type);
    }
}

static void
dump_do_emacs_relocations (struct loaded_dump *dump)
{
  struct dump_header *header = &dump->header;
  struct emacs_reloc *r = dump_ptr (dump, header->emacs_relocs.offset);
  dump_off_t nr_entries = header->emacs_relocs.nr_entries;
  for (dump_off_t i = 0; i < nr_entries; ++i)
    dump_do_emacs_relocation (dump, r[i]);
}

/* Load a dump from DUMP_FILENAME.  We run very early in
   initialization, so we can't use lisp, unwinding, xmalloc, and so
   on.  */
enum pdumper_load_result
pdumper_load (const char *dump_filename)
{
  int fd = -1;
  enum pdumper_load_result err = PDUMPER_LOAD_ERROR;
  struct loaded_dump ndump;
  struct stat stat;
  struct dump_header *header = &ndump.header;
  ptrdiff_t mark_nbytes;

  memset (&ndump, 0, sizeof (ndump));
  eassert (!initialized);
  eassert (!dump_loaded_p ());

  err = PDUMPER_LOAD_FILE_NOT_FOUND;
  fd = emacs_open (dump_filename, O_RDONLY, 0);
  if (fd < 0)
    goto out;

  if (fstat (fd, &stat) < 0)
    goto out;

  err = PDUMPER_LOAD_BAD_FILE_TYPE;
  if (stat.st_size < sizeof (*header))
    goto out;

  err = PDUMPER_LOAD_OOM;
  ndump.start = malloc (stat.st_size);
  if (ndump.start == NULL)
    goto out;
  eassert ((ptrdiff_t) ndump.start % GCALIGNMENT == 0);
  ndump.end = ndump.start + stat.st_size;

  err = PDUMPER_LOAD_BAD_FILE_TYPE;
  if (pdumper_read (fd, ndump.start, stat.st_size) < stat.st_size)
    goto out;

  memcpy (header, ndump.start, sizeof (*header));
  if (memcmp (header->magic, dump_magic, sizeof (dump_magic) != 0))
    goto out;

  err = PDUMPER_LOAD_VERSION_MISMATCH;
  verify (sizeof (header->fingerprint) == sizeof (fingerprint));
  if (memcmp (header->fingerprint, fingerprint, sizeof (fingerprint)))
    goto out;

  err = PDUMPER_LOAD_ERROR;
  mark_nbytes = dump_mark_bits_nbytes (ndump.header.hot_discardable_start);
  ndump.mark_bits = calloc (1, mark_nbytes);
  if (ndump.mark_bits == NULL)
    goto out;

  /* Point of no return.  */

  gflags.dumped_with_pdumper_ = true;
  loaded_dump = ndump;
  memset (&ndump, 0, sizeof (ndump));
  err = PDUMPER_LOAD_SUCCESS;

  dump_do_dump_relocations (&loaded_dump);
  dump_do_emacs_relocations (&loaded_dump);

  /* Run the functions Emacs registered for doing post-dump-load
     initialization.  */
  for (int i = 0; i < nr_dump_hooks; ++i)
    dump_hooks[i] ();
  gflags.initialized_ = true;

 out:
  free (ndump.mark_bits);
  free (ndump.start);
  if (0 <= fd)
    emacs_close (fd);
  return err;
}



void
syms_of_pdumper (void)
{
  defsubr (&Sdump_emacs_portable);
  defsubr (&Sdump_emacs_portable__sort_predicate);
  defsubr (&Sdump_emacs_portable__sort_predicate_copied);
  DEFSYM (Qdump_emacs_portable__sort_predicate,
          "dump-emacs-portable--sort-predicate");
  DEFSYM (Qdump_emacs_portable__sort_predicate_copied,
          "dump-emacs-portable--sort-predicate-copied");
}
