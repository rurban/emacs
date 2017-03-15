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

#include <config.h>
#include <errno.h>

#include "lisp.h"

#ifdef HAVE_NETTLE

#include "nettle.h"

DEFUN ("nettle-available-p", Fnettle_available_p, Snettle_available_p, 0, 0, 0,
       doc: /* Return t if Nettle is available in this instance of Emacs.

The Nettle integration binds Emacs with libnettle and libhogweed.
See http://www.lysator.liu.se/~nisse/nettle for more on Nettle.  */)
     (void)
{
  return Qt;
}

DEFUN ("nettle-hash", Fnettle_hash, Snettle_hash, 2, 2, 0,
       doc: /* Hash INPUT string with HASH-METHOD into a unibyte string.

The list of hash-methods can be obtained with `nettle-hashes`.
The `sha256' hashing method is recommended by the libnettle documentation.  */)
  (Lisp_Object input, Lisp_Object hash_method)
{
  Lisp_Object ret = Qnil;

  CHECK_STRING (input);
  CHECK_STRING (hash_method);

  for (int i = 0; NULL != nettle_hashes[i]; i++)
    {
      if (NETTLE_STRING_EQUAL_UNIBYTE (hash_method, nettle_hashes[i]->name))
        {
          const struct nettle_hash *alg = nettle_hashes[i];
          unsigned int length = alg->digest_size;
          void *ctx = xzalloc (alg->context_size);
          uint8_t *digest;
          ctx = xzalloc (alg->context_size);
          alg->init (ctx);
          alg->update (ctx, SCHARS (input), SDATA (input));

          digest = xzalloc (length);
          alg->digest (ctx, length, digest);

          ret = make_unibyte_string ((const char*) digest, length);

          xfree (digest);
          xfree (ctx);
        }
    }

  if (NILP (ret))
    {
      error ("Nettle hash-method %s was not found", SDATA (hash_method));
    }

  return ret;
}

DEFUN ("nettle-hmac", Fnettle_hmac, Snettle_hmac, 3, 3, 0,
       doc: /* HMAC hash INPUT string with HASH-METHOD and KEY.

The string is hashed into a unibyte string according to HMAC (RFC 2104).

The list of hash-methods can be obtained with `nettle-hashes`.
The `sha256' hashing method is recommended by the libnettle documentation.  */)
  (Lisp_Object input, Lisp_Object key, Lisp_Object hash_method)
{
  Lisp_Object ret = Qnil;

  CHECK_STRING (input);
  CHECK_STRING (hash_method);
  CHECK_STRING (key);

  for (int i = 0; NULL != nettle_hashes[i]; i++)
    {
      if (NETTLE_STRING_EQUAL_UNIBYTE (hash_method, nettle_hashes[i]->name))
        {
          const struct nettle_hash *alg = nettle_hashes[i];
          unsigned int length = alg->digest_size;
          void *inner_ctx = xzalloc (alg->context_size);
          void *outer_ctx = xzalloc (alg->context_size);
          void *state_ctx = xzalloc (alg->context_size);
          uint8_t *digest;

          hmac_set_key (outer_ctx, inner_ctx, state_ctx, alg, SCHARS (key), SDATA (key));
          hmac_update (state_ctx, alg, SCHARS (input), SDATA (input));
          digest = xzalloc (length);
          hmac_digest (outer_ctx, inner_ctx, state_ctx, alg, length, digest);

          ret = make_unibyte_string ((const char*) digest, length);

          xfree (digest);
          xfree (state_ctx);
          xfree (outer_ctx);
          xfree (inner_ctx);
        }
    }

  if (NILP (ret))
    {
      error ("Nettle hash-method %s was not found", SDATA (hash_method));
    }

  return ret;
}

DEFUN ("nettle-pbkdf2", Fnettle_pbkdf2, Snettle_pbkdf2, 5, 5, 0,
       doc: /* Make PBKDF2 of HASH-LENGTH from KEY with HASH-METHOD using ITERATIONS and SALT.

The PBKDF2 data is stored in a unibyte string according to RFC 2898.
The list of hash-methods can be obtained with `nettle-hashes`.
The `sha1' and `sha256' hashing methods are most common and only supported now.  */)
  (Lisp_Object key, Lisp_Object salt, Lisp_Object iterations, Lisp_Object hash_length, Lisp_Object hash_method)
{
  Lisp_Object ret = Qnil;
  bool sha1_mode = false;
  bool sha256_mode = false;
  int outlength = 0;

  CHECK_STRING (salt);
  CHECK_STRING (hash_method);
  CHECK_STRING (key);
  CHECK_NUMBER (iterations);
  CHECK_NUMBER (hash_length);

  outlength = XINT (hash_length);

  sha1_mode = NETTLE_STRING_EQUAL_UNIBYTE (hash_method, "sha1");
  sha256_mode = NETTLE_STRING_EQUAL_UNIBYTE (hash_method, "sha256");

  if (sha1_mode)
    {
      uint8_t *digest = xzalloc (outlength);
      pbkdf2_hmac_sha1 (SCHARS (key), SDATA (key), XINT (iterations), SCHARS (salt), SDATA (salt), outlength, digest);
      ret = make_unibyte_string ((const char*) digest, outlength);
      xfree (digest);
    }
  else if (sha256_mode)
    {
      uint8_t *digest = xzalloc (outlength);
      pbkdf2_hmac_sha256 (SCHARS (key), SDATA (key), XINT (iterations), SCHARS (salt), SDATA (salt), outlength, digest);
      ret = make_unibyte_string ((const char*) digest, outlength);
      xfree (digest);
    }
  else
    {
      error ("Nettle hash-method %s is not supported yet, sorry", SDATA (hash_method));
    }

  /* TODO: figure out why this doesn't work correctly.  For now only sha1 and sha256 are supported.
  for (int i = 0; NULL != nettle_hashes[i]; i++)
    {
      if (NETTLE_STRING_EQUAL_UNIBYTE (hash_method, nettle_hashes[i]->name))
        {
          const struct nettle_hash *alg = nettle_hashes[i];
          unsigned int length = alg->digest_size;
          void *ctx = NULL;
          uint8_t *digest = xzalloc (outlength);
          int csize = alg->context_size;

          message("Generating PBKDF2 with cipher %s, key(%d) '%s', salt(%d) '%s', iterations %d", alg->name, SCHARS (key), SDATA (key), SCHARS (salt), SDATA (salt), XINT (iterations));
          ctx = xzalloc (3*csize);

          // HMAC_SET_KEY(ctx, alg, SCHARS (key), SDATA (key));
          // PBKDF2 (ctx, alg->update, alg->digest, length, XINT (iterations), SCHARS (salt), SDATA (salt), outlength, digest);
          message("first 4 bytes generated => %x %x %x %x", digest[0], digest[1], digest[2], digest[3] );

          ret = make_unibyte_string ((const char*) digest, outlength);

          xfree (digest);
          xfree (ctx);
        }
    }
  */

  if (NILP (ret))
    {
      error ("Nettle hash-method %s was not found", SDATA (hash_method));
    }

  return ret;
}

DEFUN ("nettle-rsa-verify", Fnettle_rsa_verify, Snettle_rsa_verify, 4, 4, 0,
       doc: /* Verify the RSA SIGNATURE of DATA with PUBLIC-KEY and HASH-METHOD.

The list of hash-methods can be obtained with `nettle-hashes`.
Only the `md5', `sha1', `sha256', and `sha512' hashing methods are supported.  */)
  (Lisp_Object data, Lisp_Object signature, Lisp_Object public_key, Lisp_Object hash_method)
{
  Lisp_Object ret = Qnil;
  bool md5_mode = false;
  bool sha1_mode = false;
  bool sha256_mode = false;
  bool sha512_mode = false;
  struct rsa_public_key key;
  mpz_t s;

  CHECK_STRING (data);
  CHECK_STRING (signature);
  CHECK_STRING (public_key);
  CHECK_STRING (hash_method);

  if (SCHARS (signature) < 16)
    {
      error ("RSA signature must be at least 16 bytes long");
    }

  mpz_init(s);
  if (!mpz_set_str(s, SSDATA (signature), 16))
    {
      error ("RSA signature could not be loaded");
    }

  rsa_public_key_init(&key);

  if (!rsa_keypair_from_der (&key, NULL, 0, SCHARS (public_key), SDATA (public_key))
      && !rsa_keypair_from_sexp (&key, NULL, 0, SCHARS (public_key), SDATA (public_key)))
    {
      if (SCHARS (public_key) > 3)
        {
          // char* p = SSDATA (public_key);
          // message("first 4 bytes of bad public key => %x %x %x %x", p[0], p[1], p[2], p[3] );
        }
      error ("RSA public key could not be loaded in binary or DER formats");
    }

  md5_mode = NETTLE_STRING_EQUAL_UNIBYTE (hash_method, "md5");
  sha1_mode = NETTLE_STRING_EQUAL_UNIBYTE (hash_method, "sha1");;
  sha256_mode = NETTLE_STRING_EQUAL_UNIBYTE (hash_method, "sha256");
  sha512_mode = NETTLE_STRING_EQUAL_UNIBYTE (hash_method, "sha512");

  if (sha1_mode)
    {
      struct sha1_ctx hash;

      sha1_init(&hash);
      sha1_update(&hash, SCHARS (data), SDATA (data));

      if (rsa_sha1_verify(&key, &hash, s))
        {
          ret = Qt;
        }
    }
  else
    {
      error ("Nettle hash-method %s is not supported yet, sorry", SDATA (hash_method));
    }

  mpz_clear(s);
  rsa_public_key_clear(&key);

  return ret;
}

DEFUN ("nettle-hashes", Fnettle_hashes, Snettle_hashes, 0, 1, 0,
       doc: /* Return alist of Nettle hash names and their details.
With the optional NAME, returns just one hash's info (NAME DIGESTSIZE BLOCKSIZE).  */)
  (Lisp_Object name)
{
  Lisp_Object hashes = Qnil;

  if (! NILP (name))
    {
      CHECK_STRING (name);
    }

  for (int i = 0; nettle_hashes[i] != NULL; i++)
    {
      Lisp_Object hash = Fcons (build_string (nettle_hashes[i]->name),
                                list2i (nettle_hashes[i]->digest_size,
                                        nettle_hashes[i]->block_size));

      if (! NILP (name) && NETTLE_STRING_EQUAL_UNIBYTE (name, nettle_hashes[i]->name))
        {
          return hash;
        }

      hashes = Fcons (hash, hashes);
    }

  if (NILP (name))
    {
      return hashes;
    }

  return Qnil;
}

DEFUN ("nettle-crypt", Fnettle_crypt, Snettle_crypt, 6, 6, 0,
       doc: /* Encrypt or decrypt INPUT in CRYPT-MODE with KEY, CIPHER, CIPHER-MODE, and IV.

The INPUT will be zero-padded to be a multiple of the cipher's block size.

The KEY will be zero-padded to the cipher's key size and will be
trimmed if it exceeds that key size.

The list of ciphers can be obtained with `nettle-ciphers`.
The list of cipher modes can be obtained with `nettle-cipher-modes`.
The `aes256' cipher method is probably best for general use.
The `twofish256' cipher method may be better if you want to avoid NIST ciphers.  */)
  (Lisp_Object crypt_mode, Lisp_Object input, Lisp_Object key, Lisp_Object iv, Lisp_Object cipher, Lisp_Object cipher_mode)
{
  Lisp_Object ret = Qnil;
  Lisp_Object mode = Qnil;
  bool decrypt = NILP(crypt_mode);
  bool ctr_mode = false;

  CHECK_STRING (input);
  CHECK_SYMBOL (crypt_mode);
  CHECK_STRING (key);
  CHECK_STRING (iv);
  CHECK_STRING (cipher);
  CHECK_STRING (cipher_mode);

  mode = CAR_SAFE (Fmember (cipher_mode, Fnettle_cipher_modes ()));

  ctr_mode = NETTLE_STRING_EQUAL_UNIBYTE (mode, "CTR");

  if (NILP (mode))
    {
      error ("Nettle cipher mode %s was not found", SDATA (cipher_mode));
    }

  for (int i = 0; NULL != nettle_ciphers[i]; i++)
    {
      if (NETTLE_STRING_EQUAL_UNIBYTE (cipher, nettle_ciphers[i]->name))
        {
          const struct nettle_cipher *alg = nettle_ciphers[i];
          unsigned int input_length = SCHARS (input);
          void *ctx = xzalloc (alg->context_size);
          void *dest = NULL;
          unsigned char *key_hold = NULL;
          unsigned char *iv_hold = NULL;

          /* Increment input_length to the next multiple of block_size.  */
          if (0 != alg->block_size)
            {
              while (0 != (input_length % alg->block_size))
                {
                  input_length++;
                }
            }

          // message("Input length is %d and the block size is %d", input_length, alg->block_size);

          dest = xzalloc (input_length);
          memcpy (dest, SDATA (input), SCHARS (input));
          // message("Dest buffer: '%s' and size is %d", dest, input_length);

          key_hold = xzalloc (alg->key_size);
          memcpy (key_hold, SDATA (key), min (alg->key_size, SCHARS (key)));

          iv_hold = xzalloc (alg->block_size);
          memcpy (iv_hold, SDATA (iv), SCHARS (iv));

          // message("Key buffer: '%s' and key size %d", key_hold, alg->key_size);

          // in CTR mode we use set_encrypt_key regardless
          if (decrypt && !ctr_mode)
            {
              alg->set_decrypt_key (ctx, key_hold);
            }
          else
            {
              alg->set_encrypt_key (ctx, key_hold);
            }

          // message("%s %s with cipher %s, key(%d) '%s', IV(%d) '%s', input(%d) '%s'", SDATA (mode), decrypt ? "decrypting" : "encrypting", alg->name, SCHARS (key), SDATA (key), SCHARS (iv), SDATA (iv), SCHARS (input), SDATA (input));
          if (0 == NETTLE_STRING_EQUAL_UNIBYTE (mode, "ECB"))
            {
              if (decrypt)
                {
                  alg->decrypt (ctx, input_length, dest, dest);
                }
              else
                {
                  alg->encrypt (ctx, input_length, dest, dest);
                }
            }
          if (0 == NETTLE_STRING_EQUAL_UNIBYTE (mode, "CBC"))
            {
              if (decrypt)
                {
                  cbc_decrypt (ctx, alg->decrypt,
                               alg->block_size, iv_hold,
                               input_length, dest, dest);
                }
              else
                {
                  cbc_encrypt (ctx, alg->encrypt,
                               alg->block_size, iv_hold,
                               input_length, dest, dest);
                }
            }
          else if (ctr_mode)
            {
              ctr_crypt (ctx, alg->encrypt,
                         alg->block_size, iv_hold,
                         input_length, dest, dest);
            }
          else
            {
              error ("Unexpected error: Nettle cipher mode %s was not found", SDATA (mode));
            }

          // message("-> produced (%d) '%s'", input_length, dest);
          ret = make_unibyte_string ((const char*) dest, input_length);

          xfree (iv_hold);
          xfree (key_hold);
          xfree (dest);
          xfree (ctx);
        }
    }

  if (NILP (ret))
    {
      error ("Nettle cipher %s was not found", SDATA (cipher));
    }

  return ret;
}

DEFUN ("nettle-ciphers", Fnettle_ciphers, Snettle_ciphers, 0, 1, 0,
       doc: /* Return alist of Nettle cipher names and their descriptions.
With the optional NAME, returns just one cipher's info (NAME KEYSIZE BLOCKSIZE).  */)
  (Lisp_Object name)
{
  Lisp_Object ciphers = Qnil;

  if (! NILP (name))
    {
      CHECK_STRING (name);
    }

  for (int i = 0; nettle_ciphers[i] != NULL; i++)
    {
      Lisp_Object cipher = Fcons (build_string (nettle_ciphers[i]->name),
                                  list2i (nettle_ciphers[i]->key_size,
                                          nettle_ciphers[i]->block_size));

      if (! NILP (name) && NETTLE_STRING_EQUAL_UNIBYTE (name, nettle_ciphers[i]->name))
        {
          return cipher;
        }

      ciphers = Fcons (cipher, ciphers);
    }

  if (NILP (name))
    {
      return ciphers;
    }

  return Qnil;
}

DEFUN ("nettle-cipher-modes", Fnettle_cipher_modes, Snettle_cipher_modes, 0, 0, 0,
       doc: /* Return the list of Nettle cipher modes as strings.  */)
  (void)
{
  Lisp_Object modes = Qnil;
  modes = Fcons (build_string ("ECB"), modes);
  modes = Fcons (build_string ("CBC"), modes);
  modes = Fcons (build_string ("CTR"), modes);
  /* GCM is unsupported for now
     modes = Fcons (build_string ("GCM"), modes);
  */
  return modes;
}

void
syms_of_nettle (void)
{
  defsubr (&Snettle_available_p);
  defsubr (&Snettle_hash);
  defsubr (&Snettle_hashes);
  defsubr (&Snettle_crypt);
  defsubr (&Snettle_ciphers);
  defsubr (&Snettle_cipher_modes);
  defsubr (&Snettle_rsa_verify);
  // defsubr (&Snettle_dsa);
  // defsubr (&Snettle_ecc);
  defsubr (&Snettle_hmac);
  defsubr (&Snettle_pbkdf2);
  /* Not implemented yet. defsubr (&Snettle_umac); */
}

#endif /* HAVE_NETTLE */
