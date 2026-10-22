/* $OpenBSD: ssh-pkcs11.h,v 1.11 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* API for ssh-pkcs11.c and ssh-pkcs11-client.c */

/* Errors for pkcs11_add_provider() */
#define	SSH_PKCS11_ERR_GENERIC			1
#define	SSH_PKCS11_ERR_LOGIN_FAIL		2
#define	SSH_PKCS11_ERR_NO_SLOTS			3
#define	SSH_PKCS11_ERR_PIN_REQUIRED		4
#define	SSH_PKCS11_ERR_PIN_LOCKED		5

সংরচনা sshkey;

পূর্ণাঙ্ক	pkcs11_init(পূর্ণাঙ্ক);
শূন্য	pkcs11_terminate(শূন্য);
পূর্ণাঙ্ক	pkcs11_add_provider(ৱর্ণ *, ৱর্ণ *, সংরচনা sshkey ***, ৱর্ণ ***);
পূর্ণাঙ্ক	pkcs11_del_provider(ৱর্ণ *);
পূর্ণাঙ্ক	pkcs11_sign(সংরচনা sshkey *, u_char **, size_t *,
	    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *,
	    ধ্রুৱ ৱর্ণ *, u_int);
শূন্য	pkcs11_চাবি_free(সংরচনা sshkey *);

#ifdef WITH_PKCS11_KEYGEN
সংরচনা sshkey *
	pkcs11_gakp(ৱর্ণ *, ৱর্ণ *, unsigned পূর্ণাঙ্ক, ৱর্ণ *, unsigned পূর্ণাঙ্ক,
	    unsigned পূর্ণাঙ্ক, unsigned ৱর্ণ, uint32_t *);
সংরচনা sshkey *
	pkcs11_destroy_keypair(ৱর্ণ *, ৱর্ণ *, unsigned long, unsigned ৱর্ণ,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
পূর্ণাঙ্ক pkcs11_make_cert(ধ্রুৱ সংরচনা sshkey *,
    ধ্রুৱ সংরচনা sshkey *, সংরচনা sshkey **);
