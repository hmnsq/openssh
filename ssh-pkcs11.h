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

بنية sshkey;

صحيح	pkcs11_init(صحيح);
فراغ	pkcs11_terminate(فراغ);
صحيح	pkcs11_add_provider(حرف *, حرف *, بنية sshkey ***, حرف ***);
صحيح	pkcs11_del_provider(حرف *);
صحيح	pkcs11_sign(بنية sshkey *, u_char **, size_t *,
	    ثابت u_char *, size_t, ثابت حرف *, ثابت حرف *,
	    ثابت حرف *, u_int);
فراغ	pkcs11_مبودي_free(بنية sshkey *);

#ifdef WITH_PKCS11_KEYGEN
بنية sshkey *
	pkcs11_gakp(حرف *, حرف *, unsigned صحيح, حرف *, unsigned صحيح,
	    unsigned صحيح, unsigned حرف, uint32_t *);
بنية sshkey *
	pkcs11_destroy_keypair(حرف *, حرف *, unsigned long, unsigned حرف,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
صحيح pkcs11_make_cert(ثابت بنية sshkey *,
    ثابت بنية sshkey *, بنية sshkey **);
