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

কাঠামো sshkey;

পূর্ণসংখ্যা	pkcs11_init(পূর্ণসংখ্যা);
শূন্য	pkcs11_terminate(শূন্য);
পূর্ণসংখ্যা	pkcs11_add_provider(অক্ষর *, অক্ষর *, কাঠামো sshkey ***, অক্ষর ***);
পূর্ণসংখ্যা	pkcs11_del_provider(অক্ষর *);
পূর্ণসংখ্যা	pkcs11_sign(কাঠামো sshkey *, u_char **, আকার_t *,
	    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
	    ধ্রুবক অক্ষর *, u_int);
শূন্য	pkcs11_চাবি_free(কাঠামো sshkey *);

#ifdef WITH_PKCS11_KEYGEN
কাঠামো sshkey *
	pkcs11_gakp(অক্ষর *, অক্ষর *, unsigned পূর্ণসংখ্যা, অক্ষর *, unsigned পূর্ণসংখ্যা,
	    unsigned পূর্ণসংখ্যা, unsigned অক্ষর, uint32_t *);
কাঠামো sshkey *
	pkcs11_destroy_keypair(অক্ষর *, অক্ষর *, unsigned long, unsigned অক্ষর,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
পূর্ণসংখ্যা pkcs11_make_cert(ধ্রুবক কাঠামো sshkey *,
    ধ্রুবক কাঠামো sshkey *, কাঠামো sshkey **);
