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

ସଂରଚନା sshkey;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	pkcs11_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	pkcs11_terminate(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	pkcs11_add_provider(ଅକ୍ଷର *, ଅକ୍ଷର *, ସଂରଚନା sshkey ***, ଅକ୍ଷର ***);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	pkcs11_del_provider(ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	pkcs11_sign(ସଂରଚନା sshkey *, u_char **, size_t *,
	    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
	    ଅଚଳ ଅକ୍ଷର *, u_int);
ଶୂନ୍ୟ	pkcs11_ଚାବି_free(ସଂରଚନା sshkey *);

#ifdef WITH_PKCS11_KEYGEN
ସଂରଚନା sshkey *
	pkcs11_gakp(ଅକ୍ଷର *, ଅକ୍ଷର *, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
	    unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା, unsigned ଅକ୍ଷର, uint32_t *);
ସଂରଚନା sshkey *
	pkcs11_destroy_keypair(ଅକ୍ଷର *, ଅକ୍ଷର *, unsigned long, unsigned ଅକ୍ଷର,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା pkcs11_make_cert(ଅଚଳ ସଂରଚନା sshkey *,
    ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshkey **);
