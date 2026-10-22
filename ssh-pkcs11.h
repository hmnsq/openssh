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

ಸಂರಚನಾ sshkey;

ಪೂರ್ಣಾಙ್ಕ	pkcs11_init(ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	pkcs11_terminate(ಶೂನ್ಯ);
ಪೂರ್ಣಾಙ್ಕ	pkcs11_add_provider(ವರ್ಣ *, ವರ್ಣ *, ಸಂರಚನಾ sshkey ***, ವರ್ಣ ***);
ಪೂರ್ಣಾಙ್ಕ	pkcs11_del_provider(ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	pkcs11_sign(ಸಂರಚನಾ sshkey *, u_char **, size_t *,
	    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
	    ಧ್ರುವ ವರ್ಣ *, u_int);
ಶೂನ್ಯ	pkcs11_ಕೀಲಿ_free(ಸಂರಚನಾ sshkey *);

#ifdef WITH_PKCS11_KEYGEN
ಸಂರಚನಾ sshkey *
	pkcs11_gakp(ವರ್ಣ *, ವರ್ಣ *, unsigned ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *, unsigned ಪೂರ್ಣಾಙ್ಕ,
	    unsigned ಪೂರ್ಣಾಙ್ಕ, unsigned ವರ್ಣ, uint32_t *);
ಸಂರಚನಾ sshkey *
	pkcs11_destroy_keypair(ವರ್ಣ *, ವರ್ಣ *, unsigned long, unsigned ವರ್ಣ,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
ಪೂರ್ಣಾಙ್ಕ pkcs11_make_cert(ಧ್ರುವ ಸಂರಚನಾ sshkey *,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshkey **);
