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
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_PKCS11_ERR_GENERIC			1
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_PKCS11_ERR_LOGIN_FAIL		2
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_PKCS11_ERR_NO_SLOTS			3
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_PKCS11_ERR_PIN_REQUIRED		4
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_PKCS11_ERR_PIN_LOCKED		5

ರಚನೆ sshkey;

ಪೂರ್ಣಾಂಕ	pkcs11_init(ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	pkcs11_terminate(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ	pkcs11_ಕೂಡಿಸು_provider(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ರಚನೆ sshkey ***, ಅಕ್ಷರ ***);
ಪೂರ್ಣಾಂಕ	pkcs11_del_provider(ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	pkcs11_sign(ರಚನೆ sshkey *, u_char **, ಗಾತ್ರ_t *,
	    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int);
ಶೂನ್ಯ	pkcs11_ಕೀಲಿ_free(ರಚನೆ sshkey *);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_PKCS11_KEYGEN
ರಚನೆ sshkey *
	pkcs11_gakp(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ,
	    ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ, uint32_t *);
ರಚನೆ sshkey *
	pkcs11_destroy_keypair(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ,
	    uint32_t *);
#ಆದರೆ_ಅಂತ್ಯ

/* Only available in ssh-pkcs11-client.c */
ಪೂರ್ಣಾಂಕ pkcs11_make_cert(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshkey **);
