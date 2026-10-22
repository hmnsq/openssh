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
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_PKCS11_ERR_GENERIC			1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_PKCS11_ERR_LOGIN_FAIL		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_PKCS11_ERR_NO_SLOTS			3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_PKCS11_ERR_PIN_REQUIRED		4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SSH_PKCS11_ERR_PIN_LOCKED		5

ਬਣਤਰ sshkey;

ਪੂਰਨ	pkcs11_init(ਪੂਰਨ);
ਖਾਲੀ	pkcs11_terminate(ਖਾਲੀ);
ਪੂਰਨ	pkcs11_ਜੋੜੋ_provider(ਅੱਖਰ *, ਅੱਖਰ *, ਬਣਤਰ sshkey ***, ਅੱਖਰ ***);
ਪੂਰਨ	pkcs11_del_provider(ਅੱਖਰ *);
ਪੂਰਨ	pkcs11_sign(ਬਣਤਰ sshkey *, u_char **, ਮਾਪ_t *,
	    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
	    ਅਚਲ ਅੱਖਰ *, u_int);
ਖਾਲੀ	pkcs11_ਕੁੰਜੀ_free(ਬਣਤਰ sshkey *);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_PKCS11_KEYGEN
ਬਣਤਰ sshkey *
	pkcs11_gakp(ਅੱਖਰ *, ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ, ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ,
	    ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ, uint32_t *);
ਬਣਤਰ sshkey *
	pkcs11_destroy_keypair(ਅੱਖਰ *, ਅੱਖਰ *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ,
	    uint32_t *);
#ਜੇ_ਅੰਤ

/* Only available in ssh-pkcs11-client.c */
ਪੂਰਨ pkcs11_make_cert(ਅਚਲ ਬਣਤਰ sshkey *,
    ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey **);
