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

ഘടന sshkey;

പൂർണ്ണസംഖ്യ	pkcs11_init(പൂർണ്ണസംഖ്യ);
ശൂന്യം	pkcs11_terminate(ശൂന്യം);
പൂർണ്ണസംഖ്യ	pkcs11_add_provider(അക്ഷരം *, അക്ഷരം *, ഘടന sshkey ***, അക്ഷരം ***);
പൂർണ്ണസംഖ്യ	pkcs11_del_provider(അക്ഷരം *);
പൂർണ്ണസംഖ്യ	pkcs11_sign(ഘടന sshkey *, u_char **, size_t *,
	    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
	    സ്ഥിരം അക്ഷരം *, u_int);
ശൂന്യം	pkcs11_താക്കോൽ_free(ഘടന sshkey *);

#ifdef WITH_PKCS11_KEYGEN
ഘടന sshkey *
	pkcs11_gakp(അക്ഷരം *, അക്ഷരം *, unsigned പൂർണ്ണസംഖ്യ, അക്ഷരം *, unsigned പൂർണ്ണസംഖ്യ,
	    unsigned പൂർണ്ണസംഖ്യ, unsigned അക്ഷരം, uint32_t *);
ഘടന sshkey *
	pkcs11_destroy_keypair(അക്ഷരം *, അക്ഷരം *, unsigned long, unsigned അക്ഷരം,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
പൂർണ്ണസംഖ്യ pkcs11_make_cert(സ്ഥിരം ഘടന sshkey *,
    സ്ഥിരം ഘടന sshkey *, ഘടന sshkey **);
