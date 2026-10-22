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

સંરચના sshkey;

પૂર્ણાંક	pkcs11_init(પૂર્ણાંક);
શૂન્ય	pkcs11_terminate(શૂન્ય);
પૂર્ણાંક	pkcs11_add_provider(અક્ષર *, અક્ષર *, સંરચના sshkey ***, અક્ષર ***);
પૂર્ણાંક	pkcs11_del_provider(અક્ષર *);
પૂર્ણાંક	pkcs11_sign(સંરચના sshkey *, u_char **, size_t *,
	    અચલ u_char *, size_t, અચલ અક્ષર *, અચલ અક્ષર *,
	    અચલ અક્ષર *, u_int);
શૂન્ય	pkcs11_ચાવી_free(સંરચના sshkey *);

#ifdef WITH_PKCS11_KEYGEN
સંરચના sshkey *
	pkcs11_gakp(અક્ષર *, અક્ષર *, unsigned પૂર્ણાંક, અક્ષર *, unsigned પૂર્ણાંક,
	    unsigned પૂર્ણાંક, unsigned અક્ષર, uint32_t *);
સંરચના sshkey *
	pkcs11_destroy_keypair(અક્ષર *, અક્ષર *, unsigned long, unsigned અક્ષર,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
પૂર્ણાંક pkcs11_make_cert(અચલ સંરચના sshkey *,
    અચલ સંરચના sshkey *, સંરચના sshkey **);
