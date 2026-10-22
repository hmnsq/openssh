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

கட்டமைப்பு sshkey;

முழு	pkcs11_init(முழு);
வெறுமை	pkcs11_terminate(வெறுமை);
முழு	pkcs11_add_provider(எழுத்து *, எழுத்து *, கட்டமைப்பு sshkey ***, எழுத்து ***);
முழு	pkcs11_del_provider(எழுத்து *);
முழு	pkcs11_sign(கட்டமைப்பு sshkey *, u_char **, size_t *,
	    மாறிலி u_char *, size_t, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
	    மாறிலி எழுத்து *, u_int);
வெறுமை	pkcs11_சாவி_free(கட்டமைப்பு sshkey *);

#ifdef WITH_PKCS11_KEYGEN
கட்டமைப்பு sshkey *
	pkcs11_gakp(எழுத்து *, எழுத்து *, unsigned முழு, எழுத்து *, unsigned முழு,
	    unsigned முழு, unsigned எழுத்து, uint32_t *);
கட்டமைப்பு sshkey *
	pkcs11_destroy_keypair(எழுத்து *, எழுத்து *, unsigned long, unsigned எழுத்து,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
முழு pkcs11_make_cert(மாறிலி கட்டமைப்பு sshkey *,
    மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey **);
