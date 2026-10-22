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

संरचना sshkey;

पूर्णांक	pkcs11_init(पूर्णांक);
शून्य	pkcs11_terminate(शून्य);
पूर्णांक	pkcs11_add_provider(अक्षर *, अक्षर *, संरचना sshkey ***, अक्षर ***);
पूर्णांक	pkcs11_del_provider(अक्षर *);
पूर्णांक	pkcs11_sign(संरचना sshkey *, u_char **, माप_प्रकार *,
	    स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *, स्थिरांक अक्षर *,
	    स्थिरांक अक्षर *, u_int);
शून्य	pkcs11_किल्ली_free(संरचना sshkey *);

#ifdef WITH_PKCS11_KEYGEN
संरचना sshkey *
	pkcs11_gakp(अक्षर *, अक्षर *, अचिन्हित पूर्णांक, अक्षर *, अचिन्हित पूर्णांक,
	    अचिन्हित पूर्णांक, अचिन्हित अक्षर, uint32_t *);
संरचना sshkey *
	pkcs11_destroy_keypair(अक्षर *, अक्षर *, अचिन्हित दीर्घ, अचिन्हित अक्षर,
	    uint32_t *);
#endif

/* Only available in ssh-pkcs11-client.c */
पूर्णांक pkcs11_make_cert(स्थिरांक संरचना sshkey *,
    स्थिरांक संरचना sshkey *, संरचना sshkey **);
