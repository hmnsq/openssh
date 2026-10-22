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
#تعریف_کرو	SSH_PKCS11_ERR_GENERIC			1
#تعریف_کرو	SSH_PKCS11_ERR_LOGIN_FAIL		2
#تعریف_کرو	SSH_PKCS11_ERR_NO_SLOTS			3
#تعریف_کرو	SSH_PKCS11_ERR_PIN_REQUIRED		4
#تعریف_کرو	SSH_PKCS11_ERR_PIN_LOCKED		5

ساخت sshkey;

صحیح	pkcs11_init(صحیح);
خالی	pkcs11_terminate(خالی);
صحیح	pkcs11_جوڑو_provider(حرف *, حرف *, ساخت sshkey ***, حرف ***);
صحیح	pkcs11_del_provider(حرف *);
صحیح	pkcs11_sign(ساخت sshkey *, u_char **, سائز_t *,
	    ثابت u_char *, سائز_t, ثابت حرف *, ثابت حرف *,
	    ثابت حرف *, u_int);
خالی	pkcs11_کلید_free(ساخت sshkey *);

#اگر_تعریف_شدہ WITH_PKCS11_KEYGEN
ساخت sshkey *
	pkcs11_gakp(حرف *, حرف *, غیرعلامتی صحیح, حرف *, غیرعلامتی صحیح,
	    غیرعلامتی صحیح, غیرعلامتی حرف, uint32_t *);
ساخت sshkey *
	pkcs11_destroy_keypair(حرف *, حرف *, غیرعلامتی طویل, غیرعلامتی حرف,
	    uint32_t *);
#اگر_ختم

/* Only available in ssh-pkcs11-client.c */
صحیح pkcs11_make_cert(ثابت ساخت sshkey *,
    ثابت ساخت sshkey *, ساخت sshkey **);
