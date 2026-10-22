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
#నిర్వచించు	SSH_PKCS11_ERR_GENERIC			1
#నిర్వచించు	SSH_PKCS11_ERR_LOGIN_FAIL		2
#నిర్వచించు	SSH_PKCS11_ERR_NO_SLOTS			3
#నిర్వచించు	SSH_PKCS11_ERR_PIN_REQUIRED		4
#నిర్వచించు	SSH_PKCS11_ERR_PIN_LOCKED		5

నిర్మాణం sshkey;

పూర్ణాంకం	pkcs11_init(పూర్ణాంకం);
శూన్య	pkcs11_terminate(శూన్య);
పూర్ణాంకం	pkcs11_కూడు_provider(అక్షరం *, అక్షరం *, నిర్మాణం sshkey ***, అక్షరం ***);
పూర్ణాంకం	pkcs11_del_provider(అక్షరం *);
పూర్ణాంకం	pkcs11_sign(నిర్మాణం sshkey *, u_char **, కొలత_t *,
	    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
	    స్థిరరాశి అక్షరం *, u_int);
శూన్య	pkcs11_కీలకం_free(నిర్మాణం sshkey *);

#నిర్వచితమైతే WITH_PKCS11_KEYGEN
నిర్మాణం sshkey *
	pkcs11_gakp(అక్షరం *, అక్షరం *, గుర్తులేని పూర్ణాంకం, అక్షరం *, గుర్తులేని పూర్ణాంకం,
	    గుర్తులేని పూర్ణాంకం, గుర్తులేని అక్షరం, uint32_t *);
నిర్మాణం sshkey *
	pkcs11_destroy_keypair(అక్షరం *, అక్షరం *, గుర్తులేని దీర్ఘ, గుర్తులేని అక్షరం,
	    uint32_t *);
#అయితే_ముగింపు

/* Only available in ssh-pkcs11-client.c */
పూర్ణాంకం pkcs11_make_cert(స్థిరరాశి నిర్మాణం sshkey *,
    స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshkey **);
