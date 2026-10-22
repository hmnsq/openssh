/* $OpenBSD: mac.c,v 1.39 2026/05/13 05:58:58 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "hmac.h"
#அந்தர்பாவ "umac.h"
#அந்தர்பாவ "mac.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

கட்டமைப்பு macalg {
	எழுத்து		*name;
	முழு		type;
	முழு		alg;
	முழு		truncatebits;	/* truncate digest if != 0 */
	முழு		சாவி_len;	/* just for UMAC */
	முழு		len;		/* just for UMAC */
	முழு		etm;		/* Encrypt-then-MAC */
};

நிலையான மாறிலி கட்டமைப்பு macalg macs[] = {
	/* Encrypt-and-MAC (encrypt-and-authenticate) variants */
	{ "hmac-sha1",				SSH_DIGEST, SSH_DIGEST_SHA1, 0, 0, 0, 0 },
	{ "hmac-sha1-96",			SSH_DIGEST, SSH_DIGEST_SHA1, 96, 0, 0, 0 },
	{ "hmac-sha2-256",			SSH_DIGEST, SSH_DIGEST_SHA256, 0, 0, 0, 0 },
	{ "hmac-sha2-512",			SSH_DIGEST, SSH_DIGEST_SHA512, 0, 0, 0, 0 },
	{ "hmac-md5",				SSH_DIGEST, SSH_DIGEST_MD5, 0, 0, 0, 0 },
	{ "hmac-md5-96",			SSH_DIGEST, SSH_DIGEST_MD5, 96, 0, 0, 0 },
	{ "umac-64@openssh.com",		SSH_UMAC, 0, 0, 128, 64, 0 },
	{ "umac-128@openssh.com",		SSH_UMAC128, 0, 0, 128, 128, 0 },

	/* Encrypt-then-MAC variants */
	{ "hmac-sha1-etm@openssh.com",		SSH_DIGEST, SSH_DIGEST_SHA1, 0, 0, 0, 1 },
	{ "hmac-sha1-96-etm@openssh.com",	SSH_DIGEST, SSH_DIGEST_SHA1, 96, 0, 0, 1 },
	{ "hmac-sha2-256-etm@openssh.com",	SSH_DIGEST, SSH_DIGEST_SHA256, 0, 0, 0, 1 },
	{ "hmac-sha2-512-etm@openssh.com",	SSH_DIGEST, SSH_DIGEST_SHA512, 0, 0, 0, 1 },
	{ "hmac-md5-etm@openssh.com",		SSH_DIGEST, SSH_DIGEST_MD5, 0, 0, 0, 1 },
	{ "hmac-md5-96-etm@openssh.com",	SSH_DIGEST, SSH_DIGEST_MD5, 96, 0, 0, 1 },
	{ "umac-64-etm@openssh.com",		SSH_UMAC, 0, 0, 128, 64, 1 },
	{ "umac-128-etm@openssh.com",		SSH_UMAC128, 0, 0, 128, 128, 1 },

	{ வெற்று,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
எழுத்து *
mac_alg_list(எழுத்து sep)
{
	எழுத்து *ret = வெற்று;
	மாறிலி கட்டமைப்பு macalg *m;
	எழுத்து sep_str[2] = {sep, '\0'};

	க்கு (m = macs; m->name != வெற்று; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	திரும்பு ret;
}

நிலையான முழு
mac_setup_by_alg(கட்டமைப்பு sshmac *mac, மாறிலி கட்டமைப்பு macalg *macalg)
{
	mac->type = macalg->type;
	எனில் (mac->type == SSH_DIGEST) {
		எனில் ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == வெற்று)
			திரும்பு SSH_ERR_ALLOC_FAIL;
		mac->சாவி_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} இல்லையெனில் {
		mac->mac_len = macalg->len / 8;
		mac->சாவி_len = macalg->சாவி_len / 8;
		mac->umac_ctx = வெற்று;
	}
	எனில் (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	திரும்பு 0;
}

முழு
mac_setup(கட்டமைப்பு sshmac *mac, எழுத்து *name)
{
	மாறிலி கட்டமைப்பு macalg *m;

	க்கு (m = macs; m->name != வெற்று; m++) {
		எனில் (strcmp(name, m->name) != 0)
			தொடர்;
		எனில் (mac != வெற்று)
			திரும்பு mac_setup_by_alg(mac, m);
		திரும்பு 0;
	}
	திரும்பு SSH_ERR_INVALID_ARGUMENT;
}

முழு
mac_init(கட்டமைப்பு sshmac *mac)
{
	எனில் (mac->சாவி == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	தேர்வு (mac->type) {
	நிலை SSH_DIGEST:
		எனில் (mac->hmac_ctx == வெற்று ||
		    ssh_hmac_init(mac->hmac_ctx, mac->சாவி, mac->சாவி_len) < 0)
			திரும்பு SSH_ERR_INVALID_ARGUMENT;
		திரும்பு 0;
	நிலை SSH_UMAC:
		எனில் ((mac->umac_ctx = umac_new(mac->சாவி)) == வெற்று)
			திரும்பு SSH_ERR_ALLOC_FAIL;
		திரும்பு 0;
	நிலை SSH_UMAC128:
		எனில் ((mac->umac_ctx = umac128_new(mac->சாவி)) == வெற்று)
			திரும்பு SSH_ERR_ALLOC_FAIL;
		திரும்பு 0;
	இயல்பு:
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
}

முழு
mac_compute(கட்டமைப்பு sshmac *mac, uint32_t seqno,
    மாறிலி u_char *data, முழு datalen,
    u_char *digest, size_t dlen)
{
	நிலையான ஒன்றிப்பு {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	எனில் (mac->mac_len > அளவு(u))
		திரும்பு SSH_ERR_INTERNAL_ERROR;

	தேர்வு (mac->type) {
	நிலை SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		எனில் (ssh_hmac_init(mac->hmac_ctx, வெற்று, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, அளவு(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, அளவு(u.m)) < 0)
			திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
		நிறுத்து;
	நிலை SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		நிறுத்து;
	நிலை SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		நிறுத்து;
	இயல்பு:
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
	எனில் (digest != வெற்று) {
		எனில் (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	திரும்பு 0;
}

முழு
mac_check(கட்டமைப்பு sshmac *mac, uint32_t seqno,
    மாறிலி u_char *data, size_t dlen,
    மாறிலி u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	முழு r;

	எனில் (mac->mac_len > mlen)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, அளவு(ourmac))) != 0)
		திரும்பு r;
	எனில் (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		திரும்பு SSH_ERR_MAC_INVALID;
	திரும்பு 0;
}

வெறுமை
mac_clear(கட்டமைப்பு sshmac *mac)
{
	எனில் (mac->type == SSH_UMAC) {
		எனில் (mac->umac_ctx != வெற்று)
			umac_delete(mac->umac_ctx);
	} இல்லையெனில் எனில் (mac->type == SSH_UMAC128) {
		எனில் (mac->umac_ctx != வெற்று)
			umac128_delete(mac->umac_ctx);
	} இல்லையெனில் எனில் (mac->hmac_ctx != வெற்று)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = வெற்று;
	mac->umac_ctx = வெற்று;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
முழு
mac_valid(மாறிலி எழுத்து *names)
{
	எழுத்து *maclist, *cp, *p;
	முழு found = 0;

	எனில் (names == வெற்று || strcmp(names, "") == 0)
		திரும்பு 0;
	எனில் ((maclist = cp = strdup(names)) == வெற்று)
		திரும்பு 0;
	க்கு ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		எனில் (mac_setup(வெற்று, p) < 0) {
			விடுவி(maclist);
			திரும்பு 0;
		} இல்லையெனில்
			found = 1;
	}
	விடுவி(maclist);
	திரும்பு found;
}
