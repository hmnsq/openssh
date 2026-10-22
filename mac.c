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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "digest.h"
#समावेश "hmac.h"
#समावेश "umac.h"
#समावेश "mac.h"
#समावेश "misc.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"

#समावेश "openbsd-compat/openssl-compat.h"

#घोषणा SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#घोषणा SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#घोषणा SSH_UMAC128	3

काष्ठा macalg {
	अक्षर		*name;
	पूर्णांक		type;
	पूर्णांक		alg;
	पूर्णांक		truncatebits;	/* truncate digest if != 0 */
	पूर्णांक		कुंजी_len;	/* just for UMAC */
	पूर्णांक		len;		/* just for UMAC */
	पूर्णांक		etm;		/* Encrypt-then-MAC */
};

अटल स्थिर काष्ठा macalg macs[] = {
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

	{ शून्य,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
अक्षर *
mac_alg_list(अक्षर sep)
{
	अक्षर *ret = शून्य;
	स्थिर काष्ठा macalg *m;
	अक्षर sep_str[2] = {sep, '\0'};

	क्रम (m = macs; m->name != शून्य; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	वापस ret;
}

अटल पूर्णांक
mac_setup_by_alg(काष्ठा sshmac *mac, स्थिर काष्ठा macalg *macalg)
{
	mac->type = macalg->type;
	अगर (mac->type == SSH_DIGEST) {
		अगर ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		mac->कुंजी_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} अन्यथा {
		mac->mac_len = macalg->len / 8;
		mac->कुंजी_len = macalg->कुंजी_len / 8;
		mac->umac_ctx = शून्य;
	}
	अगर (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	वापस 0;
}

पूर्णांक
mac_setup(काष्ठा sshmac *mac, अक्षर *name)
{
	स्थिर काष्ठा macalg *m;

	क्रम (m = macs; m->name != शून्य; m++) {
		अगर (म_भेद(name, m->name) != 0)
			जारी;
		अगर (mac != शून्य)
			वापस mac_setup_by_alg(mac, m);
		वापस 0;
	}
	वापस SSH_ERR_INVALID_ARGUMENT;
}

पूर्णांक
mac_init(काष्ठा sshmac *mac)
{
	अगर (mac->कुंजी == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	चयन (mac->type) {
	हाल SSH_DIGEST:
		अगर (mac->hmac_ctx == शून्य ||
		    ssh_hmac_init(mac->hmac_ctx, mac->कुंजी, mac->कुंजी_len) < 0)
			वापस SSH_ERR_INVALID_ARGUMENT;
		वापस 0;
	हाल SSH_UMAC:
		अगर ((mac->umac_ctx = umac_new(mac->कुंजी)) == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		वापस 0;
	हाल SSH_UMAC128:
		अगर ((mac->umac_ctx = umac128_new(mac->कुंजी)) == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		वापस 0;
	शेष:
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
}

पूर्णांक
mac_compute(काष्ठा sshmac *mac, uint32_t seqno,
    स्थिर u_char *तथ्य, पूर्णांक datalen,
    u_char *digest, माप_प्रकार dlen)
{
	अटल जोड़ {
		u_char m[SSH_DIGEST_MAX_लंबाई];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	अगर (mac->mac_len > माप(u))
		वापस SSH_ERR_INTERNAL_ERROR;

	चयन (mac->type) {
	हाल SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		अगर (ssh_hmac_init(mac->hmac_ctx, शून्य, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, माप(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, तथ्य, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, माप(u.m)) < 0)
			वापस SSH_ERR_LIBCRYPTO_ERROR;
		अवरोध;
	हाल SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, तथ्य, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		अवरोध;
	हाल SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, तथ्य, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		अवरोध;
	शेष:
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
	अगर (digest != शून्य) {
		अगर (dlen > mac->mac_len)
			dlen = mac->mac_len;
		स_नकल(digest, u.m, dlen);
	}
	वापस 0;
}

पूर्णांक
mac_check(काष्ठा sshmac *mac, uint32_t seqno,
    स्थिर u_char *तथ्य, माप_प्रकार dlen,
    स्थिर u_char *theirmac, माप_प्रकार mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_लंबाई];
	पूर्णांक r;

	अगर (mac->mac_len > mlen)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((r = mac_compute(mac, seqno, तथ्य, dlen,
	    ourmac, माप(ourmac))) != 0)
		वापस r;
	अगर (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		वापस SSH_ERR_MAC_INVALID;
	वापस 0;
}

व्योम
mac_clear(काष्ठा sshmac *mac)
{
	अगर (mac->type == SSH_UMAC) {
		अगर (mac->umac_ctx != शून्य)
			umac_delete(mac->umac_ctx);
	} अन्यथा अगर (mac->type == SSH_UMAC128) {
		अगर (mac->umac_ctx != शून्य)
			umac128_delete(mac->umac_ctx);
	} अन्यथा अगर (mac->hmac_ctx != शून्य)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = शून्य;
	mac->umac_ctx = शून्य;
}

/* XXX copied from ciphers_valid */
#घोषणा	MAC_SEP	","
पूर्णांक
mac_valid(स्थिर अक्षर *names)
{
	अक्षर *maclist, *cp, *p;
	पूर्णांक found = 0;

	अगर (names == शून्य || म_भेद(names, "") == 0)
		वापस 0;
	अगर ((maclist = cp = strdup(names)) == शून्य)
		वापस 0;
	क्रम ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		अगर (mac_setup(शून्य, p) < 0) {
			मुक्त(maclist);
			वापस 0;
		} अन्यथा
			found = 1;
	}
	मुक्त(maclist);
	वापस found;
}
