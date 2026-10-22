/* $OpenBSD: hostfile.c,v 1.100 2025/11/25 00:57:04 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for manipulating the known hosts files.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 1999, 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <resolv.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "hmac.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊರತೆಗೆ_salt(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, u_int l, u_char *salt, ಗಾತ್ರ_t salt_len)
{
	ಅಕ್ಷರ *p, *b64salt;
	u_int b64len;
	ಪೂರ್ಣಾಂಕ ret;

	ಆದರೆ (l < ಗಾತ್ರ(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(s, HASH_MAGIC, ಗಾತ್ರ(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		ಹಿಂತಿರುಗಿ (-1);
	}
	s += ಗಾತ್ರ(HASH_MAGIC) - 1;
	l -= ಗಾತ್ರ(HASH_MAGIC) - 1;
	ಆದರೆ ((p = memchr(s, HASH_DELIM, l)) == ಖಾಲಿ) {
		debug2("extract_salt: missing salt termination character");
		ಹಿಂತಿರುಗಿ (-1);
	}

	b64len = p - s;
	/* Sanity check */
	ಆದರೆ (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		ಹಿಂತಿರುಗಿ (-1);
	}
	b64salt = xmalloc(1 + b64len);
	ಸ್ಮರಣೆ_ನಕಲು(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	ಬಿಡುಗಡೆ(b64salt);
	ಆದರೆ (ret == -1) {
		debug2("extract_salt: salt decode error");
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (ret != (ಪೂರ್ಣಾಂಕ)ssh_hmac_ಬೈಟುಗಳು(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_ಬೈಟುಗಳು(SSH_DIGEST_SHA1), ret);
		ಹಿಂತಿರುಗಿ (-1);
	}

	ಹಿಂತಿರುಗಿ (0);
}

ಅಕ್ಷರ *
host_hash(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name_from_hostfile, u_int src_len)
{
	ರಚನೆ ssh_hmac_ctx *ctx;
	u_char salt[256], ಫಲಿತಾಂಶ[256];
	ಅಕ್ಷರ uu_salt[512], uu_ಫಲಿತಾಂಶ[512];
	ಅಕ್ಷರ *encoded = ಖಾಲಿ;
	u_int len;

	len = ssh_digest_ಬೈಟುಗಳು(SSH_DIGEST_SHA1);

	ಆದರೆ (name_from_hostfile == ಖಾಲಿ) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Extract salt from known host entry */
		ಆದರೆ (ಹೊರತೆಗೆ_salt(name_from_hostfile, src_len, salt,
		    ಗಾತ್ರ(salt)) == -1)
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	ಆದರೆ ((ctx = ssh_hmac_ಆರಂಭ(SSH_DIGEST_SHA1)) == ಖಾಲಿ ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host)) < 0 ||
	    ssh_hmac_final(ctx, ಫಲಿತಾಂಶ, ಗಾತ್ರ(ಫಲಿತಾಂಶ)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	ಆದರೆ (__b64_ntop(salt, len, uu_salt, ಗಾತ್ರ(uu_salt)) == -1 ||
	    __b64_ntop(ಫಲಿತಾಂಶ, len, uu_ಫಲಿತಾಂಶ, ಗಾತ್ರ(uu_ಫಲಿತಾಂಶ)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_ಫಲಿತಾಂಶ);

	ಹಿಂತಿರುಗಿ (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

ಪೂರ್ಣಾಂಕ
hostfile_read_ಕೀಲಿ(ಅಕ್ಷರ **cpp, u_int *bitsp, ರಚನೆ sshkey *ret)
{
	ಅಕ್ಷರ *cp;

	/* Skip leading whitespace. */
	ಗಾಗಿ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	ಆದರೆ (sshkey_read(ret, &cp) != 0)
		ಹಿಂತಿರುಗಿ 0;

	/* Skip trailing whitespace. */
	ಗಾಗಿ (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	ಆದರೆ (bitsp != ಖಾಲಿ)
		*bitsp = sshkey_ಗಾತ್ರ(ret);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ HostkeyMarker
check_markers(ಅಕ್ಷರ **cpp)
{
	ಅಕ್ಷರ marker[32], *sp, *cp = *cpp;
	ಪೂರ್ಣಾಂಕ ret = MRK_NONE;

	ಆಗ (*cp == '@') {
		/* Only one marker is allowed */
		ಆದರೆ (ret != MRK_NONE)
			ಹಿಂತಿರುಗಿ MRK_ERROR;
		/* Markers are terminated by whitespace */
		ಆದರೆ ((sp = strchr(cp, ' ')) == ಖಾಲಿ &&
		    (sp = strchr(cp, '\t')) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ MRK_ERROR;
		/* Extract marker for comparison */
		ಆದರೆ (sp <= cp + 1 || sp >= cp + ಗಾತ್ರ(marker))
			ಹಿಂತಿರುಗಿ MRK_ERROR;
		ಸ್ಮರಣೆ_ನಕಲು(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		ಆದರೆ (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		ಇಲ್ಲದಿದ್ದರೆ
			ಹಿಂತಿರುಗಿ MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		ಗಾಗಿ (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	ಹಿಂತಿರುಗಿ ret;
}

ರಚನೆ hostkeys *
init_hostkeys(ಶೂನ್ಯ)
{
	ರಚನೆ hostkeys *ret = xcalloc(1, ಗಾತ್ರ(*ret));

	ret->entries = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ ret;
}

ರಚನೆ ತುಂಬು_callback_ctx {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host;
	u_long ಅಂಕೆ_loaded;
	ರಚನೆ hostkeys *hostkeys;
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ದಾಖಲೆ_hostkey(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ ತುಂಬು_callback_ctx *ctx = (ರಚನೆ ತುಂಬು_callback_ctx *)_ctx;
	ರಚನೆ hostkeys *hostkeys = ctx->hostkeys;
	ರಚನೆ hostkey_ನಮೂದು *tmp;

	ಆದರೆ (l->ಸ್ಥಿತಿ_2 == HKF_ಸ್ಥಿತಿ_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->ಮಾರ್ಗ, l->linenum);
		ಹಿಂತಿರುಗಿ 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->ಕೀಲಿ), l->ಮಾರ್ಗ, l->linenum);
	ಆದರೆ ((tmp = recallocarray(hostkeys->entries, hostkeys->ಅಂಕೆ_entries,
	    hostkeys->ಅಂಕೆ_entries + 1, ಗಾತ್ರ(*hostkeys->entries))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].file = xstrdup(l->ಮಾರ್ಗ);
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].ಸಾಲು = l->linenum;
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].ಕೀಲಿ = l->ಕೀಲಿ;
	l->ಕೀಲಿ = ಖಾಲಿ; /* steal it */
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].marker = l->marker;
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].note = l->note;
	hostkeys->ಅಂಕೆ_entries++;
	ctx->ಅಂಕೆ_loaded++;

	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
ತುಂಬು_hostkeys_file(ರಚನೆ hostkeys *hostkeys, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, FILE *f, u_int note)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ ತುಂಬು_callback_ctx ctx;

	ctx.host = host;
	ctx.ಅಂಕೆ_loaded = 0;
	ctx.hostkeys = hostkeys;

	ಆದರೆ ((r = hostkeys_foreach_file(ಮಾರ್ಗ, f, ದಾಖಲೆ_hostkey, &ctx, host,
	    ಖಾಲಿ, HKF_WANT_ಹೊಂದಿಕೆ|HKF_WANT_PARSE_ಕೀಲಿ, note)) != 0) {
		ಆದರೆ (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", ಮಾರ್ಗ);
	}
	ಆದರೆ (ctx.ಅಂಕೆ_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.ಅಂಕೆ_loaded, host);
}

ಶೂನ್ಯ
ತುಂಬು_hostkeys(ರಚನೆ hostkeys *hostkeys, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
    u_int note)
{
	FILE *f;

	ಆದರೆ ((f = fopen(ಮಾರ್ಗ, "r")) == ಖಾಲಿ) {
		debug_f("fopen %s: %s", ಮಾರ್ಗ, strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}

	ತುಂಬು_hostkeys_file(hostkeys, host, ಮಾರ್ಗ, f, note);
	fclose(f);
}

ಶೂನ್ಯ
free_hostkeys(ರಚನೆ hostkeys *hostkeys)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		ಬಿಡುಗಡೆ(hostkeys->entries[i].host);
		ಬಿಡುಗಡೆ(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].ಕೀಲಿ);
		explicit_bzero(hostkeys->entries + i, ಗಾತ್ರ(*hostkeys->entries));
	}
	ಬಿಡುಗಡೆ(hostkeys->entries);
	freezero(hostkeys, ಗಾತ್ರ(*hostkeys));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_ಕೀಲಿ_not_revoked(ರಚನೆ hostkeys *hostkeys, ರಚನೆ sshkey *k)
{
	ಪೂರ್ಣಾಂಕ is_cert = sshkey_is_cert(k);
	u_int i;

	ಗಾಗಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		ಆದರೆ (hostkeys->entries[i].marker != MRK_REVOKE)
			ಮುಂದುವರಿ;
		ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(k, hostkeys->entries[i].ಕೀಲಿ))
			ಹಿಂತಿರುಗಿ -1;
		ಆದರೆ (is_cert && k != ಖಾಲಿ &&
		    sshkey_equal_ಬಹಿರಂಗ(k->cert->signature_ಕೀಲಿ,
		    hostkeys->entries[i].ಕೀಲಿ))
			ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Match keys against a specified key, or look one up by key type.
 *
 * If looking for a keytype (key == NULL) and one is found then return
 * HOST_FOUND, otherwise HOST_NEW.
 *
 * If looking for a key (key != NULL):
 *  1. If the key is a cert and a matching CA is found, return HOST_OK
 *  2. If the key is not a cert and a matching key is found, return HOST_OK
 *  3. If no key matches but a key with a different type is found, then
 *     return HOST_CHANGED
 *  4. If no matching keys are found, then return HOST_NEW.
 *
 * Finally, check any found key is not revoked.
 */
ಸ್ಥಿರ Host_ಸ್ಥಿತಿ
check_hostkeys_by_ಕೀಲಿ_or_type(ರಚನೆ hostkeys *hostkeys,
    ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ keytype, ಪೂರ್ಣಾಂಕ nid, ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು **ಸಿಕ್ಕಿತು)
{
	u_int i;
	Host_ಸ್ಥಿತಿ ಕೊನೆ_return = HOST_NEW;
	ಪೂರ್ಣಾಂಕ want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	ಆದರೆ (ಸಿಕ್ಕಿತು != ಖಾಲಿ)
		*ಸಿಕ್ಕಿತು = ಖಾಲಿ;

	ಗಾಗಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		ಆದರೆ (hostkeys->entries[i].marker != want_marker)
			ಮುಂದುವರಿ;
		ಆದರೆ (k == ಖಾಲಿ) {
			ಆದರೆ (hostkeys->entries[i].ಕೀಲಿ->type != keytype)
				ಮುಂದುವರಿ;
			ಆದರೆ (nid != -1 &&
			    sshkey_type_plain(keytype) == ಕೀಲಿ_ECDSA &&
			    hostkeys->entries[i].ಕೀಲಿ->ecdsa_nid != nid)
				ಮುಂದುವರಿ;
			ಕೊನೆ_return = HOST_ಸಿಕ್ಕಿತು;
			ಆದರೆ (ಸಿಕ್ಕಿತು != ಖಾಲಿ)
				*ಸಿಕ್ಕಿತು = hostkeys->entries + i;
			k = hostkeys->entries[i].ಕೀಲಿ;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (want_cert) {
			ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(k->cert->signature_ಕೀಲಿ,
			    hostkeys->entries[i].ಕೀಲಿ)) {
				/* A matching CA exists */
				ಕೊನೆ_return = HOST_OK;
				ಆದರೆ (ಸಿಕ್ಕಿತು != ಖಾಲಿ)
					*ಸಿಕ್ಕಿತು = hostkeys->entries + i;
				ನಿಲ್ಲಿಸು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (sshkey_equal(k, hostkeys->entries[i].ಕೀಲಿ)) {
				ಕೊನೆ_return = HOST_OK;
				ಆದರೆ (ಸಿಕ್ಕಿತು != ಖಾಲಿ)
					*ಸಿಕ್ಕಿತು = hostkeys->entries + i;
				ನಿಲ್ಲಿಸು;
			}
			/* A non-matching key exists */
			ಕೊನೆ_return = HOST_ಬದಲಾಯಿತು;
			ಆದರೆ (ಸಿಕ್ಕಿತು != ಖಾಲಿ)
				*ಸಿಕ್ಕಿತು = hostkeys->entries + i;
		}
	}
	ಆದರೆ (check_ಕೀಲಿ_not_revoked(hostkeys, k) != 0) {
		ಕೊನೆ_return = HOST_REVOKED;
		ಆದರೆ (ಸಿಕ್ಕಿತು != ಖಾಲಿ)
			*ಸಿಕ್ಕಿತು = ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ಕೊನೆ_return;
}

Host_ಸ್ಥಿತಿ
check_ಕೀಲಿ_ಒಳ_hostkeys(ರಚನೆ hostkeys *hostkeys, ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು **ಸಿಕ್ಕಿತು)
{
	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
		fatal("no key to look up");
	ಹಿಂತಿರುಗಿ check_hostkeys_by_ಕೀಲಿ_or_type(hostkeys, ಕೀಲಿ, 0, -1, ಸಿಕ್ಕಿತು);
}

ಪೂರ್ಣಾಂಕ
lookup_ಕೀಲಿ_ಒಳ_hostkeys_by_type(ರಚನೆ hostkeys *hostkeys, ಪೂರ್ಣಾಂಕ keytype, ಪೂರ್ಣಾಂಕ nid,
    ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು **ಸಿಕ್ಕಿತು)
{
	ಹಿಂತಿರುಗಿ (check_hostkeys_by_ಕೀಲಿ_or_type(hostkeys, ಖಾಲಿ, keytype, nid,
	    ಸಿಕ್ಕಿತು) == HOST_ಸಿಕ್ಕಿತು);
}

ಪೂರ್ಣಾಂಕ
lookup_marker_ಒಳ_hostkeys(ರಚನೆ hostkeys *hostkeys, ಪೂರ್ಣಾಂಕ want_marker)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		ಆದರೆ (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
format_host_ನಮೂದು(ರಚನೆ sshbuf *ನಮೂದು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ store_hash)
{
	ಪೂರ್ಣಾಂಕ r, success = 0;
	ಅಕ್ಷರ *hashed_host = ಖಾಲಿ, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	ಆದರೆ (store_hash) {
		ಆದರೆ ((hashed_host = host_hash(lhost, ಖಾಲಿ, 0)) == ಖಾಲಿ) {
			error_f("host_hash failed");
			ಬಿಡುಗಡೆ(lhost);
			ಹಿಂತಿರುಗಿ 0;
		}
		ಆದರೆ ((r = sshbuf_putf(ನಮೂದು, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ip != ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_putf(ನಮೂದು, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = sshbuf_putf(ನಮೂದು, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	ಬಿಡುಗಡೆ(hashed_host);
	ಬಿಡುಗಡೆ(lhost);
	ಆದರೆ ((r = sshkey_format_ಪಠ್ಯ(ಕೀಲಿ, ನಮೂದು)) == 0)
		success = 1;
	ಇಲ್ಲದಿದ್ದರೆ
		error_fr(r, "sshkey_write");
	ಆದರೆ ((r = sshbuf_putf(ನಮೂದು, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	ಆದರೆ (success && store_hash && ip != ಖಾಲಿ)
		success = format_host_ನಮೂದು(ನಮೂದು, ip, ಖಾಲಿ, ಕೀಲಿ, 1);
	ಹಿಂತಿರುಗಿ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
write_host_ನಮೂದು(FILE *f, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ store_hash)
{
	ಪೂರ್ಣಾಂಕ r, success = 0;
	ರಚನೆ sshbuf *ನಮೂದು = ಖಾಲಿ;

	ಆದರೆ ((ನಮೂದು = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("allocation failed");
	ಆದರೆ ((r = format_host_ನಮೂದು(ನಮೂದು, host, ip, ಕೀಲಿ, store_hash)) != 1) {
		debug_f("failed to format host entry");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fwrite(sshbuf_ptr(ನಮೂದು), sshbuf_len(ನಮೂದು), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	success = 1;
 ಹೊರಹೋಗು:
	sshbuf_free(ನಮೂದು);
	ಹಿಂತಿರುಗಿ success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
ಶೂನ್ಯ
hostfile_create_user_ssh_dir(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ notify)
{
	ಅಕ್ಷರ *dotsshdir = ಖಾಲಿ, *p;
	ಗಾತ್ರ_t len;
	ರಚನೆ stat st;

	ಆದರೆ ((p = strrchr(filename, '/')) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" ಮಾರ್ಗ_SSH_USER_DIR, getuid());
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(dotsshdir) > len || ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(filename, dotsshdir, len) != 0)
		ಹೋಗು ಹೊರಹೋಗು; /* not ~/.ssh prefixed */
	ಆದರೆ (stat(dotsshdir, &st) == 0)
		ಹೋಗು ಹೊರಹೋಗು; /* dir already exists */
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	ಇಲ್ಲದಿದ್ದರೆ {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (notify)
			logit("Created directory '%s'.", dotsshdir);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
		ssh_selinux_setfscreatecon(ಖಾಲಿ);
#ಆದರೆ_ಅಂತ್ಯ
	}
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
ಪೂರ್ಣಾಂಕ
ಕೂಡಿಸು_host_ಗಮ್ಯ_hostfile(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ store_hash)
{
	FILE *f;
	ಪೂರ್ಣಾಂಕ success, addnl = 0;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	ಆದರೆ ((f = fopen(filename, "a+")) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	setvbuf(f, ಖಾಲಿ, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	ಆದರೆ (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	ಆದರೆ (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		ಹಿಂತಿರುಗಿ 0;
	}
	success = write_host_ನಮೂದು(f, host, ಖಾಲಿ, ಕೀಲಿ, store_hash);
	fclose(f);
	ಹಿಂತಿರುಗಿ success;
}

ರಚನೆ host_delete_ctx {
	FILE *ಹೊರಹೋಗು;
	ಪೂರ್ಣಾಂಕ quiet;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, *ip;
	u_int *ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು;	/* mask of HKF_MATCH_* for this key */
	ರಚನೆ sshkey * ಸ್ಥಿರಾಂಕ *ಕೀಲಿಗಳು;
	ಗಾತ್ರ_t nkeys;
	ಪೂರ್ಣಾಂಕ modified;
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
host_delete(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ host_delete_ctx *ctx = (ರಚನೆ host_delete_ctx *)_ctx;
	ಪೂರ್ಣಾಂಕ loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ಗಾತ್ರ_t i;

	/* Don't remove CA and revocation lines */
	ಆದರೆ (l->ಸ್ಥಿತಿ_2 == HKF_ಸ್ಥಿತಿ_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		ಗಾಗಿ (i = 0; i < ctx->nkeys; i++) {
			ಆದರೆ (!sshkey_equal(ctx->ಕೀಲಿಗಳು[i], l->ಕೀಲಿ))
				ಮುಂದುವರಿ;
			ctx->ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು[i] |= l->ಹೊಂದಿಕೆ;
			fprintf(ctx->ಹೊರಹೋಗು, "%s\n", l->ಸಾಲು);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->ಕೀಲಿ), l->ಮಾರ್ಗ, l->linenum);
			ಹಿಂತಿರುಗಿ 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->ಮಾರ್ಗ, l->linenum, sshkey_type(l->ಕೀಲಿ), ctx->host);
		ctx->modified = 1;
		ಹಿಂತಿರುಗಿ 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	ಆದರೆ (l->ಸ್ಥಿತಿ_2 == HKF_ಸ್ಥಿತಿ_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->ಮಾರ್ಗ, l->linenum);
	}
	fprintf(ctx->ಹೊರಹೋಗು, "%s\n", l->ಸಾಲು);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
hostfile_replace_entries(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip,
    ರಚನೆ sshkey **ಕೀಲಿಗಳು, ಗಾತ್ರ_t nkeys, ಪೂರ್ಣಾಂಕ store_hash, ಪೂರ್ಣಾಂಕ quiet, ಪೂರ್ಣಾಂಕ hash_alg)
{
	ಪೂರ್ಣಾಂಕ r, fd, oerrno = 0;
	ಪೂರ್ಣಾಂಕ loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ರಚನೆ host_delete_ctx ctx;
	ಅಕ್ಷರ *fp = ಖಾಲಿ, *ತಾತ್ಕಾಲಿಕ = ಖಾಲಿ, *ಹಿಂಭಾಗ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what;
	ಬಹುಲಕ_t omask;
	ಗಾತ್ರ_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	ಆದರೆ ((ctx.ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(nkeys, ಗಾತ್ರ(*ctx.ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ctx.ಕೀಲಿಗಳು = ಕೀಲಿಗಳು;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	ಆದರೆ ((r = asprintf(&ತಾತ್ಕಾಲಿಕ, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&ಹಿಂಭಾಗ, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು fail;
	}

	ಆದರೆ ((fd = mkstemp(ತಾತ್ಕಾಲಿಕ)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		ಹೋಗು fail;
	}
	ಆದರೆ ((ctx.ಹೊರಹೋಗು = fdopen(fd, "w")) == ಖಾಲಿ) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		ಹೋಗು fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	ಆದರೆ ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_ಕೀಲಿ, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		ಹೋಗು fail;
	}

	/* Re-add the requested keys */
	want = HKF_ಹೊಂದಿಕೆ_HOST | (ip == ಖಾಲಿ ? 0 : HKF_ಹೊಂದಿಕೆ_IP);
	ಗಾಗಿ (i = 0; i < nkeys; i++) {
		ಆದರೆ (ಕೀಲಿಗಳು[i] == ಖಾಲಿ || (want & ctx.ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು[i]) == want)
			ಮುಂದುವರಿ;
		ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿಗಳು[i], hash_alg,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು fail;
		}
		/* write host/ip */
		what = "";
		ಆದರೆ (ctx.ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು[i] == 0) {
			what = "Adding new key";
			ಆದರೆ (!write_host_ನಮೂದು(ctx.ಹೊರಹೋಗು, host, ip,
			    ಕೀಲಿಗಳು[i], store_hash)) {
				r = SSH_ERR_ಆಂತರಿಕ_ERROR;
				ಹೋಗು fail;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((want & ~ctx.ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು[i]) == HKF_ಹೊಂದಿಕೆ_HOST) {
			what = "Fixing match (hostname)";
			ಆದರೆ (!write_host_ನಮೂದು(ctx.ಹೊರಹೋಗು, host, ಖಾಲಿ,
			    ಕೀಲಿಗಳು[i], store_hash)) {
				r = SSH_ERR_ಆಂತರಿಕ_ERROR;
				ಹೋಗು fail;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((want & ~ctx.ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು[i]) == HKF_ಹೊಂದಿಕೆ_IP) {
			what = "Fixing match (address)";
			ಆದರೆ (!write_host_ನಮೂದು(ctx.ಹೊರಹೋಗು, ip, ಖಾಲಿ,
			    ಕೀಲಿಗಳು[i], store_hash)) {
				r = SSH_ERR_ಆಂತರಿಕ_ERROR;
				ಹೋಗು fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == ಖಾಲಿ ? "" : ",", ip == ಖಾಲಿ ? "" : ip, filename,
		    sshkey_ssh_name(ಕೀಲಿಗಳು[i]), fp);
		ಬಿಡುಗಡೆ(fp);
		fp = ಖಾಲಿ;
		ctx.modified = 1;
	}
	fclose(ctx.ಹೊರಹೋಗು);
	ctx.ಹೊರಹೋಗು = ಖಾಲಿ;

	ಆದರೆ (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		ಆದರೆ (unlink(ಹಿಂಭಾಗ) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", ಹಿಂಭಾಗ, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ಹೋಗು fail;
		}
		ಆದರೆ (link(filename, ಹಿಂಭಾಗ) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    ಹಿಂಭಾಗ, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ಹೋಗು fail;
		}
		ಆದರೆ (rename(ತಾತ್ಕಾಲಿಕ, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", ತಾತ್ಕಾಲಿಕ,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ಹೋಗು fail;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* No changes made; just delete the temporary file */
		ಆದರೆ (unlink(ತಾತ್ಕಾಲಿಕ) != 0)
			error_f("unlink \"%s\": %s", ತಾತ್ಕಾಲಿಕ, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	ಆದರೆ (ತಾತ್ಕಾಲಿಕ != ಖಾಲಿ && r != 0)
		unlink(ತಾತ್ಕಾಲಿಕ);
	ಬಿಡುಗಡೆ(ತಾತ್ಕಾಲಿಕ);
	ಬಿಡುಗಡೆ(ಹಿಂಭಾಗ);
	ಬಿಡುಗಡೆ(fp);
	ಆದರೆ (ctx.ಹೊರಹೋಗು != ಖಾಲಿ)
		fclose(ctx.ಹೊರಹೋಗು);
	ಬಿಡುಗಡೆ(ctx.ಹೊಂದಿಕೆ_ಕೀಲಿಗಳು);
	umask(omask);
	ಆದರೆ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_maybe_hashed(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಹೆಸರುಗಳು, ಪೂರ್ಣಾಂಕ *was_hashed)
{
	ಪೂರ್ಣಾಂಕ hashed = *ಹೆಸರುಗಳು == HASH_DELIM, ret;
	ಅಕ್ಷರ *hashed_host = ಖಾಲಿ;
	ಗಾತ್ರ_t nlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಹೆಸರುಗಳು);

	ಆದರೆ (was_hashed != ಖಾಲಿ)
		*was_hashed = hashed;
	ಆದರೆ (hashed) {
		ಆದರೆ ((hashed_host = host_hash(host, ಹೆಸರುಗಳು, nlen)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ -1;
		ret = (nlen == ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(hashed_host) &&
		    ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(hashed_host, ಹೆಸರುಗಳು, nlen) == 0);
		ಬಿಡುಗಡೆ(hashed_host);
		ಹಿಂತಿರುಗಿ ret;
	}
	ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_hostname(host, ಹೆಸರುಗಳು) == 1;
}

ಪೂರ್ಣಾಂಕ
hostkeys_foreach_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, FILE *f, hostkeys_foreach_fn *callback,
    ಶೂನ್ಯ *ctx, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip, u_int options, u_int note)
{
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ, ktype[128];
	u_long linenum = 0;
	ಅಕ್ಷರ *cp, *cp2;
	u_int kbits;
	ಪೂರ್ಣಾಂಕ hashed;
	ಪೂರ್ಣಾಂಕ s, r = 0;
	ರಚನೆ hostkey_foreach_ಸಾಲು lineinfo;
	ಗಾತ್ರ_t linesize = 0, l;

	memset(&lineinfo, 0, ಗಾತ್ರ(lineinfo));
	ಆದರೆ (host == ಖಾಲಿ && (options & HKF_WANT_ಹೊಂದಿಕೆ) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		ಸಾಲು[strcspn(ಸಾಲು, "\n")] = '\0';

		ಬಿಡುಗಡೆ(lineinfo.ಸಾಲು);
		sshkey_free(lineinfo.ಕೀಲಿ);
		memset(&lineinfo, 0, ಗಾತ್ರ(lineinfo));
		lineinfo.ಮಾರ್ಗ = ಮಾರ್ಗ;
		lineinfo.linenum = linenum;
		lineinfo.ಸಾಲು = xstrdup(ಸಾಲು);
		lineinfo.marker = MRK_NONE;
		lineinfo.ಸ್ಥಿತಿ_2 = HKF_ಸ್ಥಿತಿ_OK;
		lineinfo.keytype = ಕೀಲಿ_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		ಗಾಗಿ (cp = ಸಾಲು; *cp == ' ' || *cp == '\t'; cp++)
			;
		ಆದರೆ (!*cp || *cp == '#' || *cp == '\n') {
			ಆದರೆ ((options & HKF_WANT_ಹೊಂದಿಕೆ) == 0) {
				lineinfo.ಸ್ಥಿತಿ_2 = HKF_ಸ್ಥಿತಿ_COMMENT;
				ಆದರೆ ((r = callback(&lineinfo, ctx)) != 0)
					ನಿಲ್ಲಿಸು;
			}
			ಮುಂದುವರಿ;
		}

		ಆದರೆ ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", ಮಾರ್ಗ, linenum);
			ಆದರೆ ((options & HKF_WANT_ಹೊಂದಿಕೆ) == 0)
				ಹೋಗು bad;
			ಮುಂದುವರಿ;
		}

		/* Find the end of the host name portion. */
		ಗಾಗಿ (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		ಆದರೆ (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", ಮಾರ್ಗ, linenum);
			ಆದರೆ ((options & HKF_WANT_ಹೊಂದಿಕೆ) == 0)
				ಹೋಗು bad;
			ಮುಂದುವರಿ;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		ಆದರೆ (host != ಖಾಲಿ) {
			ಆದರೆ ((s = ಹೊಂದಿಕೆ_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    ಮಾರ್ಗ, linenum, lineinfo.hosts);
				ಹೋಗು bad;
			}
			ಆದರೆ (s == 1) {
				lineinfo.ಸ್ಥಿತಿ_2 = HKF_ಸ್ಥಿತಿ_MATCHED;
				lineinfo.ಹೊಂದಿಕೆ |= HKF_ಹೊಂದಿಕೆ_HOST |
				    (hashed ? HKF_ಹೊಂದಿಕೆ_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			ಆದರೆ (ip != ಖಾಲಿ) {
				ಆದರೆ ((s = ಹೊಂದಿಕೆ_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", ಮಾರ್ಗ, linenum,
					    lineinfo.hosts);
					ಹೋಗು bad;
				}
				ಆದರೆ (s == 1) {
					lineinfo.ಸ್ಥಿತಿ_2 = HKF_ಸ್ಥಿತಿ_MATCHED;
					lineinfo.ಹೊಂದಿಕೆ |= HKF_ಹೊಂದಿಕೆ_IP |
					    (hashed ? HKF_ಹೊಂದಿಕೆ_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			ಆದರೆ ((options & HKF_WANT_ಹೊಂದಿಕೆ) != 0 &&
			    lineinfo.ಸ್ಥಿತಿ_2 != HKF_ಸ್ಥಿತಿ_MATCHED)
				ಮುಂದುವರಿ;
		}

		/* Got a match.  Skip host name and any following whitespace */
		ಗಾಗಿ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		ಆದರೆ (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    ಮಾರ್ಗ, linenum);
			ಹೋಗು bad;
		}
		lineinfo.rawkey = cp = cp2;

		ಆದರೆ ((options & HKF_WANT_PARSE_ಕೀಲಿ) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			ಆದರೆ ((lineinfo.ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (!hostfile_read_ಕೀಲಿ(&cp, &kbits, lineinfo.ಕೀಲಿ)) {
				ಹೋಗು bad;
			}
			lineinfo.keytype = lineinfo.ಕೀಲಿ->type;
			lineinfo.comment = cp;
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			ಆದರೆ (l <= 1 || l >= ಗಾತ್ರ(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				ಹೋಗು bad;
			ಸ್ಮರಣೆ_ನಕಲು(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			ಆದರೆ (lineinfo.keytype == ಕೀಲಿ_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				ಹೋಗು bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			ಗಾಗಿ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			ಆದರೆ (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    ಮಾರ್ಗ, linenum);
				lineinfo.keytype = ಕೀಲಿ_UNSPEC;
			}
			ಆದರೆ (lineinfo.keytype == ಕೀಲಿ_UNSPEC) {
 bad:
				sshkey_free(lineinfo.ಕೀಲಿ);
				lineinfo.ಕೀಲಿ = ಖಾಲಿ;
				lineinfo.ಸ್ಥಿತಿ_2 = HKF_ಸ್ಥಿತಿ_INVALID;
				ಆದರೆ ((r = callback(&lineinfo, ctx)) != 0)
					ನಿಲ್ಲಿಸು;
				ಮುಂದುವರಿ;
			}
		}
		ಆದರೆ ((r = callback(&lineinfo, ctx)) != 0)
			ನಿಲ್ಲಿಸು;
	}
	sshkey_free(lineinfo.ಕೀಲಿ);
	ಬಿಡುಗಡೆ(lineinfo.ಸಾಲು);
	ಬಿಡುಗಡೆ(ಸಾಲು);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
hostkeys_foreach(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, hostkeys_foreach_fn *callback, ಶೂನ್ಯ *ctx,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ip, u_int options, u_int note)
{
	FILE *f;
	ಪೂರ್ಣಾಂಕ r, oerrno;

	ಆದರೆ ((f = fopen(ಮಾರ್ಗ, "r")) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", ಮಾರ್ಗ);
	r = hostkeys_foreach_file(ಮಾರ್ಗ, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}
