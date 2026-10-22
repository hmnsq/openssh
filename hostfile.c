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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <resolv.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hmac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

ਸਥਿਰ ਪੂਰਨ
ਕੱਢੋ_salt(ਅਚਲ ਅੱਖਰ *s, u_int l, u_char *salt, ਮਾਪ_t salt_len)
{
	ਅੱਖਰ *p, *b64salt;
	u_int b64len;
	ਪੂਰਨ ret;

	ਜੇ (l < ਆਕਾਰ(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		ਵਾਪਸ (-1);
	}
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(s, HASH_MAGIC, ਆਕਾਰ(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		ਵਾਪਸ (-1);
	}
	s += ਆਕਾਰ(HASH_MAGIC) - 1;
	l -= ਆਕਾਰ(HASH_MAGIC) - 1;
	ਜੇ ((p = memchr(s, HASH_DELIM, l)) == ਨਿਰਾ) {
		debug2("extract_salt: missing salt termination character");
		ਵਾਪਸ (-1);
	}

	b64len = p - s;
	/* Sanity check */
	ਜੇ (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		ਵਾਪਸ (-1);
	}
	b64salt = xmalloc(1 + b64len);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	ਮੁਕਤ(b64salt);
	ਜੇ (ret == -1) {
		debug2("extract_salt: salt decode error");
		ਵਾਪਸ (-1);
	}
	ਜੇ (ret != (ਪੂਰਨ)ssh_hmac_ਬਾਈਟਾਂ(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_ਬਾਈਟਾਂ(SSH_DIGEST_SHA1), ret);
		ਵਾਪਸ (-1);
	}

	ਵਾਪਸ (0);
}

ਅੱਖਰ *
host_hash(ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *name_from_hostfile, u_int src_len)
{
	ਬਣਤਰ ssh_hmac_ctx *ctx;
	u_char salt[256], ਨਤੀਜਾ[256];
	ਅੱਖਰ uu_salt[512], uu_ਨਤੀਜਾ[512];
	ਅੱਖਰ *encoded = ਨਿਰਾ;
	u_int len;

	len = ssh_digest_ਬਾਈਟਾਂ(SSH_DIGEST_SHA1);

	ਜੇ (name_from_hostfile == ਨਿਰਾ) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} ਨਹੀਂਤਾਂ {
		/* Extract salt from known host entry */
		ਜੇ (ਕੱਢੋ_salt(name_from_hostfile, src_len, salt,
		    ਆਕਾਰ(salt)) == -1)
			ਵਾਪਸ (ਨਿਰਾ);
	}

	ਜੇ ((ctx = ssh_hmac_ਸ਼ੁਰੂ(SSH_DIGEST_SHA1)) == ਨਿਰਾ ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, ਲੜੀ_ਲੰਬਾਈ(host)) < 0 ||
	    ssh_hmac_final(ctx, ਨਤੀਜਾ, ਆਕਾਰ(ਨਤੀਜਾ)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	ਜੇ (__b64_ntop(salt, len, uu_salt, ਆਕਾਰ(uu_salt)) == -1 ||
	    __b64_ntop(ਨਤੀਜਾ, len, uu_ਨਤੀਜਾ, ਆਕਾਰ(uu_ਨਤੀਜਾ)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_ਨਤੀਜਾ);

	ਵਾਪਸ (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

ਪੂਰਨ
hostfile_read_ਕੁੰਜੀ(ਅੱਖਰ **cpp, u_int *bitsp, ਬਣਤਰ sshkey *ret)
{
	ਅੱਖਰ *cp;

	/* Skip leading whitespace. */
	ਲਈ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	ਜੇ (sshkey_read(ret, &cp) != 0)
		ਵਾਪਸ 0;

	/* Skip trailing whitespace. */
	ਲਈ (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	ਜੇ (bitsp != ਨਿਰਾ)
		*bitsp = sshkey_ਮਾਪ(ret);
	ਵਾਪਸ 1;
}

ਸਥਿਰ HostkeyMarker
check_markers(ਅੱਖਰ **cpp)
{
	ਅੱਖਰ marker[32], *sp, *cp = *cpp;
	ਪੂਰਨ ret = MRK_NONE;

	ਜਦੋਂ (*cp == '@') {
		/* Only one marker is allowed */
		ਜੇ (ret != MRK_NONE)
			ਵਾਪਸ MRK_ERROR;
		/* Markers are terminated by whitespace */
		ਜੇ ((sp = strchr(cp, ' ')) == ਨਿਰਾ &&
		    (sp = strchr(cp, '\t')) == ਨਿਰਾ)
			ਵਾਪਸ MRK_ERROR;
		/* Extract marker for comparison */
		ਜੇ (sp <= cp + 1 || sp >= cp + ਆਕਾਰ(marker))
			ਵਾਪਸ MRK_ERROR;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		ਜੇ (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		ਨਹੀਂਤਾਂ ਜੇ (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		ਨਹੀਂਤਾਂ
			ਵਾਪਸ MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		ਲਈ (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	ਵਾਪਸ ret;
}

ਬਣਤਰ hostkeys *
init_hostkeys(ਖਾਲੀ)
{
	ਬਣਤਰ hostkeys *ret = xcalloc(1, ਆਕਾਰ(*ret));

	ret->entries = ਨਿਰਾ;
	ਵਾਪਸ ret;
}

ਬਣਤਰ ਲੱਦੋ_callback_ctx {
	ਅਚਲ ਅੱਖਰ *host;
	u_long ਅੰਕ_loaded;
	ਬਣਤਰ hostkeys *hostkeys;
};

ਸਥਿਰ ਪੂਰਨ
ਰਿਕਾਰਡ_hostkey(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ ਲੱਦੋ_callback_ctx *ctx = (ਬਣਤਰ ਲੱਦੋ_callback_ctx *)_ctx;
	ਬਣਤਰ hostkeys *hostkeys = ctx->hostkeys;
	ਬਣਤਰ hostkey_ਇੰਦਰਾਜ *tmp;

	ਜੇ (l->ਸਥਿਤੀ == HKF_ਸਥਿਤੀ_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->ਰਸਤਾ, l->linenum);
		ਵਾਪਸ 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->ਕੁੰਜੀ), l->ਰਸਤਾ, l->linenum);
	ਜੇ ((tmp = recallocarray(hostkeys->entries, hostkeys->ਅੰਕ_entries,
	    hostkeys->ਅੰਕ_entries + 1, ਆਕਾਰ(*hostkeys->entries))) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->ਅੰਕ_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->ਅੰਕ_entries].file = xstrdup(l->ਰਸਤਾ);
	hostkeys->entries[hostkeys->ਅੰਕ_entries].ਸਤਰ = l->linenum;
	hostkeys->entries[hostkeys->ਅੰਕ_entries].ਕੁੰਜੀ = l->ਕੁੰਜੀ;
	l->ਕੁੰਜੀ = ਨਿਰਾ; /* steal it */
	hostkeys->entries[hostkeys->ਅੰਕ_entries].marker = l->marker;
	hostkeys->entries[hostkeys->ਅੰਕ_entries].note = l->note;
	hostkeys->ਅੰਕ_entries++;
	ctx->ਅੰਕ_loaded++;

	ਵਾਪਸ 0;
}

ਖਾਲੀ
ਲੱਦੋ_hostkeys_file(ਬਣਤਰ hostkeys *hostkeys, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, FILE *f, u_int note)
{
	ਪੂਰਨ r;
	ਬਣਤਰ ਲੱਦੋ_callback_ctx ctx;

	ctx.host = host;
	ctx.ਅੰਕ_loaded = 0;
	ctx.hostkeys = hostkeys;

	ਜੇ ((r = hostkeys_foreach_file(ਰਸਤਾ, f, ਰਿਕਾਰਡ_hostkey, &ctx, host,
	    ਨਿਰਾ, HKF_WANT_ਮੇਲ|HKF_WANT_PARSE_ਕੁੰਜੀ, note)) != 0) {
		ਜੇ (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", ਰਸਤਾ);
	}
	ਜੇ (ctx.ਅੰਕ_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.ਅੰਕ_loaded, host);
}

ਖਾਲੀ
ਲੱਦੋ_hostkeys(ਬਣਤਰ hostkeys *hostkeys, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
    u_int note)
{
	FILE *f;

	ਜੇ ((f = fopen(ਰਸਤਾ, "r")) == ਨਿਰਾ) {
		debug_f("fopen %s: %s", ਰਸਤਾ, strerror(errno));
		ਵਾਪਸ;
	}

	ਲੱਦੋ_hostkeys_file(hostkeys, host, ਰਸਤਾ, f, note);
	fclose(f);
}

ਖਾਲੀ
free_hostkeys(ਬਣਤਰ hostkeys *hostkeys)
{
	u_int i;

	ਲਈ (i = 0; i < hostkeys->ਅੰਕ_entries; i++) {
		ਮੁਕਤ(hostkeys->entries[i].host);
		ਮੁਕਤ(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].ਕੁੰਜੀ);
		explicit_bzero(hostkeys->entries + i, ਆਕਾਰ(*hostkeys->entries));
	}
	ਮੁਕਤ(hostkeys->entries);
	freezero(hostkeys, ਆਕਾਰ(*hostkeys));
}

ਸਥਿਰ ਪੂਰਨ
check_ਕੁੰਜੀ_not_revoked(ਬਣਤਰ hostkeys *hostkeys, ਬਣਤਰ sshkey *k)
{
	ਪੂਰਨ is_cert = sshkey_is_cert(k);
	u_int i;

	ਲਈ (i = 0; i < hostkeys->ਅੰਕ_entries; i++) {
		ਜੇ (hostkeys->entries[i].marker != MRK_REVOKE)
			ਜਾਰੀ;
		ਜੇ (sshkey_equal_ਜਨਤਕ(k, hostkeys->entries[i].ਕੁੰਜੀ))
			ਵਾਪਸ -1;
		ਜੇ (is_cert && k != ਨਿਰਾ &&
		    sshkey_equal_ਜਨਤਕ(k->cert->signature_ਕੁੰਜੀ,
		    hostkeys->entries[i].ਕੁੰਜੀ))
			ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
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
ਸਥਿਰ Host_ਸਥਿਤੀ
check_hostkeys_by_ਕੁੰਜੀ_or_type(ਬਣਤਰ hostkeys *hostkeys,
    ਬਣਤਰ sshkey *k, ਪੂਰਨ keytype, ਪੂਰਨ nid, ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ **ਮਿਲਿਆ)
{
	u_int i;
	Host_ਸਥਿਤੀ ਸਿਰਾ_return = HOST_NEW;
	ਪੂਰਨ want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	ਜੇ (ਮਿਲਿਆ != ਨਿਰਾ)
		*ਮਿਲਿਆ = ਨਿਰਾ;

	ਲਈ (i = 0; i < hostkeys->ਅੰਕ_entries; i++) {
		ਜੇ (hostkeys->entries[i].marker != want_marker)
			ਜਾਰੀ;
		ਜੇ (k == ਨਿਰਾ) {
			ਜੇ (hostkeys->entries[i].ਕੁੰਜੀ->type != keytype)
				ਜਾਰੀ;
			ਜੇ (nid != -1 &&
			    sshkey_type_plain(keytype) == ਕੁੰਜੀ_ECDSA &&
			    hostkeys->entries[i].ਕੁੰਜੀ->ecdsa_nid != nid)
				ਜਾਰੀ;
			ਸਿਰਾ_return = HOST_ਮਿਲਿਆ;
			ਜੇ (ਮਿਲਿਆ != ਨਿਰਾ)
				*ਮਿਲਿਆ = hostkeys->entries + i;
			k = hostkeys->entries[i].ਕੁੰਜੀ;
			ਰੋਕੋ;
		}
		ਜੇ (want_cert) {
			ਜੇ (sshkey_equal_ਜਨਤਕ(k->cert->signature_ਕੁੰਜੀ,
			    hostkeys->entries[i].ਕੁੰਜੀ)) {
				/* A matching CA exists */
				ਸਿਰਾ_return = HOST_OK;
				ਜੇ (ਮਿਲਿਆ != ਨਿਰਾ)
					*ਮਿਲਿਆ = hostkeys->entries + i;
				ਰੋਕੋ;
			}
		} ਨਹੀਂਤਾਂ {
			ਜੇ (sshkey_equal(k, hostkeys->entries[i].ਕੁੰਜੀ)) {
				ਸਿਰਾ_return = HOST_OK;
				ਜੇ (ਮਿਲਿਆ != ਨਿਰਾ)
					*ਮਿਲਿਆ = hostkeys->entries + i;
				ਰੋਕੋ;
			}
			/* A non-matching key exists */
			ਸਿਰਾ_return = HOST_ਬਦਲਿਆ;
			ਜੇ (ਮਿਲਿਆ != ਨਿਰਾ)
				*ਮਿਲਿਆ = hostkeys->entries + i;
		}
	}
	ਜੇ (check_ਕੁੰਜੀ_not_revoked(hostkeys, k) != 0) {
		ਸਿਰਾ_return = HOST_REVOKED;
		ਜੇ (ਮਿਲਿਆ != ਨਿਰਾ)
			*ਮਿਲਿਆ = ਨਿਰਾ;
	}
	ਵਾਪਸ ਸਿਰਾ_return;
}

Host_ਸਥਿਤੀ
check_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys(ਬਣਤਰ hostkeys *hostkeys, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ **ਮਿਲਿਆ)
{
	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
		fatal("no key to look up");
	ਵਾਪਸ check_hostkeys_by_ਕੁੰਜੀ_or_type(hostkeys, ਕੁੰਜੀ, 0, -1, ਮਿਲਿਆ);
}

ਪੂਰਨ
lookup_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys_by_type(ਬਣਤਰ hostkeys *hostkeys, ਪੂਰਨ keytype, ਪੂਰਨ nid,
    ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ **ਮਿਲਿਆ)
{
	ਵਾਪਸ (check_hostkeys_by_ਕੁੰਜੀ_or_type(hostkeys, ਨਿਰਾ, keytype, nid,
	    ਮਿਲਿਆ) == HOST_ਮਿਲਿਆ);
}

ਪੂਰਨ
lookup_marker_ਵਿੱਚ_hostkeys(ਬਣਤਰ hostkeys *hostkeys, ਪੂਰਨ want_marker)
{
	u_int i;

	ਲਈ (i = 0; i < hostkeys->ਅੰਕ_entries; i++) {
		ਜੇ (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
format_host_ਇੰਦਰਾਜ(ਬਣਤਰ sshbuf *ਇੰਦਰਾਜ, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip,
    ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਪੂਰਨ store_hash)
{
	ਪੂਰਨ r, success = 0;
	ਅੱਖਰ *hashed_host = ਨਿਰਾ, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	ਜੇ (store_hash) {
		ਜੇ ((hashed_host = host_hash(lhost, ਨਿਰਾ, 0)) == ਨਿਰਾ) {
			error_f("host_hash failed");
			ਮੁਕਤ(lhost);
			ਵਾਪਸ 0;
		}
		ਜੇ ((r = sshbuf_putf(ਇੰਦਰਾਜ, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ਨਹੀਂਤਾਂ ਜੇ (ip != ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_putf(ਇੰਦਰਾਜ, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = sshbuf_putf(ਇੰਦਰਾਜ, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	ਮੁਕਤ(hashed_host);
	ਮੁਕਤ(lhost);
	ਜੇ ((r = sshkey_format_ਪਾਠ(ਕੁੰਜੀ, ਇੰਦਰਾਜ)) == 0)
		success = 1;
	ਨਹੀਂਤਾਂ
		error_fr(r, "sshkey_write");
	ਜੇ ((r = sshbuf_putf(ਇੰਦਰਾਜ, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	ਜੇ (success && store_hash && ip != ਨਿਰਾ)
		success = format_host_ਇੰਦਰਾਜ(ਇੰਦਰਾਜ, ip, ਨਿਰਾ, ਕੁੰਜੀ, 1);
	ਵਾਪਸ success;
}

ਸਥਿਰ ਪੂਰਨ
write_host_ਇੰਦਰਾਜ(FILE *f, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip,
    ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਪੂਰਨ store_hash)
{
	ਪੂਰਨ r, success = 0;
	ਬਣਤਰ sshbuf *ਇੰਦਰਾਜ = ਨਿਰਾ;

	ਜੇ ((ਇੰਦਰਾਜ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("allocation failed");
	ਜੇ ((r = format_host_ਇੰਦਰਾਜ(ਇੰਦਰਾਜ, host, ip, ਕੁੰਜੀ, store_hash)) != 1) {
		debug_f("failed to format host entry");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fwrite(sshbuf_ptr(ਇੰਦਰਾਜ), sshbuf_len(ਇੰਦਰਾਜ), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	success = 1;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਇੰਦਰਾਜ);
	ਵਾਪਸ success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
ਖਾਲੀ
hostfile_create_user_ssh_dir(ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ notify)
{
	ਅੱਖਰ *dotsshdir = ਨਿਰਾ, *p;
	ਮਾਪ_t len;
	ਬਣਤਰ stat st;

	ਜੇ ((p = strrchr(filename, '/')) == ਨਿਰਾ)
		ਵਾਪਸ;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" ਰਸਤਾ_SSH_USER_DIR, getuid());
	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(dotsshdir) > len || ਲੜੀ_ਤੁਲਨਾ(filename, dotsshdir, len) != 0)
		ਜਾਓ ਬਾਹਰਲਾ; /* not ~/.ssh prefixed */
	ਜੇ (stat(dotsshdir, &st) == 0)
		ਜਾਓ ਬਾਹਰਲਾ; /* dir already exists */
	ਨਹੀਂਤਾਂ ਜੇ (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	ਨਹੀਂਤਾਂ {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#ਜੇ_ਅੰਤ
		ਜੇ (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		ਨਹੀਂਤਾਂ ਜੇ (notify)
			logit("Created directory '%s'.", dotsshdir);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
		ssh_selinux_setfscreatecon(ਨਿਰਾ);
#ਜੇ_ਅੰਤ
	}
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
ਪੂਰਨ
ਜੋੜੋ_host_ਮੰਜ਼ਿਲ_hostfile(ਅਚਲ ਅੱਖਰ *filename, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਪੂਰਨ store_hash)
{
	FILE *f;
	ਪੂਰਨ success, addnl = 0;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	ਜੇ ((f = fopen(filename, "a+")) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	setvbuf(f, ਨਿਰਾ, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	ਜੇ (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	ਜੇ (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		ਵਾਪਸ 0;
	}
	success = write_host_ਇੰਦਰਾਜ(f, host, ਨਿਰਾ, ਕੁੰਜੀ, store_hash);
	fclose(f);
	ਵਾਪਸ success;
}

ਬਣਤਰ host_delete_ctx {
	FILE *ਬਾਹਰਲਾ;
	ਪੂਰਨ quiet;
	ਅਚਲ ਅੱਖਰ *host, *ip;
	u_int *ਮੇਲ_ਕੁੰਜੀਆਂ;	/* mask of HKF_MATCH_* for this key */
	ਬਣਤਰ sshkey * ਅਚਲ *ਕੁੰਜੀਆਂ;
	ਮਾਪ_t nkeys;
	ਪੂਰਨ modified;
};

ਸਥਿਰ ਪੂਰਨ
host_delete(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ host_delete_ctx *ctx = (ਬਣਤਰ host_delete_ctx *)_ctx;
	ਪੂਰਨ loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ਮਾਪ_t i;

	/* Don't remove CA and revocation lines */
	ਜੇ (l->ਸਥਿਤੀ == HKF_ਸਥਿਤੀ_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		ਲਈ (i = 0; i < ctx->nkeys; i++) {
			ਜੇ (!sshkey_equal(ctx->ਕੁੰਜੀਆਂ[i], l->ਕੁੰਜੀ))
				ਜਾਰੀ;
			ctx->ਮੇਲ_ਕੁੰਜੀਆਂ[i] |= l->ਮੇਲ;
			fprintf(ctx->ਬਾਹਰਲਾ, "%s\n", l->ਸਤਰ);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->ਕੁੰਜੀ), l->ਰਸਤਾ, l->linenum);
			ਵਾਪਸ 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->ਰਸਤਾ, l->linenum, sshkey_type(l->ਕੁੰਜੀ), ctx->host);
		ctx->modified = 1;
		ਵਾਪਸ 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	ਜੇ (l->ਸਥਿਤੀ == HKF_ਸਥਿਤੀ_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->ਰਸਤਾ, l->linenum);
	}
	fprintf(ctx->ਬਾਹਰਲਾ, "%s\n", l->ਸਤਰ);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
hostfile_replace_entries(ਅਚਲ ਅੱਖਰ *filename, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip,
    ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ, ਮਾਪ_t nkeys, ਪੂਰਨ store_hash, ਪੂਰਨ quiet, ਪੂਰਨ hash_alg)
{
	ਪੂਰਨ r, fd, oerrno = 0;
	ਪੂਰਨ loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ਬਣਤਰ host_delete_ctx ctx;
	ਅੱਖਰ *fp = ਨਿਰਾ, *ਆਰਜ਼ੀ = ਨਿਰਾ, *ਪਿੱਠ = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *what;
	ਬਹੁਲਕ_t omask;
	ਮਾਪ_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	ਜੇ ((ctx.ਮੇਲ_ਕੁੰਜੀਆਂ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(nkeys, ਆਕਾਰ(*ctx.ਮੇਲ_ਕੁੰਜੀਆਂ))) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ctx.ਕੁੰਜੀਆਂ = ਕੁੰਜੀਆਂ;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	ਜੇ ((r = asprintf(&ਆਰਜ਼ੀ, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&ਪਿੱਠ, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ fail;
	}

	ਜੇ ((fd = mkstemp(ਆਰਜ਼ੀ)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		ਜਾਓ fail;
	}
	ਜੇ ((ctx.ਬਾਹਰਲਾ = fdopen(fd, "w")) == ਨਿਰਾ) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		ਜਾਓ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	ਜੇ ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_ਕੁੰਜੀ, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		ਜਾਓ fail;
	}

	/* Re-add the requested keys */
	want = HKF_ਮੇਲ_HOST | (ip == ਨਿਰਾ ? 0 : HKF_ਮੇਲ_IP);
	ਲਈ (i = 0; i < nkeys; i++) {
		ਜੇ (ਕੁੰਜੀਆਂ[i] == ਨਿਰਾ || (want & ctx.ਮੇਲ_ਕੁੰਜੀਆਂ[i]) == want)
			ਜਾਰੀ;
		ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀਆਂ[i], hash_alg,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ fail;
		}
		/* write host/ip */
		what = "";
		ਜੇ (ctx.ਮੇਲ_ਕੁੰਜੀਆਂ[i] == 0) {
			what = "Adding new key";
			ਜੇ (!write_host_ਇੰਦਰਾਜ(ctx.ਬਾਹਰਲਾ, host, ip,
			    ਕੁੰਜੀਆਂ[i], store_hash)) {
				r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
				ਜਾਓ fail;
			}
		} ਨਹੀਂਤਾਂ ਜੇ ((want & ~ctx.ਮੇਲ_ਕੁੰਜੀਆਂ[i]) == HKF_ਮੇਲ_HOST) {
			what = "Fixing match (hostname)";
			ਜੇ (!write_host_ਇੰਦਰਾਜ(ctx.ਬਾਹਰਲਾ, host, ਨਿਰਾ,
			    ਕੁੰਜੀਆਂ[i], store_hash)) {
				r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
				ਜਾਓ fail;
			}
		} ਨਹੀਂਤਾਂ ਜੇ ((want & ~ctx.ਮੇਲ_ਕੁੰਜੀਆਂ[i]) == HKF_ਮੇਲ_IP) {
			what = "Fixing match (address)";
			ਜੇ (!write_host_ਇੰਦਰਾਜ(ctx.ਬਾਹਰਲਾ, ip, ਨਿਰਾ,
			    ਕੁੰਜੀਆਂ[i], store_hash)) {
				r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
				ਜਾਓ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == ਨਿਰਾ ? "" : ",", ip == ਨਿਰਾ ? "" : ip, filename,
		    sshkey_ssh_name(ਕੁੰਜੀਆਂ[i]), fp);
		ਮੁਕਤ(fp);
		fp = ਨਿਰਾ;
		ctx.modified = 1;
	}
	fclose(ctx.ਬਾਹਰਲਾ);
	ctx.ਬਾਹਰਲਾ = ਨਿਰਾ;

	ਜੇ (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		ਜੇ (unlink(ਪਿੱਠ) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", ਪਿੱਠ, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ਜਾਓ fail;
		}
		ਜੇ (link(filename, ਪਿੱਠ) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    ਪਿੱਠ, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ਜਾਓ fail;
		}
		ਜੇ (rename(ਆਰਜ਼ੀ, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", ਆਰਜ਼ੀ,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ਜਾਓ fail;
		}
	} ਨਹੀਂਤਾਂ {
		/* No changes made; just delete the temporary file */
		ਜੇ (unlink(ਆਰਜ਼ੀ) != 0)
			error_f("unlink \"%s\": %s", ਆਰਜ਼ੀ, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	ਜੇ (ਆਰਜ਼ੀ != ਨਿਰਾ && r != 0)
		unlink(ਆਰਜ਼ੀ);
	ਮੁਕਤ(ਆਰਜ਼ੀ);
	ਮੁਕਤ(ਪਿੱਠ);
	ਮੁਕਤ(fp);
	ਜੇ (ctx.ਬਾਹਰਲਾ != ਨਿਰਾ)
		fclose(ctx.ਬਾਹਰਲਾ);
	ਮੁਕਤ(ctx.ਮੇਲ_ਕੁੰਜੀਆਂ);
	umask(omask);
	ਜੇ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_maybe_hashed(ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ਨਾਂ, ਪੂਰਨ *was_hashed)
{
	ਪੂਰਨ hashed = *ਨਾਂ == HASH_DELIM, ret;
	ਅੱਖਰ *hashed_host = ਨਿਰਾ;
	ਮਾਪ_t nlen = ਲੜੀ_ਲੰਬਾਈ(ਨਾਂ);

	ਜੇ (was_hashed != ਨਿਰਾ)
		*was_hashed = hashed;
	ਜੇ (hashed) {
		ਜੇ ((hashed_host = host_hash(host, ਨਾਂ, nlen)) == ਨਿਰਾ)
			ਵਾਪਸ -1;
		ret = (nlen == ਲੜੀ_ਲੰਬਾਈ(hashed_host) &&
		    ਲੜੀ_ਤੁਲਨਾ(hashed_host, ਨਾਂ, nlen) == 0);
		ਮੁਕਤ(hashed_host);
		ਵਾਪਸ ret;
	}
	ਵਾਪਸ ਮੇਲ_hostname(host, ਨਾਂ) == 1;
}

ਪੂਰਨ
hostkeys_foreach_file(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, FILE *f, hostkeys_foreach_fn *callback,
    ਖਾਲੀ *ctx, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip, u_int options, u_int note)
{
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ, ktype[128];
	u_long linenum = 0;
	ਅੱਖਰ *cp, *cp2;
	u_int kbits;
	ਪੂਰਨ hashed;
	ਪੂਰਨ s, r = 0;
	ਬਣਤਰ hostkey_foreach_ਸਤਰ lineinfo;
	ਮਾਪ_t linesize = 0, l;

	memset(&lineinfo, 0, ਆਕਾਰ(lineinfo));
	ਜੇ (host == ਨਿਰਾ && (options & HKF_WANT_ਮੇਲ) != 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		linenum++;
		ਸਤਰ[strcspn(ਸਤਰ, "\n")] = '\0';

		ਮੁਕਤ(lineinfo.ਸਤਰ);
		sshkey_free(lineinfo.ਕੁੰਜੀ);
		memset(&lineinfo, 0, ਆਕਾਰ(lineinfo));
		lineinfo.ਰਸਤਾ = ਰਸਤਾ;
		lineinfo.linenum = linenum;
		lineinfo.ਸਤਰ = xstrdup(ਸਤਰ);
		lineinfo.marker = MRK_NONE;
		lineinfo.ਸਥਿਤੀ = HKF_ਸਥਿਤੀ_OK;
		lineinfo.keytype = ਕੁੰਜੀ_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		ਲਈ (cp = ਸਤਰ; *cp == ' ' || *cp == '\t'; cp++)
			;
		ਜੇ (!*cp || *cp == '#' || *cp == '\n') {
			ਜੇ ((options & HKF_WANT_ਮੇਲ) == 0) {
				lineinfo.ਸਥਿਤੀ = HKF_ਸਥਿਤੀ_COMMENT;
				ਜੇ ((r = callback(&lineinfo, ctx)) != 0)
					ਰੋਕੋ;
			}
			ਜਾਰੀ;
		}

		ਜੇ ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", ਰਸਤਾ, linenum);
			ਜੇ ((options & HKF_WANT_ਮੇਲ) == 0)
				ਜਾਓ bad;
			ਜਾਰੀ;
		}

		/* Find the end of the host name portion. */
		ਲਈ (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		ਜੇ (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", ਰਸਤਾ, linenum);
			ਜੇ ((options & HKF_WANT_ਮੇਲ) == 0)
				ਜਾਓ bad;
			ਜਾਰੀ;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		ਜੇ (host != ਨਿਰਾ) {
			ਜੇ ((s = ਮੇਲ_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    ਰਸਤਾ, linenum, lineinfo.hosts);
				ਜਾਓ bad;
			}
			ਜੇ (s == 1) {
				lineinfo.ਸਥਿਤੀ = HKF_ਸਥਿਤੀ_MATCHED;
				lineinfo.ਮੇਲ |= HKF_ਮੇਲ_HOST |
				    (hashed ? HKF_ਮੇਲ_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			ਜੇ (ip != ਨਿਰਾ) {
				ਜੇ ((s = ਮੇਲ_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", ਰਸਤਾ, linenum,
					    lineinfo.hosts);
					ਜਾਓ bad;
				}
				ਜੇ (s == 1) {
					lineinfo.ਸਥਿਤੀ = HKF_ਸਥਿਤੀ_MATCHED;
					lineinfo.ਮੇਲ |= HKF_ਮੇਲ_IP |
					    (hashed ? HKF_ਮੇਲ_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			ਜੇ ((options & HKF_WANT_ਮੇਲ) != 0 &&
			    lineinfo.ਸਥਿਤੀ != HKF_ਸਥਿਤੀ_MATCHED)
				ਜਾਰੀ;
		}

		/* Got a match.  Skip host name and any following whitespace */
		ਲਈ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		ਜੇ (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    ਰਸਤਾ, linenum);
			ਜਾਓ bad;
		}
		lineinfo.rawkey = cp = cp2;

		ਜੇ ((options & HKF_WANT_PARSE_ਕੁੰਜੀ) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			ਜੇ ((lineinfo.ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				ਰੋਕੋ;
			}
			ਜੇ (!hostfile_read_ਕੁੰਜੀ(&cp, &kbits, lineinfo.ਕੁੰਜੀ)) {
				ਜਾਓ bad;
			}
			lineinfo.keytype = lineinfo.ਕੁੰਜੀ->type;
			lineinfo.comment = cp;
		} ਨਹੀਂਤਾਂ {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			ਜੇ (l <= 1 || l >= ਆਕਾਰ(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				ਜਾਓ bad;
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			ਜੇ (lineinfo.keytype == ਕੁੰਜੀ_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				ਜਾਓ bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			ਲਈ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			ਜੇ (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    ਰਸਤਾ, linenum);
				lineinfo.keytype = ਕੁੰਜੀ_UNSPEC;
			}
			ਜੇ (lineinfo.keytype == ਕੁੰਜੀ_UNSPEC) {
 bad:
				sshkey_free(lineinfo.ਕੁੰਜੀ);
				lineinfo.ਕੁੰਜੀ = ਨਿਰਾ;
				lineinfo.ਸਥਿਤੀ = HKF_ਸਥਿਤੀ_INVALID;
				ਜੇ ((r = callback(&lineinfo, ctx)) != 0)
					ਰੋਕੋ;
				ਜਾਰੀ;
			}
		}
		ਜੇ ((r = callback(&lineinfo, ctx)) != 0)
			ਰੋਕੋ;
	}
	sshkey_free(lineinfo.ਕੁੰਜੀ);
	ਮੁਕਤ(lineinfo.ਸਤਰ);
	ਮੁਕਤ(ਸਤਰ);
	ਵਾਪਸ r;
}

ਪੂਰਨ
hostkeys_foreach(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, hostkeys_foreach_fn *callback, ਖਾਲੀ *ctx,
    ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip, u_int options, u_int note)
{
	FILE *f;
	ਪੂਰਨ r, oerrno;

	ਜੇ ((f = fopen(ਰਸਤਾ, "r")) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", ਰਸਤਾ);
	r = hostkeys_foreach_file(ਰਸਤਾ, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	ਵਾਪਸ r;
}
