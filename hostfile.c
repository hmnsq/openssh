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

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
extract_salt(ಧ್ರುವ ವರ್ಣ *s, u_int l, u_char *salt, size_t salt_len)
{
	ವರ್ಣ *p, *b64salt;
	u_int b64len;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ಯದಿ (l < ಪರಿಮಾಣ(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (strncmp(s, HASH_MAGIC, ಪರಿಮಾಣ(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	s += ಪರಿಮಾಣ(HASH_MAGIC) - 1;
	l -= ಪರಿಮಾಣ(HASH_MAGIC) - 1;
	ಯದಿ ((p = memchr(s, HASH_DELIM, l)) == ರಿಕ್ತ) {
		debug2("extract_salt: missing salt termination character");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	b64len = p - s;
	/* Sanity check */
	ಯದಿ (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	ಮುಕ್ತ(b64salt);
	ಯದಿ (ret == -1) {
		debug2("extract_salt: salt decode error");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (ret != (ಪೂರ್ಣಾಙ್ಕ)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	ಪ್ರತ್ಯಾಗಮ (0);
}

ವರ್ಣ *
host_hash(ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *name_from_hostfile, u_int src_len)
{
	ಸಂರಚನಾ ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	ವರ್ಣ uu_salt[512], uu_result[512];
	ವರ್ಣ *encoded = ರಿಕ್ತ;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	ಯದಿ (name_from_hostfile == ರಿಕ್ತ) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} ಅನ್ಯಥಾ {
		/* Extract salt from known host entry */
		ಯದಿ (extract_salt(name_from_hostfile, src_len, salt,
		    ಪರಿಮಾಣ(salt)) == -1)
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	ಯದಿ ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == ರಿಕ್ತ ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, ಪರಿಮಾಣ(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	ಯದಿ (__b64_ntop(salt, len, uu_salt, ಪರಿಮಾಣ(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, ಪರಿಮಾಣ(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	ಪ್ರತ್ಯಾಗಮ (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

ಪೂರ್ಣಾಙ್ಕ
hostfile_read_ಕೀಲಿ(ವರ್ಣ **cpp, u_int *bitsp, ಸಂರಚನಾ sshkey *ret)
{
	ವರ್ಣ *cp;

	/* Skip leading whitespace. */
	ಪ್ರತಿ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	ಯದಿ (sshkey_read(ret, &cp) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Skip trailing whitespace. */
	ಪ್ರತಿ (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	ಯದಿ (bitsp != ರಿಕ್ತ)
		*bitsp = sshkey_size(ret);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ HostkeyMarker
check_markers(ವರ್ಣ **cpp)
{
	ವರ್ಣ marker[32], *sp, *cp = *cpp;
	ಪೂರ್ಣಾಙ್ಕ ret = MRK_NONE;

	ಯಾವತ್ (*cp == '@') {
		/* Only one marker is allowed */
		ಯದಿ (ret != MRK_NONE)
			ಪ್ರತ್ಯಾಗಮ MRK_ERROR;
		/* Markers are terminated by whitespace */
		ಯದಿ ((sp = strchr(cp, ' ')) == ರಿಕ್ತ &&
		    (sp = strchr(cp, '\t')) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ MRK_ERROR;
		/* Extract marker for comparison */
		ಯದಿ (sp <= cp + 1 || sp >= cp + ಪರಿಮಾಣ(marker))
			ಪ್ರತ್ಯಾಗಮ MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		ಯದಿ (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		ಅನ್ಯಥಾ ಯದಿ (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		ಅನ್ಯಥಾ
			ಪ್ರತ್ಯಾಗಮ MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		ಪ್ರತಿ (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸಂರಚನಾ hostkeys *
init_hostkeys(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ hostkeys *ret = xcalloc(1, ಪರಿಮಾಣ(*ret));

	ret->entries = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸಂರಚನಾ load_callback_ctx {
	ಧ್ರುವ ವರ್ಣ *host;
	u_long ಅಂಕೆ_loaded;
	ಸಂರಚನಾ hostkeys *hostkeys;
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
record_hostkey(ಸಂರಚನಾ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ಸಂರಚನಾ load_callback_ctx *ctx = (ಸಂರಚನಾ load_callback_ctx *)_ctx;
	ಸಂರಚನಾ hostkeys *hostkeys = ctx->hostkeys;
	ಸಂರಚನಾ hostkey_entry *tmp;

	ಯದಿ (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->ಕೀಲಿ), l->path, l->linenum);
	ಯದಿ ((tmp = recallocarray(hostkeys->entries, hostkeys->ಅಂಕೆ_entries,
	    hostkeys->ಅಂಕೆ_entries + 1, ಪರಿಮಾಣ(*hostkeys->entries))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].ಸಾಲು = l->linenum;
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].ಕೀಲಿ = l->ಕೀಲಿ;
	l->ಕೀಲಿ = ರಿಕ್ತ; /* steal it */
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].marker = l->marker;
	hostkeys->entries[hostkeys->ಅಂಕೆ_entries].note = l->note;
	hostkeys->ಅಂಕೆ_entries++;
	ctx->ಅಂಕೆ_loaded++;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
load_hostkeys_file(ಸಂರಚನಾ hostkeys *hostkeys, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ವರ್ಣ *path, FILE *f, u_int note)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ load_callback_ctx ctx;

	ctx.host = host;
	ctx.ಅಂಕೆ_loaded = 0;
	ctx.hostkeys = hostkeys;

	ಯದಿ ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    ರಿಕ್ತ, HKF_WANT_MATCH|HKF_WANT_PARSE_ಕೀಲಿ, note)) != 0) {
		ಯದಿ (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	ಯದಿ (ctx.ಅಂಕೆ_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.ಅಂಕೆ_loaded, host);
}

ಶೂನ್ಯ
load_hostkeys(ಸಂರಚನಾ hostkeys *hostkeys, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *path,
    u_int note)
{
	FILE *f;

	ಯದಿ ((f = fopen(path, "r")) == ರಿಕ್ತ) {
		debug_f("fopen %s: %s", path, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

ಶೂನ್ಯ
free_hostkeys(ಸಂರಚನಾ hostkeys *hostkeys)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		ಮುಕ್ತ(hostkeys->entries[i].host);
		ಮುಕ್ತ(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].ಕೀಲಿ);
		explicit_bzero(hostkeys->entries + i, ಪರಿಮಾಣ(*hostkeys->entries));
	}
	ಮುಕ್ತ(hostkeys->entries);
	freezero(hostkeys, ಪರಿಮಾಣ(*hostkeys));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_ಕೀಲಿ_not_revoked(ಸಂರಚನಾ hostkeys *hostkeys, ಸಂರಚನಾ sshkey *k)
{
	ಪೂರ್ಣಾಙ್ಕ is_cert = sshkey_is_cert(k);
	u_int i;

	ಪ್ರತಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		ಯದಿ (hostkeys->entries[i].marker != MRK_REVOKE)
			ಅನುವರ್ತ;
		ಯದಿ (sshkey_equal_public(k, hostkeys->entries[i].ಕೀಲಿ))
			ಪ್ರತ್ಯಾಗಮ -1;
		ಯದಿ (is_cert && k != ರಿಕ್ತ &&
		    sshkey_equal_public(k->cert->signature_ಕೀಲಿ,
		    hostkeys->entries[i].ಕೀಲಿ))
			ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
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
ಸ್ಥಿರ HostStatus
check_hostkeys_by_ಕೀಲಿ_or_type(ಸಂರಚನಾ hostkeys *hostkeys,
    ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ keytype, ಪೂರ್ಣಾಙ್ಕ nid, ಧ್ರುವ ಸಂರಚನಾ hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	ಪೂರ್ಣಾಙ್ಕ want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	ಯದಿ (found != ರಿಕ್ತ)
		*found = ರಿಕ್ತ;

	ಪ್ರತಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		ಯದಿ (hostkeys->entries[i].marker != want_marker)
			ಅನುವರ್ತ;
		ಯದಿ (k == ರಿಕ್ತ) {
			ಯದಿ (hostkeys->entries[i].ಕೀಲಿ->type != keytype)
				ಅನುವರ್ತ;
			ಯದಿ (nid != -1 &&
			    sshkey_type_plain(keytype) == ಕೀಲಿ_ECDSA &&
			    hostkeys->entries[i].ಕೀಲಿ->ecdsa_nid != nid)
				ಅನುವರ್ತ;
			end_return = HOST_FOUND;
			ಯದಿ (found != ರಿಕ್ತ)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].ಕೀಲಿ;
			ಭಙ್ಗ;
		}
		ಯದಿ (want_cert) {
			ಯದಿ (sshkey_equal_public(k->cert->signature_ಕೀಲಿ,
			    hostkeys->entries[i].ಕೀಲಿ)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				ಯದಿ (found != ರಿಕ್ತ)
					*found = hostkeys->entries + i;
				ಭಙ್ಗ;
			}
		} ಅನ್ಯಥಾ {
			ಯದಿ (sshkey_equal(k, hostkeys->entries[i].ಕೀಲಿ)) {
				end_return = HOST_OK;
				ಯದಿ (found != ರಿಕ್ತ)
					*found = hostkeys->entries + i;
				ಭಙ್ಗ;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			ಯದಿ (found != ರಿಕ್ತ)
				*found = hostkeys->entries + i;
		}
	}
	ಯದಿ (check_ಕೀಲಿ_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		ಯದಿ (found != ರಿಕ್ತ)
			*found = ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ end_return;
}

HostStatus
check_ಕೀಲಿ_in_hostkeys(ಸಂರಚನಾ hostkeys *hostkeys, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ಸಂರಚನಾ hostkey_entry **found)
{
	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
		fatal("no key to look up");
	ಪ್ರತ್ಯಾಗಮ check_hostkeys_by_ಕೀಲಿ_or_type(hostkeys, ಕೀಲಿ, 0, -1, found);
}

ಪೂರ್ಣಾಙ್ಕ
lookup_ಕೀಲಿ_in_hostkeys_by_type(ಸಂರಚನಾ hostkeys *hostkeys, ಪೂರ್ಣಾಙ್ಕ keytype, ಪೂರ್ಣಾಙ್ಕ nid,
    ಧ್ರುವ ಸಂರಚನಾ hostkey_entry **found)
{
	ಪ್ರತ್ಯಾಗಮ (check_hostkeys_by_ಕೀಲಿ_or_type(hostkeys, ರಿಕ್ತ, keytype, nid,
	    found) == HOST_FOUND);
}

ಪೂರ್ಣಾಙ್ಕ
lookup_marker_in_hostkeys(ಸಂರಚನಾ hostkeys *hostkeys, ಪೂರ್ಣಾಙ್ಕ want_marker)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < hostkeys->ಅಂಕೆ_entries; i++) {
		ಯದಿ (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
format_host_entry(ಸಂರಚನಾ sshbuf *entry, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ store_hash)
{
	ಪೂರ್ಣಾಙ್ಕ r, success = 0;
	ವರ್ಣ *hashed_host = ರಿಕ್ತ, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	ಯದಿ (store_hash) {
		ಯದಿ ((hashed_host = host_hash(lhost, ರಿಕ್ತ, 0)) == ರಿಕ್ತ) {
			error_f("host_hash failed");
			ಮುಕ್ತ(lhost);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		ಯದಿ ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ಅನ್ಯಥಾ ಯದಿ (ip != ರಿಕ್ತ) {
		ಯದಿ ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	ಮುಕ್ತ(hashed_host);
	ಮುಕ್ತ(lhost);
	ಯದಿ ((r = sshkey_format_text(ಕೀಲಿ, entry)) == 0)
		success = 1;
	ಅನ್ಯಥಾ
		error_fr(r, "sshkey_write");
	ಯದಿ ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	ಯದಿ (success && store_hash && ip != ರಿಕ್ತ)
		success = format_host_entry(entry, ip, ರಿಕ್ತ, ಕೀಲಿ, 1);
	ಪ್ರತ್ಯಾಗಮ success;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
write_host_entry(FILE *f, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ store_hash)
{
	ಪೂರ್ಣಾಙ್ಕ r, success = 0;
	ಸಂರಚನಾ sshbuf *entry = ರಿಕ್ತ;

	ಯದಿ ((entry = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("allocation failed");
	ಯದಿ ((r = format_host_entry(entry, host, ip, ಕೀಲಿ, store_hash)) != 1) {
		debug_f("failed to format host entry");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		ಗಚ್ಛ out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	ಪ್ರತ್ಯಾಗಮ success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
ಶೂನ್ಯ
hostfile_create_user_ssh_dir(ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ notify)
{
	ವರ್ಣ *dotsshdir = ರಿಕ್ತ, *p;
	size_t len;
	ಸಂರಚನಾ stat st;

	ಯದಿ ((p = strrchr(filename, '/')) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	ಯದಿ (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		ಗಚ್ಛ out; /* not ~/.ssh prefixed */
	ಯದಿ (stat(dotsshdir, &st) == 0)
		ಗಚ್ಛ out; /* dir already exists */
	ಅನ್ಯಥಾ ಯದಿ (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	ಅನ್ಯಥಾ {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		ಯದಿ (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		ಅನ್ಯಥಾ ಯದಿ (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(ರಿಕ್ತ);
#endif
	}
 out:
	ಮುಕ್ತ(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
ಪೂರ್ಣಾಙ್ಕ
add_host_to_hostfile(ಧ್ರುವ ವರ್ಣ *filename, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ store_hash)
{
	FILE *f;
	ಪೂರ್ಣಾಙ್ಕ success, addnl = 0;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	ಯದಿ ((f = fopen(filename, "a+")) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	setvbuf(f, ರಿಕ್ತ, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	ಯದಿ (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	ಯದಿ (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	success = write_host_entry(f, host, ರಿಕ್ತ, ಕೀಲಿ, store_hash);
	fclose(f);
	ಪ್ರತ್ಯಾಗಮ success;
}

ಸಂರಚನಾ host_delete_ctx {
	FILE *out;
	ಪೂರ್ಣಾಙ್ಕ quiet;
	ಧ್ರುವ ವರ್ಣ *host, *ip;
	u_int *match_ಕೀಲಿಗಳು;	/* mask of HKF_MATCH_* for this key */
	ಸಂರಚನಾ sshkey * ಧ್ರುವ *ಕೀಲಿಗಳು;
	size_t nkeys;
	ಪೂರ್ಣಾಙ್ಕ modified;
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
host_delete(ಸಂರಚನಾ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ಸಂರಚನಾ host_delete_ctx *ctx = (ಸಂರಚನಾ host_delete_ctx *)_ctx;
	ಪೂರ್ಣಾಙ್ಕ loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	ಯದಿ (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		ಪ್ರತಿ (i = 0; i < ctx->nkeys; i++) {
			ಯದಿ (!sshkey_equal(ctx->ಕೀಲಿಗಳು[i], l->ಕೀಲಿ))
				ಅನುವರ್ತ;
			ctx->match_ಕೀಲಿಗಳು[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->ಸಾಲು);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->ಕೀಲಿ), l->path, l->linenum);
			ಪ್ರತ್ಯಾಗಮ 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->ಕೀಲಿ), ctx->host);
		ctx->modified = 1;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	ಯದಿ (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->ಸಾಲು);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
hostfile_replace_entries(ಧ್ರುವ ವರ್ಣ *filename, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip,
    ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು, size_t nkeys, ಪೂರ್ಣಾಙ್ಕ store_hash, ಪೂರ್ಣಾಙ್ಕ quiet, ಪೂರ್ಣಾಙ್ಕ hash_alg)
{
	ಪೂರ್ಣಾಙ್ಕ r, fd, oerrno = 0;
	ಪೂರ್ಣಾಙ್ಕ loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ಸಂರಚನಾ host_delete_ctx ctx;
	ವರ್ಣ *fp = ರಿಕ್ತ, *temp = ರಿಕ್ತ, *back = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	ಯದಿ ((ctx.match_ಕೀಲಿಗಳು = calloc(nkeys, ಪರಿಮಾಣ(*ctx.match_ಕೀಲಿಗಳು))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ctx.ಕೀಲಿಗಳು = ಕೀಲಿಗಳು;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	ಯದಿ ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ fail;
	}

	ಯದಿ ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((ctx.out = fdopen(fd, "w")) == ರಿಕ್ತ) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		ಗಚ್ಛ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	ಯದಿ ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_ಕೀಲಿ, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		ಗಚ್ಛ fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == ರಿಕ್ತ ? 0 : HKF_MATCH_IP);
	ಪ್ರತಿ (i = 0; i < nkeys; i++) {
		ಯದಿ (ಕೀಲಿಗಳು[i] == ರಿಕ್ತ || (want & ctx.match_ಕೀಲಿಗಳು[i]) == want)
			ಅನುವರ್ತ;
		ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿಗಳು[i], hash_alg,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ fail;
		}
		/* write host/ip */
		what = "";
		ಯದಿ (ctx.match_ಕೀಲಿಗಳು[i] == 0) {
			what = "Adding new key";
			ಯದಿ (!write_host_entry(ctx.out, host, ip,
			    ಕೀಲಿಗಳು[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				ಗಚ್ಛ fail;
			}
		} ಅನ್ಯಥಾ ಯದಿ ((want & ~ctx.match_ಕೀಲಿಗಳು[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			ಯದಿ (!write_host_entry(ctx.out, host, ರಿಕ್ತ,
			    ಕೀಲಿಗಳು[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				ಗಚ್ಛ fail;
			}
		} ಅನ್ಯಥಾ ಯದಿ ((want & ~ctx.match_ಕೀಲಿಗಳು[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			ಯದಿ (!write_host_entry(ctx.out, ip, ರಿಕ್ತ,
			    ಕೀಲಿಗಳು[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				ಗಚ್ಛ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == ರಿಕ್ತ ? "" : ",", ip == ರಿಕ್ತ ? "" : ip, filename,
		    sshkey_ssh_name(ಕೀಲಿಗಳು[i]), fp);
		ಮುಕ್ತ(fp);
		fp = ರಿಕ್ತ;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = ರಿಕ್ತ;

	ಯದಿ (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		ಯದಿ (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ಗಚ್ಛ fail;
		}
		ಯದಿ (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ಗಚ್ಛ fail;
		}
		ಯದಿ (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ಗಚ್ಛ fail;
		}
	} ಅನ್ಯಥಾ {
		/* No changes made; just delete the temporary file */
		ಯದಿ (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	ಯದಿ (temp != ರಿಕ್ತ && r != 0)
		unlink(temp);
	ಮುಕ್ತ(temp);
	ಮುಕ್ತ(back);
	ಮುಕ್ತ(fp);
	ಯದಿ (ctx.out != ರಿಕ್ತ)
		fclose(ctx.out);
	ಮುಕ್ತ(ctx.match_ಕೀಲಿಗಳು);
	umask(omask);
	ಯದಿ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match_maybe_hashed(ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *names, ಪೂರ್ಣಾಙ್ಕ *was_hashed)
{
	ಪೂರ್ಣಾಙ್ಕ hashed = *names == HASH_DELIM, ret;
	ವರ್ಣ *hashed_host = ರಿಕ್ತ;
	size_t nlen = strlen(names);

	ಯದಿ (was_hashed != ರಿಕ್ತ)
		*was_hashed = hashed;
	ಯದಿ (hashed) {
		ಯದಿ ((hashed_host = host_hash(host, names, nlen)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		ಮುಕ್ತ(hashed_host);
		ಪ್ರತ್ಯಾಗಮ ret;
	}
	ಪ್ರತ್ಯಾಗಮ match_hostname(host, names) == 1;
}

ಪೂರ್ಣಾಙ್ಕ
hostkeys_foreach_file(ಧ್ರುವ ವರ್ಣ *path, FILE *f, hostkeys_foreach_fn *callback,
    ಶೂನ್ಯ *ctx, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip, u_int options, u_int note)
{
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ, ktype[128];
	u_long linenum = 0;
	ವರ್ಣ *cp, *cp2;
	u_int kbits;
	ಪೂರ್ಣಾಙ್ಕ hashed;
	ಪೂರ್ಣಾಙ್ಕ s, r = 0;
	ಸಂರಚನಾ hostkey_foreach_ಸಾಲು lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, ಪರಿಮಾಣ(lineinfo));
	ಯದಿ (host == ರಿಕ್ತ && (options & HKF_WANT_MATCH) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		ಸಾಲು[strcspn(ಸಾಲು, "\n")] = '\0';

		ಮುಕ್ತ(lineinfo.ಸಾಲು);
		sshkey_free(lineinfo.ಕೀಲಿ);
		memset(&lineinfo, 0, ಪರಿಮಾಣ(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.ಸಾಲು = xstrdup(ಸಾಲು);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = ಕೀಲಿ_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		ಪ್ರತಿ (cp = ಸಾಲು; *cp == ' ' || *cp == '\t'; cp++)
			;
		ಯದಿ (!*cp || *cp == '#' || *cp == '\n') {
			ಯದಿ ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				ಯದಿ ((r = callback(&lineinfo, ctx)) != 0)
					ಭಙ್ಗ;
			}
			ಅನುವರ್ತ;
		}

		ಯದಿ ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			ಯದಿ ((options & HKF_WANT_MATCH) == 0)
				ಗಚ್ಛ bad;
			ಅನುವರ್ತ;
		}

		/* Find the end of the host name portion. */
		ಪ್ರತಿ (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		ಯದಿ (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			ಯದಿ ((options & HKF_WANT_MATCH) == 0)
				ಗಚ್ಛ bad;
			ಅನುವರ್ತ;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		ಯದಿ (host != ರಿಕ್ತ) {
			ಯದಿ ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				ಗಚ್ಛ bad;
			}
			ಯದಿ (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			ಯದಿ (ip != ರಿಕ್ತ) {
				ಯದಿ ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					ಗಚ್ಛ bad;
				}
				ಯದಿ (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			ಯದಿ ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				ಅನುವರ್ತ;
		}

		/* Got a match.  Skip host name and any following whitespace */
		ಪ್ರತಿ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		ಯದಿ (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			ಗಚ್ಛ bad;
		}
		lineinfo.rawkey = cp = cp2;

		ಯದಿ ((options & HKF_WANT_PARSE_ಕೀಲಿ) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			ಯದಿ ((lineinfo.ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				ಭಙ್ಗ;
			}
			ಯದಿ (!hostfile_read_ಕೀಲಿ(&cp, &kbits, lineinfo.ಕೀಲಿ)) {
				ಗಚ್ಛ bad;
			}
			lineinfo.keytype = lineinfo.ಕೀಲಿ->type;
			lineinfo.comment = cp;
		} ಅನ್ಯಥಾ {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			ಯದಿ (l <= 1 || l >= ಪರಿಮಾಣ(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				ಗಚ್ಛ bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			ಯದಿ (lineinfo.keytype == ಕೀಲಿ_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				ಗಚ್ಛ bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			ಪ್ರತಿ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			ಯದಿ (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = ಕೀಲಿ_UNSPEC;
			}
			ಯದಿ (lineinfo.keytype == ಕೀಲಿ_UNSPEC) {
 bad:
				sshkey_free(lineinfo.ಕೀಲಿ);
				lineinfo.ಕೀಲಿ = ರಿಕ್ತ;
				lineinfo.status = HKF_STATUS_INVALID;
				ಯದಿ ((r = callback(&lineinfo, ctx)) != 0)
					ಭಙ್ಗ;
				ಅನುವರ್ತ;
			}
		}
		ಯದಿ ((r = callback(&lineinfo, ctx)) != 0)
			ಭಙ್ಗ;
	}
	sshkey_free(lineinfo.ಕೀಲಿ);
	ಮುಕ್ತ(lineinfo.ಸಾಲು);
	ಮುಕ್ತ(ಸಾಲು);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
hostkeys_foreach(ಧ್ರುವ ವರ್ಣ *path, hostkeys_foreach_fn *callback, ಶೂನ್ಯ *ctx,
    ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ip, u_int options, u_int note)
{
	FILE *f;
	ಪೂರ್ಣಾಙ್ಕ r, oerrno;

	ಯದಿ ((f = fopen(path, "r")) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}
