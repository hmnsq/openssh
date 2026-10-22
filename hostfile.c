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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <resolv.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "hmac.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
extract_salt(ଅଚଳ ଅକ୍ଷର *s, u_int l, u_char *salt, size_t salt_len)
{
	ଅକ୍ଷର *p, *b64salt;
	u_int b64len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ଯଦି (l < ଆକାର(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (strncmp(s, HASH_MAGIC, ଆକାର(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		ଫେରନ୍ତୁ (-1);
	}
	s += ଆକାର(HASH_MAGIC) - 1;
	l -= ଆକାର(HASH_MAGIC) - 1;
	ଯଦି ((p = memchr(s, HASH_DELIM, l)) == ଖାଲି) {
		debug2("extract_salt: missing salt termination character");
		ଫେରନ୍ତୁ (-1);
	}

	b64len = p - s;
	/* Sanity check */
	ଯଦି (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		ଫେରନ୍ତୁ (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	ମୁକ୍ତ(b64salt);
	ଯଦି (ret == -1) {
		debug2("extract_salt: salt decode error");
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (ret != (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		ଫେରନ୍ତୁ (-1);
	}

	ଫେରନ୍ତୁ (0);
}

ଅକ୍ଷର *
host_hash(ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *name_from_hostfile, u_int src_len)
{
	ସଂରଚନା ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	ଅକ୍ଷର uu_salt[512], uu_result[512];
	ଅକ୍ଷର *encoded = ଖାଲି;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	ଯଦି (name_from_hostfile == ଖାଲି) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} ଅନ୍ୟଥା {
		/* Extract salt from known host entry */
		ଯଦି (extract_salt(name_from_hostfile, src_len, salt,
		    ଆକାର(salt)) == -1)
			ଫେରନ୍ତୁ (ଖାଲି);
	}

	ଯଦି ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == ଖାଲି ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, ଆକାର(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	ଯଦି (__b64_ntop(salt, len, uu_salt, ଆକାର(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, ଆକାର(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	ଫେରନ୍ତୁ (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hostfile_read_ଚାବି(ଅକ୍ଷର **cpp, u_int *bitsp, ସଂରଚନା sshkey *ret)
{
	ଅକ୍ଷର *cp;

	/* Skip leading whitespace. */
	ପାଇଁ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	ଯଦି (sshkey_read(ret, &cp) != 0)
		ଫେରନ୍ତୁ 0;

	/* Skip trailing whitespace. */
	ପାଇଁ (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	ଯଦି (bitsp != ଖାଲି)
		*bitsp = sshkey_size(ret);
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର HostkeyMarker
check_markers(ଅକ୍ଷର **cpp)
{
	ଅକ୍ଷର marker[32], *sp, *cp = *cpp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = MRK_NONE;

	ଯେତେବେଳେ (*cp == '@') {
		/* Only one marker is allowed */
		ଯଦି (ret != MRK_NONE)
			ଫେରନ୍ତୁ MRK_ERROR;
		/* Markers are terminated by whitespace */
		ଯଦି ((sp = strchr(cp, ' ')) == ଖାଲି &&
		    (sp = strchr(cp, '\t')) == ଖାଲି)
			ଫେରନ୍ତୁ MRK_ERROR;
		/* Extract marker for comparison */
		ଯଦି (sp <= cp + 1 || sp >= cp + ଆକାର(marker))
			ଫେରନ୍ତୁ MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		ଯଦି (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		ଅନ୍ୟଥା ଯଦି (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		ଅନ୍ୟଥା
			ଫେରନ୍ତୁ MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		ପାଇଁ (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	ଫେରନ୍ତୁ ret;
}

ସଂରଚନା hostkeys *
init_hostkeys(ଶୂନ୍ୟ)
{
	ସଂରଚନା hostkeys *ret = xcalloc(1, ଆକାର(*ret));

	ret->entries = ଖାଲି;
	ଫେରନ୍ତୁ ret;
}

ସଂରଚନା load_callback_ctx {
	ଅଚଳ ଅକ୍ଷର *host;
	u_long ଅଙ୍କ_loaded;
	ସଂରଚନା hostkeys *hostkeys;
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
record_hostkey(ସଂରଚନା hostkey_foreach_ଧାଡ଼ି *l, ଶୂନ୍ୟ *_ctx)
{
	ସଂରଚନା load_callback_ctx *ctx = (ସଂରଚନା load_callback_ctx *)_ctx;
	ସଂରଚନା hostkeys *hostkeys = ctx->hostkeys;
	ସଂରଚନା hostkey_entry *tmp;

	ଯଦି (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		ଫେରନ୍ତୁ 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->ଚାବି), l->path, l->linenum);
	ଯଦି ((tmp = recallocarray(hostkeys->entries, hostkeys->ଅଙ୍କ_entries,
	    hostkeys->ଅଙ୍କ_entries + 1, ଆକାର(*hostkeys->entries))) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->ଅଙ୍କ_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->ଅଙ୍କ_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->ଅଙ୍କ_entries].ଧାଡ଼ି = l->linenum;
	hostkeys->entries[hostkeys->ଅଙ୍କ_entries].ଚାବି = l->ଚାବି;
	l->ଚାବି = ଖାଲି; /* steal it */
	hostkeys->entries[hostkeys->ଅଙ୍କ_entries].marker = l->marker;
	hostkeys->entries[hostkeys->ଅଙ୍କ_entries].note = l->note;
	hostkeys->ଅଙ୍କ_entries++;
	ctx->ଅଙ୍କ_loaded++;

	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
load_hostkeys_file(ସଂରଚନା hostkeys *hostkeys, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ଅକ୍ଷର *path, FILE *f, u_int note)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା load_callback_ctx ctx;

	ctx.host = host;
	ctx.ଅଙ୍କ_loaded = 0;
	ctx.hostkeys = hostkeys;

	ଯଦି ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    ଖାଲି, HKF_WANT_MATCH|HKF_WANT_PARSE_ଚାବି, note)) != 0) {
		ଯଦି (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	ଯଦି (ctx.ଅଙ୍କ_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.ଅଙ୍କ_loaded, host);
}

ଶୂନ୍ୟ
load_hostkeys(ସଂରଚନା hostkeys *hostkeys, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *path,
    u_int note)
{
	FILE *f;

	ଯଦି ((f = fopen(path, "r")) == ଖାଲି) {
		debug_f("fopen %s: %s", path, strerror(errno));
		ଫେରନ୍ତୁ;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

ଶୂନ୍ୟ
free_hostkeys(ସଂରଚନା hostkeys *hostkeys)
{
	u_int i;

	ପାଇଁ (i = 0; i < hostkeys->ଅଙ୍କ_entries; i++) {
		ମୁକ୍ତ(hostkeys->entries[i].host);
		ମୁକ୍ତ(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].ଚାବି);
		explicit_bzero(hostkeys->entries + i, ଆକାର(*hostkeys->entries));
	}
	ମୁକ୍ତ(hostkeys->entries);
	freezero(hostkeys, ଆକାର(*hostkeys));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_ଚାବି_not_revoked(ସଂରଚନା hostkeys *hostkeys, ସଂରଚନା sshkey *k)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_cert = sshkey_is_cert(k);
	u_int i;

	ପାଇଁ (i = 0; i < hostkeys->ଅଙ୍କ_entries; i++) {
		ଯଦି (hostkeys->entries[i].marker != MRK_REVOKE)
			ଜାରି;
		ଯଦି (sshkey_equal_public(k, hostkeys->entries[i].ଚାବି))
			ଫେରନ୍ତୁ -1;
		ଯଦି (is_cert && k != ଖାଲି &&
		    sshkey_equal_public(k->cert->signature_ଚାବି,
		    hostkeys->entries[i].ଚାବି))
			ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
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
ସ୍ଥିର HostStatus
check_hostkeys_by_ଚାବି_or_type(ସଂରଚନା hostkeys *hostkeys,
    ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid, ଅଚଳ ସଂରଚନା hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	ଯଦି (found != ଖାଲି)
		*found = ଖାଲି;

	ପାଇଁ (i = 0; i < hostkeys->ଅଙ୍କ_entries; i++) {
		ଯଦି (hostkeys->entries[i].marker != want_marker)
			ଜାରି;
		ଯଦି (k == ଖାଲି) {
			ଯଦି (hostkeys->entries[i].ଚାବି->type != keytype)
				ଜାରି;
			ଯଦି (nid != -1 &&
			    sshkey_type_plain(keytype) == ଚାବି_ECDSA &&
			    hostkeys->entries[i].ଚାବି->ecdsa_nid != nid)
				ଜାରି;
			end_return = HOST_FOUND;
			ଯଦି (found != ଖାଲି)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].ଚାବି;
			ଭାଙ୍ଗ;
		}
		ଯଦି (want_cert) {
			ଯଦି (sshkey_equal_public(k->cert->signature_ଚାବି,
			    hostkeys->entries[i].ଚାବି)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				ଯଦି (found != ଖାଲି)
					*found = hostkeys->entries + i;
				ଭାଙ୍ଗ;
			}
		} ଅନ୍ୟଥା {
			ଯଦି (sshkey_equal(k, hostkeys->entries[i].ଚାବି)) {
				end_return = HOST_OK;
				ଯଦି (found != ଖାଲି)
					*found = hostkeys->entries + i;
				ଭାଙ୍ଗ;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			ଯଦି (found != ଖାଲି)
				*found = hostkeys->entries + i;
		}
	}
	ଯଦି (check_ଚାବି_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		ଯଦି (found != ଖାଲି)
			*found = ଖାଲି;
	}
	ଫେରନ୍ତୁ end_return;
}

HostStatus
check_ଚାବି_in_hostkeys(ସଂରଚନା hostkeys *hostkeys, ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ସଂରଚନା hostkey_entry **found)
{
	ଯଦି (ଚାବି == ଖାଲି)
		fatal("no key to look up");
	ଫେରନ୍ତୁ check_hostkeys_by_ଚାବି_or_type(hostkeys, ଚାବି, 0, -1, found);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
lookup_ଚାବି_in_hostkeys_by_type(ସଂରଚନା hostkeys *hostkeys, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid,
    ଅଚଳ ସଂରଚନା hostkey_entry **found)
{
	ଫେରନ୍ତୁ (check_hostkeys_by_ଚାବି_or_type(hostkeys, ଖାଲି, keytype, nid,
	    found) == HOST_FOUND);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
lookup_marker_in_hostkeys(ସଂରଚନା hostkeys *hostkeys, ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_marker)
{
	u_int i;

	ପାଇଁ (i = 0; i < hostkeys->ଅଙ୍କ_entries; i++) {
		ଯଦି (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
format_host_entry(ସଂରଚନା sshbuf *entry, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip,
    ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା store_hash)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0;
	ଅକ୍ଷର *hashed_host = ଖାଲି, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	ଯଦି (store_hash) {
		ଯଦି ((hashed_host = host_hash(lhost, ଖାଲି, 0)) == ଖାଲି) {
			error_f("host_hash failed");
			ମୁକ୍ତ(lhost);
			ଫେରନ୍ତୁ 0;
		}
		ଯଦି ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ଅନ୍ୟଥା ଯଦି (ip != ଖାଲି) {
		ଯଦି ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ଅନ୍ୟଥା {
		ଯଦି ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	ମୁକ୍ତ(hashed_host);
	ମୁକ୍ତ(lhost);
	ଯଦି ((r = sshkey_format_text(ଚାବି, entry)) == 0)
		success = 1;
	ଅନ୍ୟଥା
		error_fr(r, "sshkey_write");
	ଯଦି ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	ଯଦି (success && store_hash && ip != ଖାଲି)
		success = format_host_entry(entry, ip, ଖାଲି, ଚାବି, 1);
	ଫେରନ୍ତୁ success;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
write_host_entry(FILE *f, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip,
    ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା store_hash)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0;
	ସଂରଚନା sshbuf *entry = ଖାଲି;

	ଯଦି ((entry = sshbuf_new()) == ଖାଲି)
		fatal_f("allocation failed");
	ଯଦି ((r = format_host_entry(entry, host, ip, ଚାବି, store_hash)) != 1) {
		debug_f("failed to format host entry");
		ଯାଅ out;
	}
	ଯଦି ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		ଯାଅ out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	ଫେରନ୍ତୁ success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
ଶୂନ୍ୟ
hostfile_create_user_ssh_dir(ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା notify)
{
	ଅକ୍ଷର *dotsshdir = ଖାଲି, *p;
	size_t len;
	ସଂରଚନା stat st;

	ଯଦି ((p = strrchr(filename, '/')) == ଖାଲି)
		ଫେରନ୍ତୁ;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	ଯଦି (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		ଯାଅ out; /* not ~/.ssh prefixed */
	ଯଦି (stat(dotsshdir, &st) == 0)
		ଯାଅ out; /* dir already exists */
	ଅନ୍ୟଥା ଯଦି (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	ଅନ୍ୟଥା {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		ଯଦି (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		ଅନ୍ୟଥା ଯଦି (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(ଖାଲି);
#endif
	}
 out:
	ମୁକ୍ତ(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
add_host_to_hostfile(ଅଚଳ ଅକ୍ଷର *filename, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା store_hash)
{
	FILE *f;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success, addnl = 0;

	ଯଦି (ଚାବି == ଖାଲି)
		ଫେରନ୍ତୁ 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	ଯଦି ((f = fopen(filename, "a+")) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	setvbuf(f, ଖାଲି, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	ଯଦି (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	ଯଦି (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		ଫେରନ୍ତୁ 0;
	}
	success = write_host_entry(f, host, ଖାଲି, ଚାବି, store_hash);
	fclose(f);
	ଫେରନ୍ତୁ success;
}

ସଂରଚନା host_delete_ctx {
	FILE *out;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet;
	ଅଚଳ ଅକ୍ଷର *host, *ip;
	u_int *match_ଚାବିଗୁଡ଼ିକ;	/* mask of HKF_MATCH_* for this key */
	ସଂରଚନା sshkey * ଅଚଳ *ଚାବିଗୁଡ଼ିକ;
	size_t nkeys;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା modified;
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
host_delete(ସଂରଚନା hostkey_foreach_ଧାଡ଼ି *l, ଶୂନ୍ୟ *_ctx)
{
	ସଂରଚନା host_delete_ctx *ctx = (ସଂରଚନା host_delete_ctx *)_ctx;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	ଯଦି (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		ପାଇଁ (i = 0; i < ctx->nkeys; i++) {
			ଯଦି (!sshkey_equal(ctx->ଚାବିଗୁଡ଼ିକ[i], l->ଚାବି))
				ଜାରି;
			ctx->match_ଚାବିଗୁଡ଼ିକ[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->ଧାଡ଼ି);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->ଚାବି), l->path, l->linenum);
			ଫେରନ୍ତୁ 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->ଚାବି), ctx->host);
		ctx->modified = 1;
		ଫେରନ୍ତୁ 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	ଯଦି (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->ଧାଡ଼ି);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hostfile_replace_entries(ଅଚଳ ଅକ୍ଷର *filename, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip,
    ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ, size_t nkeys, ପୂର୍ଣ୍ଣସଂଖ୍ୟା store_hash, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet, ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, fd, oerrno = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ସଂରଚନା host_delete_ctx ctx;
	ଅକ୍ଷର *fp = ଖାଲି, *temp = ଖାଲି, *back = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, ଆକାର(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	ଯଦି ((ctx.match_ଚାବିଗୁଡ଼ିକ = calloc(nkeys, ଆକାର(*ctx.match_ଚାବିଗୁଡ଼ିକ))) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ctx.ଚାବିଗୁଡ଼ିକ = ଚାବିଗୁଡ଼ିକ;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	ଯଦି ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ fail;
	}

	ଯଦି ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		ଯାଅ fail;
	}
	ଯଦି ((ctx.out = fdopen(fd, "w")) == ଖାଲି) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		ଯାଅ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	ଯଦି ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_ଚାବି, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		ଯାଅ fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == ଖାଲି ? 0 : HKF_MATCH_IP);
	ପାଇଁ (i = 0; i < nkeys; i++) {
		ଯଦି (ଚାବିଗୁଡ଼ିକ[i] == ଖାଲି || (want & ctx.match_ଚାବିଗୁଡ଼ିକ[i]) == want)
			ଜାରି;
		ଯଦି ((fp = sshkey_fingerprint(ଚାବିଗୁଡ଼ିକ[i], hash_alg,
		    SSH_FP_DEFAULT)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ fail;
		}
		/* write host/ip */
		what = "";
		ଯଦି (ctx.match_ଚାବିଗୁଡ଼ିକ[i] == 0) {
			what = "Adding new key";
			ଯଦି (!write_host_entry(ctx.out, host, ip,
			    ଚାବିଗୁଡ଼ିକ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				ଯାଅ fail;
			}
		} ଅନ୍ୟଥା ଯଦି ((want & ~ctx.match_ଚାବିଗୁଡ଼ିକ[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			ଯଦି (!write_host_entry(ctx.out, host, ଖାଲି,
			    ଚାବିଗୁଡ଼ିକ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				ଯାଅ fail;
			}
		} ଅନ୍ୟଥା ଯଦି ((want & ~ctx.match_ଚାବିଗୁଡ଼ିକ[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			ଯଦି (!write_host_entry(ctx.out, ip, ଖାଲି,
			    ଚାବିଗୁଡ଼ିକ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				ଯାଅ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == ଖାଲି ? "" : ",", ip == ଖାଲି ? "" : ip, filename,
		    sshkey_ssh_name(ଚାବିଗୁଡ଼ିକ[i]), fp);
		ମୁକ୍ତ(fp);
		fp = ଖାଲି;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = ଖାଲି;

	ଯଦି (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		ଯଦି (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ଯାଅ fail;
		}
		ଯଦି (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ଯାଅ fail;
		}
		ଯଦି (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			ଯାଅ fail;
		}
	} ଅନ୍ୟଥା {
		/* No changes made; just delete the temporary file */
		ଯଦି (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	ଯଦି (temp != ଖାଲି && r != 0)
		unlink(temp);
	ମୁକ୍ତ(temp);
	ମୁକ୍ତ(back);
	ମୁକ୍ତ(fp);
	ଯଦି (ctx.out != ଖାଲି)
		fclose(ctx.out);
	ମୁକ୍ତ(ctx.match_ଚାବିଗୁଡ଼ିକ);
	umask(omask);
	ଯଦି (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_maybe_hashed(ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *names, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *was_hashed)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hashed = *names == HASH_DELIM, ret;
	ଅକ୍ଷର *hashed_host = ଖାଲି;
	size_t nlen = strlen(names);

	ଯଦି (was_hashed != ଖାଲି)
		*was_hashed = hashed;
	ଯଦି (hashed) {
		ଯଦି ((hashed_host = host_hash(host, names, nlen)) == ଖାଲି)
			ଫେରନ୍ତୁ -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		ମୁକ୍ତ(hashed_host);
		ଫେରନ୍ତୁ ret;
	}
	ଫେରନ୍ତୁ match_hostname(host, names) == 1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hostkeys_foreach_file(ଅଚଳ ଅକ୍ଷର *path, FILE *f, hostkeys_foreach_fn *callback,
    ଶୂନ୍ୟ *ctx, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip, u_int options, u_int note)
{
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି, ktype[128];
	u_long linenum = 0;
	ଅକ୍ଷର *cp, *cp2;
	u_int kbits;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hashed;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା s, r = 0;
	ସଂରଚନା hostkey_foreach_ଧାଡ଼ି lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, ଆକାର(lineinfo));
	ଯଦି (host == ଖାଲି && (options & HKF_WANT_MATCH) != 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		linenum++;
		ଧାଡ଼ି[strcspn(ଧାଡ଼ି, "\n")] = '\0';

		ମୁକ୍ତ(lineinfo.ଧାଡ଼ି);
		sshkey_free(lineinfo.ଚାବି);
		memset(&lineinfo, 0, ଆକାର(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.ଧାଡ଼ି = xstrdup(ଧାଡ଼ି);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = ଚାବି_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		ପାଇଁ (cp = ଧାଡ଼ି; *cp == ' ' || *cp == '\t'; cp++)
			;
		ଯଦି (!*cp || *cp == '#' || *cp == '\n') {
			ଯଦି ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				ଯଦି ((r = callback(&lineinfo, ctx)) != 0)
					ଭାଙ୍ଗ;
			}
			ଜାରି;
		}

		ଯଦି ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			ଯଦି ((options & HKF_WANT_MATCH) == 0)
				ଯାଅ bad;
			ଜାରି;
		}

		/* Find the end of the host name portion. */
		ପାଇଁ (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		ଯଦି (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			ଯଦି ((options & HKF_WANT_MATCH) == 0)
				ଯାଅ bad;
			ଜାରି;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		ଯଦି (host != ଖାଲି) {
			ଯଦି ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				ଯାଅ bad;
			}
			ଯଦି (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			ଯଦି (ip != ଖାଲି) {
				ଯଦି ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					ଯାଅ bad;
				}
				ଯଦି (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			ଯଦି ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				ଜାରି;
		}

		/* Got a match.  Skip host name and any following whitespace */
		ପାଇଁ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		ଯଦି (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			ଯାଅ bad;
		}
		lineinfo.rawkey = cp = cp2;

		ଯଦି ((options & HKF_WANT_PARSE_ଚାବି) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			ଯଦି ((lineinfo.ଚାବି = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				ଭାଙ୍ଗ;
			}
			ଯଦି (!hostfile_read_ଚାବି(&cp, &kbits, lineinfo.ଚାବି)) {
				ଯାଅ bad;
			}
			lineinfo.keytype = lineinfo.ଚାବି->type;
			lineinfo.comment = cp;
		} ଅନ୍ୟଥା {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			ଯଦି (l <= 1 || l >= ଆକାର(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				ଯାଅ bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			ଯଦି (lineinfo.keytype == ଚାବି_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				ଯାଅ bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			ପାଇଁ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			ଯଦି (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = ଚାବି_UNSPEC;
			}
			ଯଦି (lineinfo.keytype == ଚାବି_UNSPEC) {
 bad:
				sshkey_free(lineinfo.ଚାବି);
				lineinfo.ଚାବି = ଖାଲି;
				lineinfo.status = HKF_STATUS_INVALID;
				ଯଦି ((r = callback(&lineinfo, ctx)) != 0)
					ଭାଙ୍ଗ;
				ଜାରି;
			}
		}
		ଯଦି ((r = callback(&lineinfo, ctx)) != 0)
			ଭାଙ୍ଗ;
	}
	sshkey_free(lineinfo.ଚାବି);
	ମୁକ୍ତ(lineinfo.ଧାଡ଼ି);
	ମୁକ୍ତ(ଧାଡ଼ି);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hostkeys_foreach(ଅଚଳ ଅକ୍ଷର *path, hostkeys_foreach_fn *callback, ଶୂନ୍ୟ *ctx,
    ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip, u_int options, u_int note)
{
	FILE *f;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, oerrno;

	ଯଦି ((f = fopen(path, "r")) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	ଫେରନ୍ତୁ r;
}
