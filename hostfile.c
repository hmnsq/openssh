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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <netinet/in.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <resolv.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "hmac.h"
#అన్తర్భావ "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

స్థిర పూర్ణాంకం
వెలికితీయి_salt(స్థిరరాశి అక్షరం *s, u_int l, u_char *salt, కొలత_t salt_len)
{
	అక్షరం *p, *b64salt;
	u_int b64len;
	పూర్ణాంకం ret;

	ఒకవేళ (l < పరిమాణం(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		తిరిగి (-1);
	}
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(s, HASH_MAGIC, పరిమాణం(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		తిరిగి (-1);
	}
	s += పరిమాణం(HASH_MAGIC) - 1;
	l -= పరిమాణం(HASH_MAGIC) - 1;
	ఒకవేళ ((p = memchr(s, HASH_DELIM, l)) == ఖాళీ) {
		debug2("extract_salt: missing salt termination character");
		తిరిగి (-1);
	}

	b64len = p - s;
	/* Sanity check */
	ఒకవేళ (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		తిరిగి (-1);
	}
	b64salt = xmalloc(1 + b64len);
	జ్ఞాపకం_నకలు(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	విడుదల(b64salt);
	ఒకవేళ (ret == -1) {
		debug2("extract_salt: salt decode error");
		తిరిగి (-1);
	}
	ఒకవేళ (ret != (పూర్ణాంకం)ssh_hmac_బైట్లు(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_బైట్లు(SSH_DIGEST_SHA1), ret);
		తిరిగి (-1);
	}

	తిరిగి (0);
}

అక్షరం *
host_hash(స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *name_from_hostfile, u_int src_len)
{
	నిర్మాణం ssh_hmac_ctx *ctx;
	u_char salt[256], ఫలితం[256];
	అక్షరం uu_salt[512], uu_ఫలితం[512];
	అక్షరం *encoded = ఖాళీ;
	u_int len;

	len = ssh_digest_బైట్లు(SSH_DIGEST_SHA1);

	ఒకవేళ (name_from_hostfile == ఖాళీ) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} లేకపోతే {
		/* Extract salt from known host entry */
		ఒకవేళ (వెలికితీయి_salt(name_from_hostfile, src_len, salt,
		    పరిమాణం(salt)) == -1)
			తిరిగి (ఖాళీ);
	}

	ఒకవేళ ((ctx = ssh_hmac_ప్రారంభం(SSH_DIGEST_SHA1)) == ఖాళీ ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, అక్షరశ్రేణి_పొడవు(host)) < 0 ||
	    ssh_hmac_final(ctx, ఫలితం, పరిమాణం(ఫలితం)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	ఒకవేళ (__b64_ntop(salt, len, uu_salt, పరిమాణం(uu_salt)) == -1 ||
	    __b64_ntop(ఫలితం, len, uu_ఫలితం, పరిమాణం(uu_ఫలితం)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_ఫలితం);

	తిరిగి (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

పూర్ణాంకం
hostfile_read_కీలకం(అక్షరం **cpp, u_int *bitsp, నిర్మాణం sshkey *ret)
{
	అక్షరం *cp;

	/* Skip leading whitespace. */
	కొరకు (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	ఒకవేళ (sshkey_read(ret, &cp) != 0)
		తిరిగి 0;

	/* Skip trailing whitespace. */
	కొరకు (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	ఒకవేళ (bitsp != ఖాళీ)
		*bitsp = sshkey_కొలత(ret);
	తిరిగి 1;
}

స్థిర HostkeyMarker
check_markers(అక్షరం **cpp)
{
	అక్షరం marker[32], *sp, *cp = *cpp;
	పూర్ణాంకం ret = MRK_NONE;

	అయితే (*cp == '@') {
		/* Only one marker is allowed */
		ఒకవేళ (ret != MRK_NONE)
			తిరిగి MRK_ERROR;
		/* Markers are terminated by whitespace */
		ఒకవేళ ((sp = strchr(cp, ' ')) == ఖాళీ &&
		    (sp = strchr(cp, '\t')) == ఖాళీ)
			తిరిగి MRK_ERROR;
		/* Extract marker for comparison */
		ఒకవేళ (sp <= cp + 1 || sp >= cp + పరిమాణం(marker))
			తిరిగి MRK_ERROR;
		జ్ఞాపకం_నకలు(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		ఒకవేళ (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		లేకపోతే ఒకవేళ (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		లేకపోతే
			తిరిగి MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		కొరకు (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	తిరిగి ret;
}

నిర్మాణం hostkeys *
init_hostkeys(శూన్య)
{
	నిర్మాణం hostkeys *ret = xcalloc(1, పరిమాణం(*ret));

	ret->entries = ఖాళీ;
	తిరిగి ret;
}

నిర్మాణం ఎక్కించు_callback_ctx {
	స్థిరరాశి అక్షరం *host;
	u_long అంకె_loaded;
	నిర్మాణం hostkeys *hostkeys;
};

స్థిర పూర్ణాంకం
రికార్డు_hostkey(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *_ctx)
{
	నిర్మాణం ఎక్కించు_callback_ctx *ctx = (నిర్మాణం ఎక్కించు_callback_ctx *)_ctx;
	నిర్మాణం hostkeys *hostkeys = ctx->hostkeys;
	నిర్మాణం hostkey_నమోదు *tmp;

	ఒకవేళ (l->స్థితి_2 == HKF_స్థితి_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->మార్గం, l->linenum);
		తిరిగి 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->కీలకం), l->మార్గం, l->linenum);
	ఒకవేళ ((tmp = recallocarray(hostkeys->entries, hostkeys->అంకె_entries,
	    hostkeys->అంకె_entries + 1, పరిమాణం(*hostkeys->entries))) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->అంకె_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->అంకె_entries].file = xstrdup(l->మార్గం);
	hostkeys->entries[hostkeys->అంకె_entries].పంక్తి = l->linenum;
	hostkeys->entries[hostkeys->అంకె_entries].కీలకం = l->కీలకం;
	l->కీలకం = ఖాళీ; /* steal it */
	hostkeys->entries[hostkeys->అంకె_entries].marker = l->marker;
	hostkeys->entries[hostkeys->అంకె_entries].note = l->note;
	hostkeys->అంకె_entries++;
	ctx->అంకె_loaded++;

	తిరిగి 0;
}

శూన్య
ఎక్కించు_hostkeys_file(నిర్మాణం hostkeys *hostkeys, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి అక్షరం *మార్గం, FILE *f, u_int note)
{
	పూర్ణాంకం r;
	నిర్మాణం ఎక్కించు_callback_ctx ctx;

	ctx.host = host;
	ctx.అంకె_loaded = 0;
	ctx.hostkeys = hostkeys;

	ఒకవేళ ((r = hostkeys_foreach_file(మార్గం, f, రికార్డు_hostkey, &ctx, host,
	    ఖాళీ, HKF_WANT_సరిపోలిక|HKF_WANT_PARSE_కీలకం, note)) != 0) {
		ఒకవేళ (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", మార్గం);
	}
	ఒకవేళ (ctx.అంకె_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.అంకె_loaded, host);
}

శూన్య
ఎక్కించు_hostkeys(నిర్మాణం hostkeys *hostkeys, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *మార్గం,
    u_int note)
{
	FILE *f;

	ఒకవేళ ((f = fopen(మార్గం, "r")) == ఖాళీ) {
		debug_f("fopen %s: %s", మార్గం, strerror(errno));
		తిరిగి;
	}

	ఎక్కించు_hostkeys_file(hostkeys, host, మార్గం, f, note);
	fclose(f);
}

శూన్య
free_hostkeys(నిర్మాణం hostkeys *hostkeys)
{
	u_int i;

	కొరకు (i = 0; i < hostkeys->అంకె_entries; i++) {
		విడుదల(hostkeys->entries[i].host);
		విడుదల(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].కీలకం);
		explicit_bzero(hostkeys->entries + i, పరిమాణం(*hostkeys->entries));
	}
	విడుదల(hostkeys->entries);
	freezero(hostkeys, పరిమాణం(*hostkeys));
}

స్థిర పూర్ణాంకం
check_కీలకం_not_revoked(నిర్మాణం hostkeys *hostkeys, నిర్మాణం sshkey *k)
{
	పూర్ణాంకం is_cert = sshkey_is_cert(k);
	u_int i;

	కొరకు (i = 0; i < hostkeys->అంకె_entries; i++) {
		ఒకవేళ (hostkeys->entries[i].marker != MRK_REVOKE)
			కొనసాగు;
		ఒకవేళ (sshkey_equal_ప్రజా(k, hostkeys->entries[i].కీలకం))
			తిరిగి -1;
		ఒకవేళ (is_cert && k != ఖాళీ &&
		    sshkey_equal_ప్రజా(k->cert->signature_కీలకం,
		    hostkeys->entries[i].కీలకం))
			తిరిగి -1;
	}
	తిరిగి 0;
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
స్థిర Host_స్థితి
check_hostkeys_by_కీలకం_or_type(నిర్మాణం hostkeys *hostkeys,
    నిర్మాణం sshkey *k, పూర్ణాంకం keytype, పూర్ణాంకం nid, స్థిరరాశి నిర్మాణం hostkey_నమోదు **దొరికింది)
{
	u_int i;
	Host_స్థితి చివర_return = HOST_NEW;
	పూర్ణాంకం want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	ఒకవేళ (దొరికింది != ఖాళీ)
		*దొరికింది = ఖాళీ;

	కొరకు (i = 0; i < hostkeys->అంకె_entries; i++) {
		ఒకవేళ (hostkeys->entries[i].marker != want_marker)
			కొనసాగు;
		ఒకవేళ (k == ఖాళీ) {
			ఒకవేళ (hostkeys->entries[i].కీలకం->type != keytype)
				కొనసాగు;
			ఒకవేళ (nid != -1 &&
			    sshkey_type_plain(keytype) == కీలకం_ECDSA &&
			    hostkeys->entries[i].కీలకం->ecdsa_nid != nid)
				కొనసాగు;
			చివర_return = HOST_దొరికింది;
			ఒకవేళ (దొరికింది != ఖాళీ)
				*దొరికింది = hostkeys->entries + i;
			k = hostkeys->entries[i].కీలకం;
			ఆపు;
		}
		ఒకవేళ (want_cert) {
			ఒకవేళ (sshkey_equal_ప్రజా(k->cert->signature_కీలకం,
			    hostkeys->entries[i].కీలకం)) {
				/* A matching CA exists */
				చివర_return = HOST_OK;
				ఒకవేళ (దొరికింది != ఖాళీ)
					*దొరికింది = hostkeys->entries + i;
				ఆపు;
			}
		} లేకపోతే {
			ఒకవేళ (sshkey_equal(k, hostkeys->entries[i].కీలకం)) {
				చివర_return = HOST_OK;
				ఒకవేళ (దొరికింది != ఖాళీ)
					*దొరికింది = hostkeys->entries + i;
				ఆపు;
			}
			/* A non-matching key exists */
			చివర_return = HOST_మారింది;
			ఒకవేళ (దొరికింది != ఖాళీ)
				*దొరికింది = hostkeys->entries + i;
		}
	}
	ఒకవేళ (check_కీలకం_not_revoked(hostkeys, k) != 0) {
		చివర_return = HOST_REVOKED;
		ఒకవేళ (దొరికింది != ఖాళీ)
			*దొరికింది = ఖాళీ;
	}
	తిరిగి చివర_return;
}

Host_స్థితి
check_కీలకం_లోపల_hostkeys(నిర్మాణం hostkeys *hostkeys, నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి నిర్మాణం hostkey_నమోదు **దొరికింది)
{
	ఒకవేళ (కీలకం == ఖాళీ)
		fatal("no key to look up");
	తిరిగి check_hostkeys_by_కీలకం_or_type(hostkeys, కీలకం, 0, -1, దొరికింది);
}

పూర్ణాంకం
lookup_కీలకం_లోపల_hostkeys_by_type(నిర్మాణం hostkeys *hostkeys, పూర్ణాంకం keytype, పూర్ణాంకం nid,
    స్థిరరాశి నిర్మాణం hostkey_నమోదు **దొరికింది)
{
	తిరిగి (check_hostkeys_by_కీలకం_or_type(hostkeys, ఖాళీ, keytype, nid,
	    దొరికింది) == HOST_దొరికింది);
}

పూర్ణాంకం
lookup_marker_లోపల_hostkeys(నిర్మాణం hostkeys *hostkeys, పూర్ణాంకం want_marker)
{
	u_int i;

	కొరకు (i = 0; i < hostkeys->అంకె_entries; i++) {
		ఒకవేళ (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			తిరిగి 1;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
format_host_నమోదు(నిర్మాణం sshbuf *నమోదు_2, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip,
    స్థిరరాశి నిర్మాణం sshkey *కీలకం, పూర్ణాంకం store_hash)
{
	పూర్ణాంకం r, success = 0;
	అక్షరం *hashed_host = ఖాళీ, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	ఒకవేళ (store_hash) {
		ఒకవేళ ((hashed_host = host_hash(lhost, ఖాళీ, 0)) == ఖాళీ) {
			error_f("host_hash failed");
			విడుదల(lhost);
			తిరిగి 0;
		}
		ఒకవేళ ((r = sshbuf_putf(నమోదు_2, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} లేకపోతే ఒకవేళ (ip != ఖాళీ) {
		ఒకవేళ ((r = sshbuf_putf(నమోదు_2, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} లేకపోతే {
		ఒకవేళ ((r = sshbuf_putf(నమోదు_2, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	విడుదల(hashed_host);
	విడుదల(lhost);
	ఒకవేళ ((r = sshkey_format_పాఠ్యం(కీలకం, నమోదు_2)) == 0)
		success = 1;
	లేకపోతే
		error_fr(r, "sshkey_write");
	ఒకవేళ ((r = sshbuf_putf(నమోదు_2, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	ఒకవేళ (success && store_hash && ip != ఖాళీ)
		success = format_host_నమోదు(నమోదు_2, ip, ఖాళీ, కీలకం, 1);
	తిరిగి success;
}

స్థిర పూర్ణాంకం
write_host_నమోదు(FILE *f, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip,
    స్థిరరాశి నిర్మాణం sshkey *కీలకం, పూర్ణాంకం store_hash)
{
	పూర్ణాంకం r, success = 0;
	నిర్మాణం sshbuf *నమోదు_2 = ఖాళీ;

	ఒకవేళ ((నమోదు_2 = sshbuf_new()) == ఖాళీ)
		fatal_f("allocation failed");
	ఒకవేళ ((r = format_host_నమోదు(నమోదు_2, host, ip, కీలకం, store_hash)) != 1) {
		debug_f("failed to format host entry");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fwrite(sshbuf_ptr(నమోదు_2), sshbuf_len(నమోదు_2), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	success = 1;
 బహిర్గతం:
	sshbuf_free(నమోదు_2);
	తిరిగి success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
శూన్య
hostfile_create_user_ssh_dir(స్థిరరాశి అక్షరం *filename, పూర్ణాంకం notify)
{
	అక్షరం *dotsshdir = ఖాళీ, *p;
	కొలత_t len;
	నిర్మాణం stat st;

	ఒకవేళ ((p = strrchr(filename, '/')) == ఖాళీ)
		తిరిగి;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" మార్గం_SSH_USER_DIR, getuid());
	ఒకవేళ (అక్షరశ్రేణి_పొడవు(dotsshdir) > len || అక్షరశ్రేణి_పోలిక(filename, dotsshdir, len) != 0)
		వెళ్ళు బహిర్గతం; /* not ~/.ssh prefixed */
	ఒకవేళ (stat(dotsshdir, &st) == 0)
		వెళ్ళు బహిర్గతం; /* dir already exists */
	లేకపోతే ఒకవేళ (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	లేకపోతే {
#నిర్వచితమైతే WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#అయితే_ముగింపు
		ఒకవేళ (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		లేకపోతే ఒకవేళ (notify)
			logit("Created directory '%s'.", dotsshdir);
#నిర్వచితమైతే WITH_SELINUX
		ssh_selinux_setfscreatecon(ఖాళీ);
#అయితే_ముగింపు
	}
 బహిర్గతం:
	విడుదల(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
పూర్ణాంకం
కూడు_host_గమ్యం_hostfile(స్థిరరాశి అక్షరం *filename, స్థిరరాశి అక్షరం *host,
    స్థిరరాశి నిర్మాణం sshkey *కీలకం, పూర్ణాంకం store_hash)
{
	FILE *f;
	పూర్ణాంకం success, addnl = 0;

	ఒకవేళ (కీలకం == ఖాళీ)
		తిరిగి 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	ఒకవేళ ((f = fopen(filename, "a+")) == ఖాళీ)
		తిరిగి 0;
	setvbuf(f, ఖాళీ, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	ఒకవేళ (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	ఒకవేళ (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		తిరిగి 0;
	}
	success = write_host_నమోదు(f, host, ఖాళీ, కీలకం, store_hash);
	fclose(f);
	తిరిగి success;
}

నిర్మాణం host_delete_ctx {
	FILE *బహిర్గతం;
	పూర్ణాంకం quiet;
	స్థిరరాశి అక్షరం *host, *ip;
	u_int *సరిపోలిక_కీలకాలు;	/* mask of HKF_MATCH_* for this key */
	నిర్మాణం sshkey * స్థిరరాశి *కీలకాలు;
	కొలత_t nkeys;
	పూర్ణాంకం modified;
};

స్థిర పూర్ణాంకం
host_delete(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *_ctx)
{
	నిర్మాణం host_delete_ctx *ctx = (నిర్మాణం host_delete_ctx *)_ctx;
	పూర్ణాంకం loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	కొలత_t i;

	/* Don't remove CA and revocation lines */
	ఒకవేళ (l->స్థితి_2 == HKF_స్థితి_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		కొరకు (i = 0; i < ctx->nkeys; i++) {
			ఒకవేళ (!sshkey_equal(ctx->కీలకాలు[i], l->కీలకం))
				కొనసాగు;
			ctx->సరిపోలిక_కీలకాలు[i] |= l->సరిపోలిక;
			fprintf(ctx->బహిర్గతం, "%s\n", l->పంక్తి);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->కీలకం), l->మార్గం, l->linenum);
			తిరిగి 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->మార్గం, l->linenum, sshkey_type(l->కీలకం), ctx->host);
		ctx->modified = 1;
		తిరిగి 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	ఒకవేళ (l->స్థితి_2 == HKF_స్థితి_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->మార్గం, l->linenum);
	}
	fprintf(ctx->బహిర్గతం, "%s\n", l->పంక్తి);
	తిరిగి 0;
}

పూర్ణాంకం
hostfile_replace_entries(స్థిరరాశి అక్షరం *filename, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip,
    నిర్మాణం sshkey **కీలకాలు, కొలత_t nkeys, పూర్ణాంకం store_hash, పూర్ణాంకం quiet, పూర్ణాంకం hash_alg)
{
	పూర్ణాంకం r, fd, oerrno = 0;
	పూర్ణాంకం loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	నిర్మాణం host_delete_ctx ctx;
	అక్షరం *fp = ఖాళీ, *తాత్కాలిక = ఖాళీ, *వెనుక = ఖాళీ;
	స్థిరరాశి అక్షరం *what;
	బహుళకం_t omask;
	కొలత_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	ఒకవేళ ((ctx.సరిపోలిక_కీలకాలు = సున్నా_జ్ఞాపకం_ఇవ్వు(nkeys, పరిమాణం(*ctx.సరిపోలిక_కీలకాలు))) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ctx.కీలకాలు = కీలకాలు;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	ఒకవేళ ((r = asprintf(&తాత్కాలిక, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&వెనుక, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు fail;
	}

	ఒకవేళ ((fd = mkstemp(తాత్కాలిక)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		వెళ్ళు fail;
	}
	ఒకవేళ ((ctx.బహిర్గతం = fdopen(fd, "w")) == ఖాళీ) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		వెళ్ళు fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	ఒకవేళ ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_కీలకం, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		వెళ్ళు fail;
	}

	/* Re-add the requested keys */
	want = HKF_సరిపోలిక_HOST | (ip == ఖాళీ ? 0 : HKF_సరిపోలిక_IP);
	కొరకు (i = 0; i < nkeys; i++) {
		ఒకవేళ (కీలకాలు[i] == ఖాళీ || (want & ctx.సరిపోలిక_కీలకాలు[i]) == want)
			కొనసాగు;
		ఒకవేళ ((fp = sshkey_fingerprint(కీలకాలు[i], hash_alg,
		    SSH_FP_DEFAULT)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు fail;
		}
		/* write host/ip */
		what = "";
		ఒకవేళ (ctx.సరిపోలిక_కీలకాలు[i] == 0) {
			what = "Adding new key";
			ఒకవేళ (!write_host_నమోదు(ctx.బహిర్గతం, host, ip,
			    కీలకాలు[i], store_hash)) {
				r = SSH_ERR_అంతర్గత_ERROR;
				వెళ్ళు fail;
			}
		} లేకపోతే ఒకవేళ ((want & ~ctx.సరిపోలిక_కీలకాలు[i]) == HKF_సరిపోలిక_HOST) {
			what = "Fixing match (hostname)";
			ఒకవేళ (!write_host_నమోదు(ctx.బహిర్గతం, host, ఖాళీ,
			    కీలకాలు[i], store_hash)) {
				r = SSH_ERR_అంతర్గత_ERROR;
				వెళ్ళు fail;
			}
		} లేకపోతే ఒకవేళ ((want & ~ctx.సరిపోలిక_కీలకాలు[i]) == HKF_సరిపోలిక_IP) {
			what = "Fixing match (address)";
			ఒకవేళ (!write_host_నమోదు(ctx.బహిర్గతం, ip, ఖాళీ,
			    కీలకాలు[i], store_hash)) {
				r = SSH_ERR_అంతర్గత_ERROR;
				వెళ్ళు fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == ఖాళీ ? "" : ",", ip == ఖాళీ ? "" : ip, filename,
		    sshkey_ssh_name(కీలకాలు[i]), fp);
		విడుదల(fp);
		fp = ఖాళీ;
		ctx.modified = 1;
	}
	fclose(ctx.బహిర్గతం);
	ctx.బహిర్గతం = ఖాళీ;

	ఒకవేళ (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		ఒకవేళ (unlink(వెనుక) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", వెనుక, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			వెళ్ళు fail;
		}
		ఒకవేళ (link(filename, వెనుక) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    వెనుక, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			వెళ్ళు fail;
		}
		ఒకవేళ (rename(తాత్కాలిక, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", తాత్కాలిక,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			వెళ్ళు fail;
		}
	} లేకపోతే {
		/* No changes made; just delete the temporary file */
		ఒకవేళ (unlink(తాత్కాలిక) != 0)
			error_f("unlink \"%s\": %s", తాత్కాలిక, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	ఒకవేళ (తాత్కాలిక != ఖాళీ && r != 0)
		unlink(తాత్కాలిక);
	విడుదల(తాత్కాలిక);
	విడుదల(వెనుక);
	విడుదల(fp);
	ఒకవేళ (ctx.బహిర్గతం != ఖాళీ)
		fclose(ctx.బహిర్గతం);
	విడుదల(ctx.సరిపోలిక_కీలకాలు);
	umask(omask);
	ఒకవేళ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	తిరిగి r;
}

స్థిర పూర్ణాంకం
సరిపోలిక_maybe_hashed(స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *పేర్లు, పూర్ణాంకం *was_hashed)
{
	పూర్ణాంకం hashed = *పేర్లు == HASH_DELIM, ret;
	అక్షరం *hashed_host = ఖాళీ;
	కొలత_t nlen = అక్షరశ్రేణి_పొడవు(పేర్లు);

	ఒకవేళ (was_hashed != ఖాళీ)
		*was_hashed = hashed;
	ఒకవేళ (hashed) {
		ఒకవేళ ((hashed_host = host_hash(host, పేర్లు, nlen)) == ఖాళీ)
			తిరిగి -1;
		ret = (nlen == అక్షరశ్రేణి_పొడవు(hashed_host) &&
		    అక్షరశ్రేణి_పోలిక(hashed_host, పేర్లు, nlen) == 0);
		విడుదల(hashed_host);
		తిరిగి ret;
	}
	తిరిగి సరిపోలిక_hostname(host, పేర్లు) == 1;
}

పూర్ణాంకం
hostkeys_foreach_file(స్థిరరాశి అక్షరం *మార్గం, FILE *f, hostkeys_foreach_fn *callback,
    శూన్య *ctx, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip, u_int options, u_int note)
{
	అక్షరం *పంక్తి = ఖాళీ, ktype[128];
	u_long linenum = 0;
	అక్షరం *cp, *cp2;
	u_int kbits;
	పూర్ణాంకం hashed;
	పూర్ణాంకం s, r = 0;
	నిర్మాణం hostkey_foreach_పంక్తి lineinfo;
	కొలత_t linesize = 0, l;

	memset(&lineinfo, 0, పరిమాణం(lineinfo));
	ఒకవేళ (host == ఖాళీ && (options & HKF_WANT_సరిపోలిక) != 0)
		తిరిగి SSH_ERR_INVALID_వాదం;

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		linenum++;
		పంక్తి[strcspn(పంక్తి, "\n")] = '\0';

		విడుదల(lineinfo.పంక్తి);
		sshkey_free(lineinfo.కీలకం);
		memset(&lineinfo, 0, పరిమాణం(lineinfo));
		lineinfo.మార్గం = మార్గం;
		lineinfo.linenum = linenum;
		lineinfo.పంక్తి = xstrdup(పంక్తి);
		lineinfo.marker = MRK_NONE;
		lineinfo.స్థితి_2 = HKF_స్థితి_OK;
		lineinfo.keytype = కీలకం_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		కొరకు (cp = పంక్తి; *cp == ' ' || *cp == '\t'; cp++)
			;
		ఒకవేళ (!*cp || *cp == '#' || *cp == '\n') {
			ఒకవేళ ((options & HKF_WANT_సరిపోలిక) == 0) {
				lineinfo.స్థితి_2 = HKF_స్థితి_COMMENT;
				ఒకవేళ ((r = callback(&lineinfo, ctx)) != 0)
					ఆపు;
			}
			కొనసాగు;
		}

		ఒకవేళ ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", మార్గం, linenum);
			ఒకవేళ ((options & HKF_WANT_సరిపోలిక) == 0)
				వెళ్ళు bad;
			కొనసాగు;
		}

		/* Find the end of the host name portion. */
		కొరకు (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		ఒకవేళ (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", మార్గం, linenum);
			ఒకవేళ ((options & HKF_WANT_సరిపోలిక) == 0)
				వెళ్ళు bad;
			కొనసాగు;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		ఒకవేళ (host != ఖాళీ) {
			ఒకవేళ ((s = సరిపోలిక_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    మార్గం, linenum, lineinfo.hosts);
				వెళ్ళు bad;
			}
			ఒకవేళ (s == 1) {
				lineinfo.స్థితి_2 = HKF_స్థితి_MATCHED;
				lineinfo.సరిపోలిక |= HKF_సరిపోలిక_HOST |
				    (hashed ? HKF_సరిపోలిక_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			ఒకవేళ (ip != ఖాళీ) {
				ఒకవేళ ((s = సరిపోలిక_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", మార్గం, linenum,
					    lineinfo.hosts);
					వెళ్ళు bad;
				}
				ఒకవేళ (s == 1) {
					lineinfo.స్థితి_2 = HKF_స్థితి_MATCHED;
					lineinfo.సరిపోలిక |= HKF_సరిపోలిక_IP |
					    (hashed ? HKF_సరిపోలిక_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			ఒకవేళ ((options & HKF_WANT_సరిపోలిక) != 0 &&
			    lineinfo.స్థితి_2 != HKF_స్థితి_MATCHED)
				కొనసాగు;
		}

		/* Got a match.  Skip host name and any following whitespace */
		కొరకు (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		ఒకవేళ (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    మార్గం, linenum);
			వెళ్ళు bad;
		}
		lineinfo.rawkey = cp = cp2;

		ఒకవేళ ((options & HKF_WANT_PARSE_కీలకం) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			ఒకవేళ ((lineinfo.కీలకం = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				ఆపు;
			}
			ఒకవేళ (!hostfile_read_కీలకం(&cp, &kbits, lineinfo.కీలకం)) {
				వెళ్ళు bad;
			}
			lineinfo.keytype = lineinfo.కీలకం->type;
			lineinfo.comment = cp;
		} లేకపోతే {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			ఒకవేళ (l <= 1 || l >= పరిమాణం(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				వెళ్ళు bad;
			జ్ఞాపకం_నకలు(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			ఒకవేళ (lineinfo.keytype == కీలకం_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				వెళ్ళు bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			కొరకు (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			ఒకవేళ (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    మార్గం, linenum);
				lineinfo.keytype = కీలకం_UNSPEC;
			}
			ఒకవేళ (lineinfo.keytype == కీలకం_UNSPEC) {
 bad:
				sshkey_free(lineinfo.కీలకం);
				lineinfo.కీలకం = ఖాళీ;
				lineinfo.స్థితి_2 = HKF_స్థితి_INVALID;
				ఒకవేళ ((r = callback(&lineinfo, ctx)) != 0)
					ఆపు;
				కొనసాగు;
			}
		}
		ఒకవేళ ((r = callback(&lineinfo, ctx)) != 0)
			ఆపు;
	}
	sshkey_free(lineinfo.కీలకం);
	విడుదల(lineinfo.పంక్తి);
	విడుదల(పంక్తి);
	తిరిగి r;
}

పూర్ణాంకం
hostkeys_foreach(స్థిరరాశి అక్షరం *మార్గం, hostkeys_foreach_fn *callback, శూన్య *ctx,
    స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip, u_int options, u_int note)
{
	FILE *f;
	పూర్ణాంకం r, oerrno;

	ఒకవేళ ((f = fopen(మార్గం, "r")) == ఖాళీ)
		తిరిగి SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", మార్గం);
	r = hostkeys_foreach_file(మార్గం, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	తిరిగి r;
}
