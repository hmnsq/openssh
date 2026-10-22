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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <netinet/in.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <resolv.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "hmac.h"
#অন্তর্ভাব "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

স্থির পূর্ণসংখ্যা
extract_salt(ধ্রুবক অক্ষর *s, u_int l, u_char *salt, আকার_t salt_len)
{
	অক্ষর *p, *b64salt;
	u_int b64len;
	পূর্ণসংখ্যা ret;

	যদি (l < আকার(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		ফেরত (-1);
	}
	যদি (strncmp(s, HASH_MAGIC, আকার(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		ফেরত (-1);
	}
	s += আকার(HASH_MAGIC) - 1;
	l -= আকার(HASH_MAGIC) - 1;
	যদি ((p = memchr(s, HASH_DELIM, l)) == ফাঁকা) {
		debug2("extract_salt: missing salt termination character");
		ফেরত (-1);
	}

	b64len = p - s;
	/* Sanity check */
	যদি (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		ফেরত (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	মুক্ত(b64salt);
	যদি (ret == -1) {
		debug2("extract_salt: salt decode error");
		ফেরত (-1);
	}
	যদি (ret != (পূর্ণসংখ্যা)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		ফেরত (-1);
	}

	ফেরত (0);
}

অক্ষর *
host_hash(ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *name_from_hostfile, u_int src_len)
{
	কাঠামো ssh_hmac_ctx *ctx;
	u_char salt[256], ফলাফল[256];
	অক্ষর uu_salt[512], uu_ফলাফল[512];
	অক্ষর *encoded = ফাঁকা;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	যদি (name_from_hostfile == ফাঁকা) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} অন্যথা {
		/* Extract salt from known host entry */
		যদি (extract_salt(name_from_hostfile, src_len, salt,
		    আকার(salt)) == -1)
			ফেরত (ফাঁকা);
	}

	যদি ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == ফাঁকা ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, ফলাফল, আকার(ফলাফল)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	যদি (__b64_ntop(salt, len, uu_salt, আকার(uu_salt)) == -1 ||
	    __b64_ntop(ফলাফল, len, uu_ফলাফল, আকার(uu_ফলাফল)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_ফলাফল);

	ফেরত (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

পূর্ণসংখ্যা
hostfile_read_চাবি(অক্ষর **cpp, u_int *bitsp, কাঠামো sshkey *ret)
{
	অক্ষর *cp;

	/* Skip leading whitespace. */
	জন্য (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	যদি (sshkey_read(ret, &cp) != 0)
		ফেরত 0;

	/* Skip trailing whitespace. */
	জন্য (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	যদি (bitsp != ফাঁকা)
		*bitsp = sshkey_আকার(ret);
	ফেরত 1;
}

স্থির HostkeyMarker
check_markers(অক্ষর **cpp)
{
	অক্ষর marker[32], *sp, *cp = *cpp;
	পূর্ণসংখ্যা ret = MRK_NONE;

	যখন (*cp == '@') {
		/* Only one marker is allowed */
		যদি (ret != MRK_NONE)
			ফেরত MRK_ERROR;
		/* Markers are terminated by whitespace */
		যদি ((sp = strchr(cp, ' ')) == ফাঁকা &&
		    (sp = strchr(cp, '\t')) == ফাঁকা)
			ফেরত MRK_ERROR;
		/* Extract marker for comparison */
		যদি (sp <= cp + 1 || sp >= cp + আকার(marker))
			ফেরত MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		যদি (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		অন্যথা যদি (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		অন্যথা
			ফেরত MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		জন্য (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	ফেরত ret;
}

কাঠামো hostkeys *
init_hostkeys(শূন্য)
{
	কাঠামো hostkeys *ret = xcalloc(1, আকার(*ret));

	ret->entries = ফাঁকা;
	ফেরত ret;
}

কাঠামো load_callback_ctx {
	ধ্রুবক অক্ষর *host;
	u_long অঙ্ক_loaded;
	কাঠামো hostkeys *hostkeys;
};

স্থির পূর্ণসংখ্যা
record_hostkey(কাঠামো hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	কাঠামো load_callback_ctx *ctx = (কাঠামো load_callback_ctx *)_ctx;
	কাঠামো hostkeys *hostkeys = ctx->hostkeys;
	কাঠামো hostkey_entry *tmp;

	যদি (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		ফেরত 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->চাবি), l->path, l->linenum);
	যদি ((tmp = recallocarray(hostkeys->entries, hostkeys->অঙ্ক_entries,
	    hostkeys->অঙ্ক_entries + 1, আকার(*hostkeys->entries))) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->অঙ্ক_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->অঙ্ক_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->অঙ্ক_entries].সারি = l->linenum;
	hostkeys->entries[hostkeys->অঙ্ক_entries].চাবি = l->চাবি;
	l->চাবি = ফাঁকা; /* steal it */
	hostkeys->entries[hostkeys->অঙ্ক_entries].marker = l->marker;
	hostkeys->entries[hostkeys->অঙ্ক_entries].note = l->note;
	hostkeys->অঙ্ক_entries++;
	ctx->অঙ্ক_loaded++;

	ফেরত 0;
}

শূন্য
load_hostkeys_file(কাঠামো hostkeys *hostkeys, ধ্রুবক অক্ষর *host,
    ধ্রুবক অক্ষর *path, FILE *f, u_int note)
{
	পূর্ণসংখ্যা r;
	কাঠামো load_callback_ctx ctx;

	ctx.host = host;
	ctx.অঙ্ক_loaded = 0;
	ctx.hostkeys = hostkeys;

	যদি ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    ফাঁকা, HKF_WANT_MATCH|HKF_WANT_PARSE_চাবি, note)) != 0) {
		যদি (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	যদি (ctx.অঙ্ক_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.অঙ্ক_loaded, host);
}

শূন্য
load_hostkeys(কাঠামো hostkeys *hostkeys, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *path,
    u_int note)
{
	FILE *f;

	যদি ((f = fopen(path, "r")) == ফাঁকা) {
		debug_f("fopen %s: %s", path, strerror(errno));
		ফেরত;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

শূন্য
free_hostkeys(কাঠামো hostkeys *hostkeys)
{
	u_int i;

	জন্য (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		মুক্ত(hostkeys->entries[i].host);
		মুক্ত(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].চাবি);
		explicit_bzero(hostkeys->entries + i, আকার(*hostkeys->entries));
	}
	মুক্ত(hostkeys->entries);
	freezero(hostkeys, আকার(*hostkeys));
}

স্থির পূর্ণসংখ্যা
check_চাবি_not_revoked(কাঠামো hostkeys *hostkeys, কাঠামো sshkey *k)
{
	পূর্ণসংখ্যা is_cert = sshkey_is_cert(k);
	u_int i;

	জন্য (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		যদি (hostkeys->entries[i].marker != MRK_REVOKE)
			চালু;
		যদি (sshkey_equal_public(k, hostkeys->entries[i].চাবি))
			ফেরত -1;
		যদি (is_cert && k != ফাঁকা &&
		    sshkey_equal_public(k->cert->signature_চাবি,
		    hostkeys->entries[i].চাবি))
			ফেরত -1;
	}
	ফেরত 0;
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
স্থির HostStatus
check_hostkeys_by_চাবি_or_type(কাঠামো hostkeys *hostkeys,
    কাঠামো sshkey *k, পূর্ণসংখ্যা keytype, পূর্ণসংখ্যা nid, ধ্রুবক কাঠামো hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	পূর্ণসংখ্যা want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	যদি (found != ফাঁকা)
		*found = ফাঁকা;

	জন্য (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		যদি (hostkeys->entries[i].marker != want_marker)
			চালু;
		যদি (k == ফাঁকা) {
			যদি (hostkeys->entries[i].চাবি->type != keytype)
				চালু;
			যদি (nid != -1 &&
			    sshkey_type_plain(keytype) == চাবি_ECDSA &&
			    hostkeys->entries[i].চাবি->ecdsa_nid != nid)
				চালু;
			end_return = HOST_FOUND;
			যদি (found != ফাঁকা)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].চাবি;
			বিরতি;
		}
		যদি (want_cert) {
			যদি (sshkey_equal_public(k->cert->signature_চাবি,
			    hostkeys->entries[i].চাবি)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				যদি (found != ফাঁকা)
					*found = hostkeys->entries + i;
				বিরতি;
			}
		} অন্যথা {
			যদি (sshkey_equal(k, hostkeys->entries[i].চাবি)) {
				end_return = HOST_OK;
				যদি (found != ফাঁকা)
					*found = hostkeys->entries + i;
				বিরতি;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			যদি (found != ফাঁকা)
				*found = hostkeys->entries + i;
		}
	}
	যদি (check_চাবি_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		যদি (found != ফাঁকা)
			*found = ফাঁকা;
	}
	ফেরত end_return;
}

HostStatus
check_চাবি_in_hostkeys(কাঠামো hostkeys *hostkeys, কাঠামো sshkey *চাবি,
    ধ্রুবক কাঠামো hostkey_entry **found)
{
	যদি (চাবি == ফাঁকা)
		fatal("no key to look up");
	ফেরত check_hostkeys_by_চাবি_or_type(hostkeys, চাবি, 0, -1, found);
}

পূর্ণসংখ্যা
lookup_চাবি_in_hostkeys_by_type(কাঠামো hostkeys *hostkeys, পূর্ণসংখ্যা keytype, পূর্ণসংখ্যা nid,
    ধ্রুবক কাঠামো hostkey_entry **found)
{
	ফেরত (check_hostkeys_by_চাবি_or_type(hostkeys, ফাঁকা, keytype, nid,
	    found) == HOST_FOUND);
}

পূর্ণসংখ্যা
lookup_marker_in_hostkeys(কাঠামো hostkeys *hostkeys, পূর্ণসংখ্যা want_marker)
{
	u_int i;

	জন্য (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		যদি (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			ফেরত 1;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
format_host_entry(কাঠামো sshbuf *entry, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip,
    ধ্রুবক কাঠামো sshkey *চাবি, পূর্ণসংখ্যা store_hash)
{
	পূর্ণসংখ্যা r, success = 0;
	অক্ষর *hashed_host = ফাঁকা, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	যদি (store_hash) {
		যদি ((hashed_host = host_hash(lhost, ফাঁকা, 0)) == ফাঁকা) {
			error_f("host_hash failed");
			মুক্ত(lhost);
			ফেরত 0;
		}
		যদি ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} অন্যথা যদি (ip != ফাঁকা) {
		যদি ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} অন্যথা {
		যদি ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	মুক্ত(hashed_host);
	মুক্ত(lhost);
	যদি ((r = sshkey_format_text(চাবি, entry)) == 0)
		success = 1;
	অন্যথা
		error_fr(r, "sshkey_write");
	যদি ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	যদি (success && store_hash && ip != ফাঁকা)
		success = format_host_entry(entry, ip, ফাঁকা, চাবি, 1);
	ফেরত success;
}

স্থির পূর্ণসংখ্যা
write_host_entry(FILE *f, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip,
    ধ্রুবক কাঠামো sshkey *চাবি, পূর্ণসংখ্যা store_hash)
{
	পূর্ণসংখ্যা r, success = 0;
	কাঠামো sshbuf *entry = ফাঁকা;

	যদি ((entry = sshbuf_new()) == ফাঁকা)
		fatal_f("allocation failed");
	যদি ((r = format_host_entry(entry, host, ip, চাবি, store_hash)) != 1) {
		debug_f("failed to format host entry");
		যাও out;
	}
	যদি ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		যাও out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	ফেরত success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
শূন্য
hostfile_create_user_ssh_dir(ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা notify)
{
	অক্ষর *dotsshdir = ফাঁকা, *p;
	আকার_t len;
	কাঠামো stat st;

	যদি ((p = strrchr(filename, '/')) == ফাঁকা)
		ফেরত;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	যদি (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		যাও out; /* not ~/.ssh prefixed */
	যদি (stat(dotsshdir, &st) == 0)
		যাও out; /* dir already exists */
	অন্যথা যদি (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	অন্যথা {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		যদি (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		অন্যথা যদি (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(ফাঁকা);
#endif
	}
 out:
	মুক্ত(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
পূর্ণসংখ্যা
add_host_to_hostfile(ধ্রুবক অক্ষর *filename, ধ্রুবক অক্ষর *host,
    ধ্রুবক কাঠামো sshkey *চাবি, পূর্ণসংখ্যা store_hash)
{
	FILE *f;
	পূর্ণসংখ্যা success, addnl = 0;

	যদি (চাবি == ফাঁকা)
		ফেরত 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	যদি ((f = fopen(filename, "a+")) == ফাঁকা)
		ফেরত 0;
	setvbuf(f, ফাঁকা, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	যদি (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	যদি (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		ফেরত 0;
	}
	success = write_host_entry(f, host, ফাঁকা, চাবি, store_hash);
	fclose(f);
	ফেরত success;
}

কাঠামো host_delete_ctx {
	FILE *out;
	পূর্ণসংখ্যা quiet;
	ধ্রুবক অক্ষর *host, *ip;
	u_int *match_চাবিগুলি;	/* mask of HKF_MATCH_* for this key */
	কাঠামো sshkey * ধ্রুবক *চাবিগুলি;
	আকার_t nkeys;
	পূর্ণসংখ্যা modified;
};

স্থির পূর্ণসংখ্যা
host_delete(কাঠামো hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	কাঠামো host_delete_ctx *ctx = (কাঠামো host_delete_ctx *)_ctx;
	পূর্ণসংখ্যা loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	আকার_t i;

	/* Don't remove CA and revocation lines */
	যদি (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		জন্য (i = 0; i < ctx->nkeys; i++) {
			যদি (!sshkey_equal(ctx->চাবিগুলি[i], l->চাবি))
				চালু;
			ctx->match_চাবিগুলি[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->সারি);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->চাবি), l->path, l->linenum);
			ফেরত 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->চাবি), ctx->host);
		ctx->modified = 1;
		ফেরত 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	যদি (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->সারি);
	ফেরত 0;
}

পূর্ণসংখ্যা
hostfile_replace_entries(ধ্রুবক অক্ষর *filename, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip,
    কাঠামো sshkey **চাবিগুলি, আকার_t nkeys, পূর্ণসংখ্যা store_hash, পূর্ণসংখ্যা quiet, পূর্ণসংখ্যা hash_alg)
{
	পূর্ণসংখ্যা r, fd, oerrno = 0;
	পূর্ণসংখ্যা loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	কাঠামো host_delete_ctx ctx;
	অক্ষর *fp = ফাঁকা, *অস্থায়ী = ফাঁকা, *back = ফাঁকা;
	ধ্রুবক অক্ষর *what;
	mode_t omask;
	আকার_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, আকার(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	যদি ((ctx.match_চাবিগুলি = calloc(nkeys, আকার(*ctx.match_চাবিগুলি))) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	ctx.চাবিগুলি = চাবিগুলি;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	যদি ((r = asprintf(&অস্থায়ী, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও fail;
	}

	যদি ((fd = mkstemp(অস্থায়ী)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		যাও fail;
	}
	যদি ((ctx.out = fdopen(fd, "w")) == ফাঁকা) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		যাও fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	যদি ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_চাবি, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		যাও fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == ফাঁকা ? 0 : HKF_MATCH_IP);
	জন্য (i = 0; i < nkeys; i++) {
		যদি (চাবিগুলি[i] == ফাঁকা || (want & ctx.match_চাবিগুলি[i]) == want)
			চালু;
		যদি ((fp = sshkey_fingerprint(চাবিগুলি[i], hash_alg,
		    SSH_FP_DEFAULT)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও fail;
		}
		/* write host/ip */
		what = "";
		যদি (ctx.match_চাবিগুলি[i] == 0) {
			what = "Adding new key";
			যদি (!write_host_entry(ctx.out, host, ip,
			    চাবিগুলি[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				যাও fail;
			}
		} অন্যথা যদি ((want & ~ctx.match_চাবিগুলি[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			যদি (!write_host_entry(ctx.out, host, ফাঁকা,
			    চাবিগুলি[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				যাও fail;
			}
		} অন্যথা যদি ((want & ~ctx.match_চাবিগুলি[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			যদি (!write_host_entry(ctx.out, ip, ফাঁকা,
			    চাবিগুলি[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				যাও fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == ফাঁকা ? "" : ",", ip == ফাঁকা ? "" : ip, filename,
		    sshkey_ssh_name(চাবিগুলি[i]), fp);
		মুক্ত(fp);
		fp = ফাঁকা;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = ফাঁকা;

	যদি (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		যদি (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			যাও fail;
		}
		যদি (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			যাও fail;
		}
		যদি (rename(অস্থায়ী, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", অস্থায়ী,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			যাও fail;
		}
	} অন্যথা {
		/* No changes made; just delete the temporary file */
		যদি (unlink(অস্থায়ী) != 0)
			error_f("unlink \"%s\": %s", অস্থায়ী, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	যদি (অস্থায়ী != ফাঁকা && r != 0)
		unlink(অস্থায়ী);
	মুক্ত(অস্থায়ী);
	মুক্ত(back);
	মুক্ত(fp);
	যদি (ctx.out != ফাঁকা)
		fclose(ctx.out);
	মুক্ত(ctx.match_চাবিগুলি);
	umask(omask);
	যদি (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
match_maybe_hashed(ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *names, পূর্ণসংখ্যা *was_hashed)
{
	পূর্ণসংখ্যা hashed = *names == HASH_DELIM, ret;
	অক্ষর *hashed_host = ফাঁকা;
	আকার_t nlen = strlen(names);

	যদি (was_hashed != ফাঁকা)
		*was_hashed = hashed;
	যদি (hashed) {
		যদি ((hashed_host = host_hash(host, names, nlen)) == ফাঁকা)
			ফেরত -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		মুক্ত(hashed_host);
		ফেরত ret;
	}
	ফেরত match_hostname(host, names) == 1;
}

পূর্ণসংখ্যা
hostkeys_foreach_file(ধ্রুবক অক্ষর *path, FILE *f, hostkeys_foreach_fn *callback,
    শূন্য *ctx, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip, u_int options, u_int note)
{
	অক্ষর *সারি = ফাঁকা, ktype[128];
	u_long linenum = 0;
	অক্ষর *cp, *cp2;
	u_int kbits;
	পূর্ণসংখ্যা hashed;
	পূর্ণসংখ্যা s, r = 0;
	কাঠামো hostkey_foreach_সারি lineinfo;
	আকার_t linesize = 0, l;

	memset(&lineinfo, 0, আকার(lineinfo));
	যদি (host == ফাঁকা && (options & HKF_WANT_MATCH) != 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যখন (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		সারি[strcspn(সারি, "\n")] = '\0';

		মুক্ত(lineinfo.সারি);
		sshkey_free(lineinfo.চাবি);
		memset(&lineinfo, 0, আকার(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.সারি = xstrdup(সারি);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = চাবি_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		জন্য (cp = সারি; *cp == ' ' || *cp == '\t'; cp++)
			;
		যদি (!*cp || *cp == '#' || *cp == '\n') {
			যদি ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				যদি ((r = callback(&lineinfo, ctx)) != 0)
					বিরতি;
			}
			চালু;
		}

		যদি ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			যদি ((options & HKF_WANT_MATCH) == 0)
				যাও bad;
			চালু;
		}

		/* Find the end of the host name portion. */
		জন্য (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		যদি (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			যদি ((options & HKF_WANT_MATCH) == 0)
				যাও bad;
			চালু;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		যদি (host != ফাঁকা) {
			যদি ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				যাও bad;
			}
			যদি (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			যদি (ip != ফাঁকা) {
				যদি ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					যাও bad;
				}
				যদি (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			যদি ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				চালু;
		}

		/* Got a match.  Skip host name and any following whitespace */
		জন্য (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		যদি (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			যাও bad;
		}
		lineinfo.rawkey = cp = cp2;

		যদি ((options & HKF_WANT_PARSE_চাবি) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			যদি ((lineinfo.চাবি = sshkey_new(চাবি_UNSPEC)) == ফাঁকা) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				বিরতি;
			}
			যদি (!hostfile_read_চাবি(&cp, &kbits, lineinfo.চাবি)) {
				যাও bad;
			}
			lineinfo.keytype = lineinfo.চাবি->type;
			lineinfo.comment = cp;
		} অন্যথা {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			যদি (l <= 1 || l >= আকার(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				যাও bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			যদি (lineinfo.keytype == চাবি_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				যাও bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			জন্য (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			যদি (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = চাবি_UNSPEC;
			}
			যদি (lineinfo.keytype == চাবি_UNSPEC) {
 bad:
				sshkey_free(lineinfo.চাবি);
				lineinfo.চাবি = ফাঁকা;
				lineinfo.status = HKF_STATUS_INVALID;
				যদি ((r = callback(&lineinfo, ctx)) != 0)
					বিরতি;
				চালু;
			}
		}
		যদি ((r = callback(&lineinfo, ctx)) != 0)
			বিরতি;
	}
	sshkey_free(lineinfo.চাবি);
	মুক্ত(lineinfo.সারি);
	মুক্ত(সারি);
	ফেরত r;
}

পূর্ণসংখ্যা
hostkeys_foreach(ধ্রুবক অক্ষর *path, hostkeys_foreach_fn *callback, শূন্য *ctx,
    ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ip, u_int options, u_int note)
{
	FILE *f;
	পূর্ণসংখ্যা r, oerrno;

	যদি ((f = fopen(path, "r")) == ফাঁকা)
		ফেরত SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	ফেরত r;
}
