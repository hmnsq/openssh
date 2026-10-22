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

স্থির পূর্ণাঙ্ক
extract_salt(ধ্রুব বর্ণ *s, u_int l, u_char *salt, size_t salt_len)
{
	বর্ণ *p, *b64salt;
	u_int b64len;
	পূর্ণাঙ্ক ret;

	যদি (l < পরিমাণ(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		প্রত্যাগম (-1);
	}
	যদি (strncmp(s, HASH_MAGIC, পরিমাণ(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		প্রত্যাগম (-1);
	}
	s += পরিমাণ(HASH_MAGIC) - 1;
	l -= পরিমাণ(HASH_MAGIC) - 1;
	যদি ((p = memchr(s, HASH_DELIM, l)) == রিক্ত) {
		debug2("extract_salt: missing salt termination character");
		প্রত্যাগম (-1);
	}

	b64len = p - s;
	/* Sanity check */
	যদি (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		প্রত্যাগম (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	মুক্ত(b64salt);
	যদি (ret == -1) {
		debug2("extract_salt: salt decode error");
		প্রত্যাগম (-1);
	}
	যদি (ret != (পূর্ণাঙ্ক)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		প্রত্যাগম (-1);
	}

	প্রত্যাগম (0);
}

বর্ণ *
host_hash(ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *name_from_hostfile, u_int src_len)
{
	সংরচনা ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	বর্ণ uu_salt[512], uu_result[512];
	বর্ণ *encoded = রিক্ত;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	যদি (name_from_hostfile == রিক্ত) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} অন্যথা {
		/* Extract salt from known host entry */
		যদি (extract_salt(name_from_hostfile, src_len, salt,
		    পরিমাণ(salt)) == -1)
			প্রত্যাগম (রিক্ত);
	}

	যদি ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == রিক্ত ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, পরিমাণ(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	যদি (__b64_ntop(salt, len, uu_salt, পরিমাণ(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, পরিমাণ(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	প্রত্যাগম (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

পূর্ণাঙ্ক
hostfile_read_চাবি(বর্ণ **cpp, u_int *bitsp, সংরচনা sshkey *ret)
{
	বর্ণ *cp;

	/* Skip leading whitespace. */
	প্রতি (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	যদি (sshkey_read(ret, &cp) != 0)
		প্রত্যাগম 0;

	/* Skip trailing whitespace. */
	প্রতি (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	যদি (bitsp != রিক্ত)
		*bitsp = sshkey_size(ret);
	প্রত্যাগম 1;
}

স্থির HostkeyMarker
check_markers(বর্ণ **cpp)
{
	বর্ণ marker[32], *sp, *cp = *cpp;
	পূর্ণাঙ্ক ret = MRK_NONE;

	যাবত্ (*cp == '@') {
		/* Only one marker is allowed */
		যদি (ret != MRK_NONE)
			প্রত্যাগম MRK_ERROR;
		/* Markers are terminated by whitespace */
		যদি ((sp = strchr(cp, ' ')) == রিক্ত &&
		    (sp = strchr(cp, '\t')) == রিক্ত)
			প্রত্যাগম MRK_ERROR;
		/* Extract marker for comparison */
		যদি (sp <= cp + 1 || sp >= cp + পরিমাণ(marker))
			প্রত্যাগম MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		যদি (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		অন্যথা যদি (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		অন্যথা
			প্রত্যাগম MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		প্রতি (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	প্রত্যাগম ret;
}

সংরচনা hostkeys *
init_hostkeys(শূন্য)
{
	সংরচনা hostkeys *ret = xcalloc(1, পরিমাণ(*ret));

	ret->entries = রিক্ত;
	প্রত্যাগম ret;
}

সংরচনা load_callback_ctx {
	ধ্রুব বর্ণ *host;
	u_long অঙ্ক_loaded;
	সংরচনা hostkeys *hostkeys;
};

স্থির পূর্ণাঙ্ক
record_hostkey(সংরচনা hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	সংরচনা load_callback_ctx *ctx = (সংরচনা load_callback_ctx *)_ctx;
	সংরচনা hostkeys *hostkeys = ctx->hostkeys;
	সংরচনা hostkey_entry *tmp;

	যদি (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		প্রত্যাগম 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->চাবি), l->path, l->linenum);
	যদি ((tmp = recallocarray(hostkeys->entries, hostkeys->অঙ্ক_entries,
	    hostkeys->অঙ্ক_entries + 1, পরিমাণ(*hostkeys->entries))) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->অঙ্ক_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->অঙ্ক_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->অঙ্ক_entries].সারি = l->linenum;
	hostkeys->entries[hostkeys->অঙ্ক_entries].চাবি = l->চাবি;
	l->চাবি = রিক্ত; /* steal it */
	hostkeys->entries[hostkeys->অঙ্ক_entries].marker = l->marker;
	hostkeys->entries[hostkeys->অঙ্ক_entries].note = l->note;
	hostkeys->অঙ্ক_entries++;
	ctx->অঙ্ক_loaded++;

	প্রত্যাগম 0;
}

শূন্য
load_hostkeys_file(সংরচনা hostkeys *hostkeys, ধ্রুব বর্ণ *host,
    ধ্রুব বর্ণ *path, FILE *f, u_int note)
{
	পূর্ণাঙ্ক r;
	সংরচনা load_callback_ctx ctx;

	ctx.host = host;
	ctx.অঙ্ক_loaded = 0;
	ctx.hostkeys = hostkeys;

	যদি ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    রিক্ত, HKF_WANT_MATCH|HKF_WANT_PARSE_চাবি, note)) != 0) {
		যদি (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	যদি (ctx.অঙ্ক_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.অঙ্ক_loaded, host);
}

শূন্য
load_hostkeys(সংরচনা hostkeys *hostkeys, ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *path,
    u_int note)
{
	FILE *f;

	যদি ((f = fopen(path, "r")) == রিক্ত) {
		debug_f("fopen %s: %s", path, strerror(errno));
		প্রত্যাগম;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

শূন্য
free_hostkeys(সংরচনা hostkeys *hostkeys)
{
	u_int i;

	প্রতি (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		মুক্ত(hostkeys->entries[i].host);
		মুক্ত(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].চাবি);
		explicit_bzero(hostkeys->entries + i, পরিমাণ(*hostkeys->entries));
	}
	মুক্ত(hostkeys->entries);
	freezero(hostkeys, পরিমাণ(*hostkeys));
}

স্থির পূর্ণাঙ্ক
check_চাবি_not_revoked(সংরচনা hostkeys *hostkeys, সংরচনা sshkey *k)
{
	পূর্ণাঙ্ক is_cert = sshkey_is_cert(k);
	u_int i;

	প্রতি (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		যদি (hostkeys->entries[i].marker != MRK_REVOKE)
			অনুবর্ত;
		যদি (sshkey_equal_public(k, hostkeys->entries[i].চাবি))
			প্রত্যাগম -1;
		যদি (is_cert && k != রিক্ত &&
		    sshkey_equal_public(k->cert->signature_চাবি,
		    hostkeys->entries[i].চাবি))
			প্রত্যাগম -1;
	}
	প্রত্যাগম 0;
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
check_hostkeys_by_চাবি_or_type(সংরচনা hostkeys *hostkeys,
    সংরচনা sshkey *k, পূর্ণাঙ্ক keytype, পূর্ণাঙ্ক nid, ধ্রুব সংরচনা hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	পূর্ণাঙ্ক want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	যদি (found != রিক্ত)
		*found = রিক্ত;

	প্রতি (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		যদি (hostkeys->entries[i].marker != want_marker)
			অনুবর্ত;
		যদি (k == রিক্ত) {
			যদি (hostkeys->entries[i].চাবি->type != keytype)
				অনুবর্ত;
			যদি (nid != -1 &&
			    sshkey_type_plain(keytype) == চাবি_ECDSA &&
			    hostkeys->entries[i].চাবি->ecdsa_nid != nid)
				অনুবর্ত;
			end_return = HOST_FOUND;
			যদি (found != রিক্ত)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].চাবি;
			ভঙ্গ;
		}
		যদি (want_cert) {
			যদি (sshkey_equal_public(k->cert->signature_চাবি,
			    hostkeys->entries[i].চাবি)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				যদি (found != রিক্ত)
					*found = hostkeys->entries + i;
				ভঙ্গ;
			}
		} অন্যথা {
			যদি (sshkey_equal(k, hostkeys->entries[i].চাবি)) {
				end_return = HOST_OK;
				যদি (found != রিক্ত)
					*found = hostkeys->entries + i;
				ভঙ্গ;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			যদি (found != রিক্ত)
				*found = hostkeys->entries + i;
		}
	}
	যদি (check_চাবি_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		যদি (found != রিক্ত)
			*found = রিক্ত;
	}
	প্রত্যাগম end_return;
}

HostStatus
check_চাবি_in_hostkeys(সংরচনা hostkeys *hostkeys, সংরচনা sshkey *চাবি,
    ধ্রুব সংরচনা hostkey_entry **found)
{
	যদি (চাবি == রিক্ত)
		fatal("no key to look up");
	প্রত্যাগম check_hostkeys_by_চাবি_or_type(hostkeys, চাবি, 0, -1, found);
}

পূর্ণাঙ্ক
lookup_চাবি_in_hostkeys_by_type(সংরচনা hostkeys *hostkeys, পূর্ণাঙ্ক keytype, পূর্ণাঙ্ক nid,
    ধ্রুব সংরচনা hostkey_entry **found)
{
	প্রত্যাগম (check_hostkeys_by_চাবি_or_type(hostkeys, রিক্ত, keytype, nid,
	    found) == HOST_FOUND);
}

পূর্ণাঙ্ক
lookup_marker_in_hostkeys(সংরচনা hostkeys *hostkeys, পূর্ণাঙ্ক want_marker)
{
	u_int i;

	প্রতি (i = 0; i < hostkeys->অঙ্ক_entries; i++) {
		যদি (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			প্রত্যাগম 1;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
format_host_entry(সংরচনা sshbuf *entry, ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *ip,
    ধ্রুব সংরচনা sshkey *চাবি, পূর্ণাঙ্ক store_hash)
{
	পূর্ণাঙ্ক r, success = 0;
	বর্ণ *hashed_host = রিক্ত, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	যদি (store_hash) {
		যদি ((hashed_host = host_hash(lhost, রিক্ত, 0)) == রিক্ত) {
			error_f("host_hash failed");
			মুক্ত(lhost);
			প্রত্যাগম 0;
		}
		যদি ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} অন্যথা যদি (ip != রিক্ত) {
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
	যদি (success && store_hash && ip != রিক্ত)
		success = format_host_entry(entry, ip, রিক্ত, চাবি, 1);
	প্রত্যাগম success;
}

স্থির পূর্ণাঙ্ক
write_host_entry(FILE *f, ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *ip,
    ধ্রুব সংরচনা sshkey *চাবি, পূর্ণাঙ্ক store_hash)
{
	পূর্ণাঙ্ক r, success = 0;
	সংরচনা sshbuf *entry = রিক্ত;

	যদি ((entry = sshbuf_new()) == রিক্ত)
		fatal_f("allocation failed");
	যদি ((r = format_host_entry(entry, host, ip, চাবি, store_hash)) != 1) {
		debug_f("failed to format host entry");
		গচ্ছ out;
	}
	যদি ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		গচ্ছ out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	প্রত্যাগম success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
শূন্য
hostfile_create_user_ssh_dir(ধ্রুব বর্ণ *filename, পূর্ণাঙ্ক notify)
{
	বর্ণ *dotsshdir = রিক্ত, *p;
	size_t len;
	সংরচনা stat st;

	যদি ((p = strrchr(filename, '/')) == রিক্ত)
		প্রত্যাগম;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	যদি (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		গচ্ছ out; /* not ~/.ssh prefixed */
	যদি (stat(dotsshdir, &st) == 0)
		গচ্ছ out; /* dir already exists */
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
		ssh_selinux_setfscreatecon(রিক্ত);
#endif
	}
 out:
	মুক্ত(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
পূর্ণাঙ্ক
add_host_to_hostfile(ধ্রুব বর্ণ *filename, ধ্রুব বর্ণ *host,
    ধ্রুব সংরচনা sshkey *চাবি, পূর্ণাঙ্ক store_hash)
{
	FILE *f;
	পূর্ণাঙ্ক success, addnl = 0;

	যদি (চাবি == রিক্ত)
		প্রত্যাগম 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	যদি ((f = fopen(filename, "a+")) == রিক্ত)
		প্রত্যাগম 0;
	setvbuf(f, রিক্ত, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	যদি (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	যদি (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		প্রত্যাগম 0;
	}
	success = write_host_entry(f, host, রিক্ত, চাবি, store_hash);
	fclose(f);
	প্রত্যাগম success;
}

সংরচনা host_delete_ctx {
	FILE *out;
	পূর্ণাঙ্ক quiet;
	ধ্রুব বর্ণ *host, *ip;
	u_int *match_চাবিগুলি;	/* mask of HKF_MATCH_* for this key */
	সংরচনা sshkey * ধ্রুব *চাবিগুলি;
	size_t nkeys;
	পূর্ণাঙ্ক modified;
};

স্থির পূর্ণাঙ্ক
host_delete(সংরচনা hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	সংরচনা host_delete_ctx *ctx = (সংরচনা host_delete_ctx *)_ctx;
	পূর্ণাঙ্ক loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	যদি (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		প্রতি (i = 0; i < ctx->nkeys; i++) {
			যদি (!sshkey_equal(ctx->চাবিগুলি[i], l->চাবি))
				অনুবর্ত;
			ctx->match_চাবিগুলি[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->সারি);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->চাবি), l->path, l->linenum);
			প্রত্যাগম 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->চাবি), ctx->host);
		ctx->modified = 1;
		প্রত্যাগম 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	যদি (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->সারি);
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
hostfile_replace_entries(ধ্রুব বর্ণ *filename, ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *ip,
    সংরচনা sshkey **চাবিগুলি, size_t nkeys, পূর্ণাঙ্ক store_hash, পূর্ণাঙ্ক quiet, পূর্ণাঙ্ক hash_alg)
{
	পূর্ণাঙ্ক r, fd, oerrno = 0;
	পূর্ণাঙ্ক loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	সংরচনা host_delete_ctx ctx;
	বর্ণ *fp = রিক্ত, *temp = রিক্ত, *back = রিক্ত;
	ধ্রুব বর্ণ *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	যদি ((ctx.match_চাবিগুলি = calloc(nkeys, পরিমাণ(*ctx.match_চাবিগুলি))) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	ctx.চাবিগুলি = চাবিগুলি;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	যদি ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ fail;
	}

	যদি ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		গচ্ছ fail;
	}
	যদি ((ctx.out = fdopen(fd, "w")) == রিক্ত) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		গচ্ছ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	যদি ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_চাবি, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		গচ্ছ fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == রিক্ত ? 0 : HKF_MATCH_IP);
	প্রতি (i = 0; i < nkeys; i++) {
		যদি (চাবিগুলি[i] == রিক্ত || (want & ctx.match_চাবিগুলি[i]) == want)
			অনুবর্ত;
		যদি ((fp = sshkey_fingerprint(চাবিগুলি[i], hash_alg,
		    SSH_FP_DEFAULT)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ fail;
		}
		/* write host/ip */
		what = "";
		যদি (ctx.match_চাবিগুলি[i] == 0) {
			what = "Adding new key";
			যদি (!write_host_entry(ctx.out, host, ip,
			    চাবিগুলি[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				গচ্ছ fail;
			}
		} অন্যথা যদি ((want & ~ctx.match_চাবিগুলি[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			যদি (!write_host_entry(ctx.out, host, রিক্ত,
			    চাবিগুলি[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				গচ্ছ fail;
			}
		} অন্যথা যদি ((want & ~ctx.match_চাবিগুলি[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			যদি (!write_host_entry(ctx.out, ip, রিক্ত,
			    চাবিগুলি[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				গচ্ছ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == রিক্ত ? "" : ",", ip == রিক্ত ? "" : ip, filename,
		    sshkey_ssh_name(চাবিগুলি[i]), fp);
		মুক্ত(fp);
		fp = রিক্ত;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = রিক্ত;

	যদি (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		যদি (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			গচ্ছ fail;
		}
		যদি (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			গচ্ছ fail;
		}
		যদি (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			গচ্ছ fail;
		}
	} অন্যথা {
		/* No changes made; just delete the temporary file */
		যদি (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	যদি (temp != রিক্ত && r != 0)
		unlink(temp);
	মুক্ত(temp);
	মুক্ত(back);
	মুক্ত(fp);
	যদি (ctx.out != রিক্ত)
		fclose(ctx.out);
	মুক্ত(ctx.match_চাবিগুলি);
	umask(omask);
	যদি (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
match_maybe_hashed(ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *names, পূর্ণাঙ্ক *was_hashed)
{
	পূর্ণাঙ্ক hashed = *names == HASH_DELIM, ret;
	বর্ণ *hashed_host = রিক্ত;
	size_t nlen = strlen(names);

	যদি (was_hashed != রিক্ত)
		*was_hashed = hashed;
	যদি (hashed) {
		যদি ((hashed_host = host_hash(host, names, nlen)) == রিক্ত)
			প্রত্যাগম -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		মুক্ত(hashed_host);
		প্রত্যাগম ret;
	}
	প্রত্যাগম match_hostname(host, names) == 1;
}

পূর্ণাঙ্ক
hostkeys_foreach_file(ধ্রুব বর্ণ *path, FILE *f, hostkeys_foreach_fn *callback,
    শূন্য *ctx, ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *ip, u_int options, u_int note)
{
	বর্ণ *সারি = রিক্ত, ktype[128];
	u_long linenum = 0;
	বর্ণ *cp, *cp2;
	u_int kbits;
	পূর্ণাঙ্ক hashed;
	পূর্ণাঙ্ক s, r = 0;
	সংরচনা hostkey_foreach_সারি lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, পরিমাণ(lineinfo));
	যদি (host == রিক্ত && (options & HKF_WANT_MATCH) != 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যাবত্ (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		সারি[strcspn(সারি, "\n")] = '\0';

		মুক্ত(lineinfo.সারি);
		sshkey_free(lineinfo.চাবি);
		memset(&lineinfo, 0, পরিমাণ(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.সারি = xstrdup(সারি);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = চাবি_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		প্রতি (cp = সারি; *cp == ' ' || *cp == '\t'; cp++)
			;
		যদি (!*cp || *cp == '#' || *cp == '\n') {
			যদি ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				যদি ((r = callback(&lineinfo, ctx)) != 0)
					ভঙ্গ;
			}
			অনুবর্ত;
		}

		যদি ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			যদি ((options & HKF_WANT_MATCH) == 0)
				গচ্ছ bad;
			অনুবর্ত;
		}

		/* Find the end of the host name portion. */
		প্রতি (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		যদি (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			যদি ((options & HKF_WANT_MATCH) == 0)
				গচ্ছ bad;
			অনুবর্ত;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		যদি (host != রিক্ত) {
			যদি ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				গচ্ছ bad;
			}
			যদি (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			যদি (ip != রিক্ত) {
				যদি ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					গচ্ছ bad;
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
				অনুবর্ত;
		}

		/* Got a match.  Skip host name and any following whitespace */
		প্রতি (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		যদি (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			গচ্ছ bad;
		}
		lineinfo.rawkey = cp = cp2;

		যদি ((options & HKF_WANT_PARSE_চাবি) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			যদি ((lineinfo.চাবি = sshkey_new(চাবি_UNSPEC)) == রিক্ত) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				ভঙ্গ;
			}
			যদি (!hostfile_read_চাবি(&cp, &kbits, lineinfo.চাবি)) {
				গচ্ছ bad;
			}
			lineinfo.keytype = lineinfo.চাবি->type;
			lineinfo.comment = cp;
		} অন্যথা {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			যদি (l <= 1 || l >= পরিমাণ(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				গচ্ছ bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			যদি (lineinfo.keytype == চাবি_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				গচ্ছ bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			প্রতি (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			যদি (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = চাবি_UNSPEC;
			}
			যদি (lineinfo.keytype == চাবি_UNSPEC) {
 bad:
				sshkey_free(lineinfo.চাবি);
				lineinfo.চাবি = রিক্ত;
				lineinfo.status = HKF_STATUS_INVALID;
				যদি ((r = callback(&lineinfo, ctx)) != 0)
					ভঙ্গ;
				অনুবর্ত;
			}
		}
		যদি ((r = callback(&lineinfo, ctx)) != 0)
			ভঙ্গ;
	}
	sshkey_free(lineinfo.চাবি);
	মুক্ত(lineinfo.সারি);
	মুক্ত(সারি);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
hostkeys_foreach(ধ্রুব বর্ণ *path, hostkeys_foreach_fn *callback, শূন্য *ctx,
    ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *ip, u_int options, u_int note)
{
	FILE *f;
	পূর্ণাঙ্ক r, oerrno;

	যদি ((f = fopen(path, "r")) == রিক্ত)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	প্রত্যাগম r;
}
