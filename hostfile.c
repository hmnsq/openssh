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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <netinet/in.h>

#ضمن <errno.h>
#ضمن <resolv.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "match.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "pathnames.h"
#ضمن "ssherr.h"
#ضمن "digest.h"
#ضمن "hmac.h"
#ضمن "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

ساكن صحيح
extract_salt(ثابت حرف *s, u_int l, u_char *salt, size_t salt_len)
{
	حرف *p, *b64salt;
	u_int b64len;
	صحيح ret;

	إذا (l < حجم(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		أرجع (-1);
	}
	إذا (strncmp(s, HASH_MAGIC, حجم(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		أرجع (-1);
	}
	s += حجم(HASH_MAGIC) - 1;
	l -= حجم(HASH_MAGIC) - 1;
	إذا ((p = memchr(s, HASH_DELIM, l)) == عدم) {
		debug2("extract_salt: missing salt termination character");
		أرجع (-1);
	}

	b64len = p - s;
	/* Sanity check */
	إذا (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		أرجع (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	حرر(b64salt);
	إذا (ret == -1) {
		debug2("extract_salt: salt decode error");
		أرجع (-1);
	}
	إذا (ret != (صحيح)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		أرجع (-1);
	}

	أرجع (0);
}

حرف *
host_hash(ثابت حرف *host, ثابت حرف *name_from_hostfile, u_int src_len)
{
	بنية ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	حرف uu_salt[512], uu_result[512];
	حرف *encoded = عدم;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	إذا (name_from_hostfile == عدم) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} وإلا {
		/* Extract salt from known host entry */
		إذا (extract_salt(name_from_hostfile, src_len, salt,
		    حجم(salt)) == -1)
			أرجع (عدم);
	}

	إذا ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == عدم ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, حجم(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	إذا (__b64_ntop(salt, len, uu_salt, حجم(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, حجم(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	أرجع (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

صحيح
hostfile_read_مبودي(حرف **cpp, u_int *bitsp, بنية sshkey *ret)
{
	حرف *cp;

	/* Skip leading whitespace. */
	لكل (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	إذا (sshkey_read(ret, &cp) != 0)
		أرجع 0;

	/* Skip trailing whitespace. */
	لكل (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	إذا (bitsp != عدم)
		*bitsp = sshkey_size(ret);
	أرجع 1;
}

ساكن HostkeyMarker
check_markers(حرف **cpp)
{
	حرف marker[32], *sp, *cp = *cpp;
	صحيح ret = MRK_NONE;

	طالما (*cp == '@') {
		/* Only one marker is allowed */
		إذا (ret != MRK_NONE)
			أرجع MRK_ERROR;
		/* Markers are terminated by whitespace */
		إذا ((sp = strchr(cp, ' ')) == عدم &&
		    (sp = strchr(cp, '\t')) == عدم)
			أرجع MRK_ERROR;
		/* Extract marker for comparison */
		إذا (sp <= cp + 1 || sp >= cp + حجم(marker))
			أرجع MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		إذا (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		وإلا إذا (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		وإلا
			أرجع MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		لكل (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	أرجع ret;
}

بنية hostkeys *
init_hostkeys(فراغ)
{
	بنية hostkeys *ret = xcalloc(1, حجم(*ret));

	ret->entries = عدم;
	أرجع ret;
}

بنية load_callback_ctx {
	ثابت حرف *host;
	u_long لمب_loaded;
	بنية hostkeys *hostkeys;
};

ساكن صحيح
record_hostkey(بنية hostkey_foreach_لي *l, فراغ *_ctx)
{
	بنية load_callback_ctx *ctx = (بنية load_callback_ctx *)_ctx;
	بنية hostkeys *hostkeys = ctx->hostkeys;
	بنية hostkey_entry *tmp;

	إذا (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		أرجع 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->مبودي), l->path, l->linenum);
	إذا ((tmp = recallocarray(hostkeys->entries, hostkeys->لمب_entries,
	    hostkeys->لمب_entries + 1, حجم(*hostkeys->entries))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->لمب_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->لمب_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->لمب_entries].لي = l->linenum;
	hostkeys->entries[hostkeys->لمب_entries].مبودي = l->مبودي;
	l->مبودي = عدم; /* steal it */
	hostkeys->entries[hostkeys->لمب_entries].marker = l->marker;
	hostkeys->entries[hostkeys->لمب_entries].note = l->note;
	hostkeys->لمب_entries++;
	ctx->لمب_loaded++;

	أرجع 0;
}

فراغ
load_hostkeys_file(بنية hostkeys *hostkeys, ثابت حرف *host,
    ثابت حرف *path, FILE *f, u_int note)
{
	صحيح r;
	بنية load_callback_ctx ctx;

	ctx.host = host;
	ctx.لمب_loaded = 0;
	ctx.hostkeys = hostkeys;

	إذا ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    عدم, HKF_WANT_MATCH|HKF_WANT_PARSE_مبودي, note)) != 0) {
		إذا (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	إذا (ctx.لمب_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.لمب_loaded, host);
}

فراغ
load_hostkeys(بنية hostkeys *hostkeys, ثابت حرف *host, ثابت حرف *path,
    u_int note)
{
	FILE *f;

	إذا ((f = fopen(path, "r")) == عدم) {
		debug_f("fopen %s: %s", path, strerror(errno));
		أرجع;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

فراغ
free_hostkeys(بنية hostkeys *hostkeys)
{
	u_int i;

	لكل (i = 0; i < hostkeys->لمب_entries; i++) {
		حرر(hostkeys->entries[i].host);
		حرر(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].مبودي);
		explicit_bzero(hostkeys->entries + i, حجم(*hostkeys->entries));
	}
	حرر(hostkeys->entries);
	freezero(hostkeys, حجم(*hostkeys));
}

ساكن صحيح
check_مبودي_not_revoked(بنية hostkeys *hostkeys, بنية sshkey *k)
{
	صحيح is_cert = sshkey_is_cert(k);
	u_int i;

	لكل (i = 0; i < hostkeys->لمب_entries; i++) {
		إذا (hostkeys->entries[i].marker != MRK_REVOKE)
			استمر;
		إذا (sshkey_equal_public(k, hostkeys->entries[i].مبودي))
			أرجع -1;
		إذا (is_cert && k != عدم &&
		    sshkey_equal_public(k->cert->signature_مبودي,
		    hostkeys->entries[i].مبودي))
			أرجع -1;
	}
	أرجع 0;
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
ساكن HostStatus
check_hostkeys_by_مبودي_or_type(بنية hostkeys *hostkeys,
    بنية sshkey *k, صحيح keytype, صحيح nid, ثابت بنية hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	صحيح want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	إذا (found != عدم)
		*found = عدم;

	لكل (i = 0; i < hostkeys->لمب_entries; i++) {
		إذا (hostkeys->entries[i].marker != want_marker)
			استمر;
		إذا (k == عدم) {
			إذا (hostkeys->entries[i].مبودي->type != keytype)
				استمر;
			إذا (nid != -1 &&
			    sshkey_type_plain(keytype) == مبودي_ECDSA &&
			    hostkeys->entries[i].مبودي->ecdsa_nid != nid)
				استمر;
			end_return = HOST_FOUND;
			إذا (found != عدم)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].مبودي;
			اكسر;
		}
		إذا (want_cert) {
			إذا (sshkey_equal_public(k->cert->signature_مبودي,
			    hostkeys->entries[i].مبودي)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				إذا (found != عدم)
					*found = hostkeys->entries + i;
				اكسر;
			}
		} وإلا {
			إذا (sshkey_equal(k, hostkeys->entries[i].مبودي)) {
				end_return = HOST_OK;
				إذا (found != عدم)
					*found = hostkeys->entries + i;
				اكسر;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			إذا (found != عدم)
				*found = hostkeys->entries + i;
		}
	}
	إذا (check_مبودي_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		إذا (found != عدم)
			*found = عدم;
	}
	أرجع end_return;
}

HostStatus
check_مبودي_in_hostkeys(بنية hostkeys *hostkeys, بنية sshkey *مبودي,
    ثابت بنية hostkey_entry **found)
{
	إذا (مبودي == عدم)
		fatal("no key to look up");
	أرجع check_hostkeys_by_مبودي_or_type(hostkeys, مبودي, 0, -1, found);
}

صحيح
lookup_مبودي_in_hostkeys_by_type(بنية hostkeys *hostkeys, صحيح keytype, صحيح nid,
    ثابت بنية hostkey_entry **found)
{
	أرجع (check_hostkeys_by_مبودي_or_type(hostkeys, عدم, keytype, nid,
	    found) == HOST_FOUND);
}

صحيح
lookup_marker_in_hostkeys(بنية hostkeys *hostkeys, صحيح want_marker)
{
	u_int i;

	لكل (i = 0; i < hostkeys->لمب_entries; i++) {
		إذا (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			أرجع 1;
	}
	أرجع 0;
}

ساكن صحيح
format_host_entry(بنية sshbuf *entry, ثابت حرف *host, ثابت حرف *ip,
    ثابت بنية sshkey *مبودي, صحيح store_hash)
{
	صحيح r, success = 0;
	حرف *hashed_host = عدم, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	إذا (store_hash) {
		إذا ((hashed_host = host_hash(lhost, عدم, 0)) == عدم) {
			error_f("host_hash failed");
			حرر(lhost);
			أرجع 0;
		}
		إذا ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} وإلا إذا (ip != عدم) {
		إذا ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} وإلا {
		إذا ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	حرر(hashed_host);
	حرر(lhost);
	إذا ((r = sshkey_format_text(مبودي, entry)) == 0)
		success = 1;
	وإلا
		error_fr(r, "sshkey_write");
	إذا ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	إذا (success && store_hash && ip != عدم)
		success = format_host_entry(entry, ip, عدم, مبودي, 1);
	أرجع success;
}

ساكن صحيح
write_host_entry(FILE *f, ثابت حرف *host, ثابت حرف *ip,
    ثابت بنية sshkey *مبودي, صحيح store_hash)
{
	صحيح r, success = 0;
	بنية sshbuf *entry = عدم;

	إذا ((entry = sshbuf_new()) == عدم)
		fatal_f("allocation failed");
	إذا ((r = format_host_entry(entry, host, ip, مبودي, store_hash)) != 1) {
		debug_f("failed to format host entry");
		اذهب out;
	}
	إذا ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		اذهب out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	أرجع success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
فراغ
hostfile_create_user_ssh_dir(ثابت حرف *filename, صحيح notify)
{
	حرف *dotsshdir = عدم, *p;
	size_t len;
	بنية stat st;

	إذا ((p = strrchr(filename, '/')) == عدم)
		أرجع;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	إذا (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		اذهب out; /* not ~/.ssh prefixed */
	إذا (stat(dotsshdir, &st) == 0)
		اذهب out; /* dir already exists */
	وإلا إذا (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	وإلا {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		إذا (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		وإلا إذا (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(عدم);
#endif
	}
 out:
	حرر(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
صحيح
add_host_to_hostfile(ثابت حرف *filename, ثابت حرف *host,
    ثابت بنية sshkey *مبودي, صحيح store_hash)
{
	FILE *f;
	صحيح success, addnl = 0;

	إذا (مبودي == عدم)
		أرجع 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	إذا ((f = fopen(filename, "a+")) == عدم)
		أرجع 0;
	setvbuf(f, عدم, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	إذا (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	إذا (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		أرجع 0;
	}
	success = write_host_entry(f, host, عدم, مبودي, store_hash);
	fclose(f);
	أرجع success;
}

بنية host_delete_ctx {
	FILE *out;
	صحيح quiet;
	ثابت حرف *host, *ip;
	u_int *match_مبوداي;	/* mask of HKF_MATCH_* for this key */
	بنية sshkey * ثابت *مبوداي;
	size_t nkeys;
	صحيح modified;
};

ساكن صحيح
host_delete(بنية hostkey_foreach_لي *l, فراغ *_ctx)
{
	بنية host_delete_ctx *ctx = (بنية host_delete_ctx *)_ctx;
	صحيح loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	إذا (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		لكل (i = 0; i < ctx->nkeys; i++) {
			إذا (!sshkey_equal(ctx->مبوداي[i], l->مبودي))
				استمر;
			ctx->match_مبوداي[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->لي);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->مبودي), l->path, l->linenum);
			أرجع 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->مبودي), ctx->host);
		ctx->modified = 1;
		أرجع 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	إذا (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->لي);
	أرجع 0;
}

صحيح
hostfile_replace_entries(ثابت حرف *filename, ثابت حرف *host, ثابت حرف *ip,
    بنية sshkey **مبوداي, size_t nkeys, صحيح store_hash, صحيح quiet, صحيح hash_alg)
{
	صحيح r, fd, oerrno = 0;
	صحيح loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	بنية host_delete_ctx ctx;
	حرف *fp = عدم, *temp = عدم, *back = عدم;
	ثابت حرف *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, حجم(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	إذا ((ctx.match_مبوداي = calloc(nkeys, حجم(*ctx.match_مبوداي))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	ctx.مبوداي = مبوداي;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	إذا ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب fail;
	}

	إذا ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}
	إذا ((ctx.out = fdopen(fd, "w")) == عدم) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	إذا ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_مبودي, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		اذهب fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == عدم ? 0 : HKF_MATCH_IP);
	لكل (i = 0; i < nkeys; i++) {
		إذا (مبوداي[i] == عدم || (want & ctx.match_مبوداي[i]) == want)
			استمر;
		إذا ((fp = sshkey_fingerprint(مبوداي[i], hash_alg,
		    SSH_FP_DEFAULT)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب fail;
		}
		/* write host/ip */
		what = "";
		إذا (ctx.match_مبوداي[i] == 0) {
			what = "Adding new key";
			إذا (!write_host_entry(ctx.out, host, ip,
			    مبوداي[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				اذهب fail;
			}
		} وإلا إذا ((want & ~ctx.match_مبوداي[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			إذا (!write_host_entry(ctx.out, host, عدم,
			    مبوداي[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				اذهب fail;
			}
		} وإلا إذا ((want & ~ctx.match_مبوداي[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			إذا (!write_host_entry(ctx.out, ip, عدم,
			    مبوداي[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				اذهب fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == عدم ? "" : ",", ip == عدم ? "" : ip, filename,
		    sshkey_ssh_name(مبوداي[i]), fp);
		حرر(fp);
		fp = عدم;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = عدم;

	إذا (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		إذا (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
		إذا (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
		إذا (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
	} وإلا {
		/* No changes made; just delete the temporary file */
		إذا (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	إذا (temp != عدم && r != 0)
		unlink(temp);
	حرر(temp);
	حرر(back);
	حرر(fp);
	إذا (ctx.out != عدم)
		fclose(ctx.out);
	حرر(ctx.match_مبوداي);
	umask(omask);
	إذا (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	أرجع r;
}

ساكن صحيح
match_maybe_hashed(ثابت حرف *host, ثابت حرف *names, صحيح *was_hashed)
{
	صحيح hashed = *names == HASH_DELIM, ret;
	حرف *hashed_host = عدم;
	size_t nlen = strlen(names);

	إذا (was_hashed != عدم)
		*was_hashed = hashed;
	إذا (hashed) {
		إذا ((hashed_host = host_hash(host, names, nlen)) == عدم)
			أرجع -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		حرر(hashed_host);
		أرجع ret;
	}
	أرجع match_hostname(host, names) == 1;
}

صحيح
hostkeys_foreach_file(ثابت حرف *path, FILE *f, hostkeys_foreach_fn *callback,
    فراغ *ctx, ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note)
{
	حرف *لي = عدم, ktype[128];
	u_long linenum = 0;
	حرف *cp, *cp2;
	u_int kbits;
	صحيح hashed;
	صحيح s, r = 0;
	بنية hostkey_foreach_لي lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, حجم(lineinfo));
	إذا (host == عدم && (options & HKF_WANT_MATCH) != 0)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	طالما (getline(&لي, &linesize, f) != -1) {
		linenum++;
		لي[strcspn(لي, "\n")] = '\0';

		حرر(lineinfo.لي);
		sshkey_free(lineinfo.مبودي);
		memset(&lineinfo, 0, حجم(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.لي = xstrdup(لي);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = مبودي_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		لكل (cp = لي; *cp == ' ' || *cp == '\t'; cp++)
			;
		إذا (!*cp || *cp == '#' || *cp == '\n') {
			إذا ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				إذا ((r = callback(&lineinfo, ctx)) != 0)
					اكسر;
			}
			استمر;
		}

		إذا ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			إذا ((options & HKF_WANT_MATCH) == 0)
				اذهب bad;
			استمر;
		}

		/* Find the end of the host name portion. */
		لكل (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		إذا (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			إذا ((options & HKF_WANT_MATCH) == 0)
				اذهب bad;
			استمر;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		إذا (host != عدم) {
			إذا ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				اذهب bad;
			}
			إذا (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			إذا (ip != عدم) {
				إذا ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					اذهب bad;
				}
				إذا (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			إذا ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				استمر;
		}

		/* Got a match.  Skip host name and any following whitespace */
		لكل (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		إذا (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			اذهب bad;
		}
		lineinfo.rawkey = cp = cp2;

		إذا ((options & HKF_WANT_PARSE_مبودي) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			إذا ((lineinfo.مبودي = sshkey_new(مبودي_UNSPEC)) == عدم) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				اكسر;
			}
			إذا (!hostfile_read_مبودي(&cp, &kbits, lineinfo.مبودي)) {
				اذهب bad;
			}
			lineinfo.keytype = lineinfo.مبودي->type;
			lineinfo.comment = cp;
		} وإلا {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			إذا (l <= 1 || l >= حجم(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				اذهب bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			إذا (lineinfo.keytype == مبودي_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				اذهب bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			لكل (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			إذا (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = مبودي_UNSPEC;
			}
			إذا (lineinfo.keytype == مبودي_UNSPEC) {
 bad:
				sshkey_free(lineinfo.مبودي);
				lineinfo.مبودي = عدم;
				lineinfo.status = HKF_STATUS_INVALID;
				إذا ((r = callback(&lineinfo, ctx)) != 0)
					اكسر;
				استمر;
			}
		}
		إذا ((r = callback(&lineinfo, ctx)) != 0)
			اكسر;
	}
	sshkey_free(lineinfo.مبودي);
	حرر(lineinfo.لي);
	حرر(لي);
	أرجع r;
}

صحيح
hostkeys_foreach(ثابت حرف *path, hostkeys_foreach_fn *callback, فراغ *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note)
{
	FILE *f;
	صحيح r, oerrno;

	إذا ((f = fopen(path, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	أرجع r;
}
