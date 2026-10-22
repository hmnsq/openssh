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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <netinet/in.h>

#شامل <errno.h>
#شامل <resolv.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "match.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "pathnames.h"
#شامل "ssherr.h"
#شامل "digest.h"
#شامل "hmac.h"
#شامل "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

ایستا صحیح
extract_salt(ثابت نویسه *s, u_int l, u_char *salt, size_t salt_len)
{
	نویسه *p, *b64salt;
	u_int b64len;
	صحیح ret;

	اگر (l < اندازه(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		بازگشت (-1);
	}
	اگر (strncmp(s, HASH_MAGIC, اندازه(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		بازگشت (-1);
	}
	s += اندازه(HASH_MAGIC) - 1;
	l -= اندازه(HASH_MAGIC) - 1;
	اگر ((p = memchr(s, HASH_DELIM, l)) == پوچ) {
		debug2("extract_salt: missing salt termination character");
		بازگشت (-1);
	}

	b64len = p - s;
	/* Sanity check */
	اگر (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		بازگشت (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	آزاد(b64salt);
	اگر (ret == -1) {
		debug2("extract_salt: salt decode error");
		بازگشت (-1);
	}
	اگر (ret != (صحیح)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		بازگشت (-1);
	}

	بازگشت (0);
}

نویسه *
host_hash(ثابت نویسه *host, ثابت نویسه *name_from_hostfile, u_int src_len)
{
	ساختار ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	نویسه uu_salt[512], uu_result[512];
	نویسه *encoded = پوچ;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	اگر (name_from_hostfile == پوچ) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} وگرنه {
		/* Extract salt from known host entry */
		اگر (extract_salt(name_from_hostfile, src_len, salt,
		    اندازه(salt)) == -1)
			بازگشت (پوچ);
	}

	اگر ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == پوچ ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, اندازه(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	اگر (__b64_ntop(salt, len, uu_salt, اندازه(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, اندازه(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	بازگشت (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

صحیح
hostfile_read_کلید(نویسه **cpp, u_int *bitsp, ساختار sshkey *ret)
{
	نویسه *cp;

	/* Skip leading whitespace. */
	برای (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	اگر (sshkey_read(ret, &cp) != 0)
		بازگشت 0;

	/* Skip trailing whitespace. */
	برای (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	اگر (bitsp != پوچ)
		*bitsp = sshkey_size(ret);
	بازگشت 1;
}

ایستا HostkeyMarker
check_markers(نویسه **cpp)
{
	نویسه marker[32], *sp, *cp = *cpp;
	صحیح ret = MRK_NONE;

	وقتی (*cp == '@') {
		/* Only one marker is allowed */
		اگر (ret != MRK_NONE)
			بازگشت MRK_ERROR;
		/* Markers are terminated by whitespace */
		اگر ((sp = strchr(cp, ' ')) == پوچ &&
		    (sp = strchr(cp, '\t')) == پوچ)
			بازگشت MRK_ERROR;
		/* Extract marker for comparison */
		اگر (sp <= cp + 1 || sp >= cp + اندازه(marker))
			بازگشت MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		اگر (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		وگرنه اگر (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		وگرنه
			بازگشت MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		برای (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	بازگشت ret;
}

ساختار hostkeys *
init_hostkeys(تهی)
{
	ساختار hostkeys *ret = xcalloc(1, اندازه(*ret));

	ret->entries = پوچ;
	بازگشت ret;
}

ساختار load_callback_ctx {
	ثابت نویسه *host;
	u_long رقم_loaded;
	ساختار hostkeys *hostkeys;
};

ایستا صحیح
record_hostkey(ساختار hostkey_foreach_سطر *l, تهی *_ctx)
{
	ساختار load_callback_ctx *ctx = (ساختار load_callback_ctx *)_ctx;
	ساختار hostkeys *hostkeys = ctx->hostkeys;
	ساختار hostkey_entry *tmp;

	اگر (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		بازگشت 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->کلید), l->path, l->linenum);
	اگر ((tmp = recallocarray(hostkeys->entries, hostkeys->رقم_entries,
	    hostkeys->رقم_entries + 1, اندازه(*hostkeys->entries))) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->رقم_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->رقم_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->رقم_entries].سطر = l->linenum;
	hostkeys->entries[hostkeys->رقم_entries].کلید = l->کلید;
	l->کلید = پوچ; /* steal it */
	hostkeys->entries[hostkeys->رقم_entries].marker = l->marker;
	hostkeys->entries[hostkeys->رقم_entries].note = l->note;
	hostkeys->رقم_entries++;
	ctx->رقم_loaded++;

	بازگشت 0;
}

تهی
load_hostkeys_file(ساختار hostkeys *hostkeys, ثابت نویسه *host,
    ثابت نویسه *path, FILE *f, u_int note)
{
	صحیح r;
	ساختار load_callback_ctx ctx;

	ctx.host = host;
	ctx.رقم_loaded = 0;
	ctx.hostkeys = hostkeys;

	اگر ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    پوچ, HKF_WANT_MATCH|HKF_WANT_PARSE_کلید, note)) != 0) {
		اگر (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	اگر (ctx.رقم_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.رقم_loaded, host);
}

تهی
load_hostkeys(ساختار hostkeys *hostkeys, ثابت نویسه *host, ثابت نویسه *path,
    u_int note)
{
	FILE *f;

	اگر ((f = fopen(path, "r")) == پوچ) {
		debug_f("fopen %s: %s", path, strerror(errno));
		بازگشت;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

تهی
free_hostkeys(ساختار hostkeys *hostkeys)
{
	u_int i;

	برای (i = 0; i < hostkeys->رقم_entries; i++) {
		آزاد(hostkeys->entries[i].host);
		آزاد(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].کلید);
		explicit_bzero(hostkeys->entries + i, اندازه(*hostkeys->entries));
	}
	آزاد(hostkeys->entries);
	freezero(hostkeys, اندازه(*hostkeys));
}

ایستا صحیح
check_کلید_not_revoked(ساختار hostkeys *hostkeys, ساختار sshkey *k)
{
	صحیح is_cert = sshkey_is_cert(k);
	u_int i;

	برای (i = 0; i < hostkeys->رقم_entries; i++) {
		اگر (hostkeys->entries[i].marker != MRK_REVOKE)
			ادامه;
		اگر (sshkey_equal_public(k, hostkeys->entries[i].کلید))
			بازگشت -1;
		اگر (is_cert && k != پوچ &&
		    sshkey_equal_public(k->cert->signature_کلید,
		    hostkeys->entries[i].کلید))
			بازگشت -1;
	}
	بازگشت 0;
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
ایستا HostStatus
check_hostkeys_by_کلید_or_type(ساختار hostkeys *hostkeys,
    ساختار sshkey *k, صحیح keytype, صحیح nid, ثابت ساختار hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	صحیح want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	اگر (found != پوچ)
		*found = پوچ;

	برای (i = 0; i < hostkeys->رقم_entries; i++) {
		اگر (hostkeys->entries[i].marker != want_marker)
			ادامه;
		اگر (k == پوچ) {
			اگر (hostkeys->entries[i].کلید->type != keytype)
				ادامه;
			اگر (nid != -1 &&
			    sshkey_type_plain(keytype) == کلید_ECDSA &&
			    hostkeys->entries[i].کلید->ecdsa_nid != nid)
				ادامه;
			end_return = HOST_FOUND;
			اگر (found != پوچ)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].کلید;
			بشکن;
		}
		اگر (want_cert) {
			اگر (sshkey_equal_public(k->cert->signature_کلید,
			    hostkeys->entries[i].کلید)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				اگر (found != پوچ)
					*found = hostkeys->entries + i;
				بشکن;
			}
		} وگرنه {
			اگر (sshkey_equal(k, hostkeys->entries[i].کلید)) {
				end_return = HOST_OK;
				اگر (found != پوچ)
					*found = hostkeys->entries + i;
				بشکن;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			اگر (found != پوچ)
				*found = hostkeys->entries + i;
		}
	}
	اگر (check_کلید_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		اگر (found != پوچ)
			*found = پوچ;
	}
	بازگشت end_return;
}

HostStatus
check_کلید_in_hostkeys(ساختار hostkeys *hostkeys, ساختار sshkey *کلید,
    ثابت ساختار hostkey_entry **found)
{
	اگر (کلید == پوچ)
		fatal("no key to look up");
	بازگشت check_hostkeys_by_کلید_or_type(hostkeys, کلید, 0, -1, found);
}

صحیح
lookup_کلید_in_hostkeys_by_type(ساختار hostkeys *hostkeys, صحیح keytype, صحیح nid,
    ثابت ساختار hostkey_entry **found)
{
	بازگشت (check_hostkeys_by_کلید_or_type(hostkeys, پوچ, keytype, nid,
	    found) == HOST_FOUND);
}

صحیح
lookup_marker_in_hostkeys(ساختار hostkeys *hostkeys, صحیح want_marker)
{
	u_int i;

	برای (i = 0; i < hostkeys->رقم_entries; i++) {
		اگر (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			بازگشت 1;
	}
	بازگشت 0;
}

ایستا صحیح
format_host_entry(ساختار sshbuf *entry, ثابت نویسه *host, ثابت نویسه *ip,
    ثابت ساختار sshkey *کلید, صحیح store_hash)
{
	صحیح r, success = 0;
	نویسه *hashed_host = پوچ, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	اگر (store_hash) {
		اگر ((hashed_host = host_hash(lhost, پوچ, 0)) == پوچ) {
			error_f("host_hash failed");
			آزاد(lhost);
			بازگشت 0;
		}
		اگر ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} وگرنه اگر (ip != پوچ) {
		اگر ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} وگرنه {
		اگر ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	آزاد(hashed_host);
	آزاد(lhost);
	اگر ((r = sshkey_format_text(کلید, entry)) == 0)
		success = 1;
	وگرنه
		error_fr(r, "sshkey_write");
	اگر ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	اگر (success && store_hash && ip != پوچ)
		success = format_host_entry(entry, ip, پوچ, کلید, 1);
	بازگشت success;
}

ایستا صحیح
write_host_entry(FILE *f, ثابت نویسه *host, ثابت نویسه *ip,
    ثابت ساختار sshkey *کلید, صحیح store_hash)
{
	صحیح r, success = 0;
	ساختار sshbuf *entry = پوچ;

	اگر ((entry = sshbuf_new()) == پوچ)
		fatal_f("allocation failed");
	اگر ((r = format_host_entry(entry, host, ip, کلید, store_hash)) != 1) {
		debug_f("failed to format host entry");
		برو out;
	}
	اگر ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		برو out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	بازگشت success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
تهی
hostfile_create_user_ssh_dir(ثابت نویسه *filename, صحیح notify)
{
	نویسه *dotsshdir = پوچ, *p;
	size_t len;
	ساختار stat st;

	اگر ((p = strrchr(filename, '/')) == پوچ)
		بازگشت;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	اگر (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		برو out; /* not ~/.ssh prefixed */
	اگر (stat(dotsshdir, &st) == 0)
		برو out; /* dir already exists */
	وگرنه اگر (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	وگرنه {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		اگر (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		وگرنه اگر (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(پوچ);
#endif
	}
 out:
	آزاد(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
صحیح
add_host_to_hostfile(ثابت نویسه *filename, ثابت نویسه *host,
    ثابت ساختار sshkey *کلید, صحیح store_hash)
{
	FILE *f;
	صحیح success, addnl = 0;

	اگر (کلید == پوچ)
		بازگشت 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	اگر ((f = fopen(filename, "a+")) == پوچ)
		بازگشت 0;
	setvbuf(f, پوچ, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	اگر (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	اگر (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		بازگشت 0;
	}
	success = write_host_entry(f, host, پوچ, کلید, store_hash);
	fclose(f);
	بازگشت success;
}

ساختار host_delete_ctx {
	FILE *out;
	صحیح quiet;
	ثابت نویسه *host, *ip;
	u_int *match_کلیدها;	/* mask of HKF_MATCH_* for this key */
	ساختار sshkey * ثابت *کلیدها;
	size_t nkeys;
	صحیح modified;
};

ایستا صحیح
host_delete(ساختار hostkey_foreach_سطر *l, تهی *_ctx)
{
	ساختار host_delete_ctx *ctx = (ساختار host_delete_ctx *)_ctx;
	صحیح loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	اگر (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		برای (i = 0; i < ctx->nkeys; i++) {
			اگر (!sshkey_equal(ctx->کلیدها[i], l->کلید))
				ادامه;
			ctx->match_کلیدها[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->سطر);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->کلید), l->path, l->linenum);
			بازگشت 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->کلید), ctx->host);
		ctx->modified = 1;
		بازگشت 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	اگر (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->سطر);
	بازگشت 0;
}

صحیح
hostfile_replace_entries(ثابت نویسه *filename, ثابت نویسه *host, ثابت نویسه *ip,
    ساختار sshkey **کلیدها, size_t nkeys, صحیح store_hash, صحیح quiet, صحیح hash_alg)
{
	صحیح r, fd, oerrno = 0;
	صحیح loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ساختار host_delete_ctx ctx;
	نویسه *fp = پوچ, *temp = پوچ, *back = پوچ;
	ثابت نویسه *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, اندازه(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	اگر ((ctx.match_کلیدها = calloc(nkeys, اندازه(*ctx.match_کلیدها))) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	ctx.کلیدها = کلیدها;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	اگر ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		برو fail;
	}

	اگر ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		برو fail;
	}
	اگر ((ctx.out = fdopen(fd, "w")) == پوچ) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		برو fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	اگر ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_کلید, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		برو fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == پوچ ? 0 : HKF_MATCH_IP);
	برای (i = 0; i < nkeys; i++) {
		اگر (کلیدها[i] == پوچ || (want & ctx.match_کلیدها[i]) == want)
			ادامه;
		اگر ((fp = sshkey_fingerprint(کلیدها[i], hash_alg,
		    SSH_FP_DEFAULT)) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو fail;
		}
		/* write host/ip */
		what = "";
		اگر (ctx.match_کلیدها[i] == 0) {
			what = "Adding new key";
			اگر (!write_host_entry(ctx.out, host, ip,
			    کلیدها[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				برو fail;
			}
		} وگرنه اگر ((want & ~ctx.match_کلیدها[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			اگر (!write_host_entry(ctx.out, host, پوچ,
			    کلیدها[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				برو fail;
			}
		} وگرنه اگر ((want & ~ctx.match_کلیدها[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			اگر (!write_host_entry(ctx.out, ip, پوچ,
			    کلیدها[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				برو fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == پوچ ? "" : ",", ip == پوچ ? "" : ip, filename,
		    sshkey_ssh_name(کلیدها[i]), fp);
		آزاد(fp);
		fp = پوچ;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = پوچ;

	اگر (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		اگر (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			برو fail;
		}
		اگر (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			برو fail;
		}
		اگر (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			برو fail;
		}
	} وگرنه {
		/* No changes made; just delete the temporary file */
		اگر (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	اگر (temp != پوچ && r != 0)
		unlink(temp);
	آزاد(temp);
	آزاد(back);
	آزاد(fp);
	اگر (ctx.out != پوچ)
		fclose(ctx.out);
	آزاد(ctx.match_کلیدها);
	umask(omask);
	اگر (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	بازگشت r;
}

ایستا صحیح
match_maybe_hashed(ثابت نویسه *host, ثابت نویسه *names, صحیح *was_hashed)
{
	صحیح hashed = *names == HASH_DELIM, ret;
	نویسه *hashed_host = پوچ;
	size_t nlen = strlen(names);

	اگر (was_hashed != پوچ)
		*was_hashed = hashed;
	اگر (hashed) {
		اگر ((hashed_host = host_hash(host, names, nlen)) == پوچ)
			بازگشت -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		آزاد(hashed_host);
		بازگشت ret;
	}
	بازگشت match_hostname(host, names) == 1;
}

صحیح
hostkeys_foreach_file(ثابت نویسه *path, FILE *f, hostkeys_foreach_fn *callback,
    تهی *ctx, ثابت نویسه *host, ثابت نویسه *ip, u_int options, u_int note)
{
	نویسه *سطر = پوچ, ktype[128];
	u_long linenum = 0;
	نویسه *cp, *cp2;
	u_int kbits;
	صحیح hashed;
	صحیح s, r = 0;
	ساختار hostkey_foreach_سطر lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, اندازه(lineinfo));
	اگر (host == پوچ && (options & HKF_WANT_MATCH) != 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	وقتی (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		سطر[strcspn(سطر, "\n")] = '\0';

		آزاد(lineinfo.سطر);
		sshkey_free(lineinfo.کلید);
		memset(&lineinfo, 0, اندازه(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.سطر = xstrdup(سطر);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = کلید_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		برای (cp = سطر; *cp == ' ' || *cp == '\t'; cp++)
			;
		اگر (!*cp || *cp == '#' || *cp == '\n') {
			اگر ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				اگر ((r = callback(&lineinfo, ctx)) != 0)
					بشکن;
			}
			ادامه;
		}

		اگر ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			اگر ((options & HKF_WANT_MATCH) == 0)
				برو bad;
			ادامه;
		}

		/* Find the end of the host name portion. */
		برای (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		اگر (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			اگر ((options & HKF_WANT_MATCH) == 0)
				برو bad;
			ادامه;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		اگر (host != پوچ) {
			اگر ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				برو bad;
			}
			اگر (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			اگر (ip != پوچ) {
				اگر ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					برو bad;
				}
				اگر (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			اگر ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				ادامه;
		}

		/* Got a match.  Skip host name and any following whitespace */
		برای (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		اگر (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			برو bad;
		}
		lineinfo.rawkey = cp = cp2;

		اگر ((options & HKF_WANT_PARSE_کلید) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			اگر ((lineinfo.کلید = sshkey_new(کلید_UNSPEC)) == پوچ) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				بشکن;
			}
			اگر (!hostfile_read_کلید(&cp, &kbits, lineinfo.کلید)) {
				برو bad;
			}
			lineinfo.keytype = lineinfo.کلید->type;
			lineinfo.comment = cp;
		} وگرنه {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			اگر (l <= 1 || l >= اندازه(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				برو bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			اگر (lineinfo.keytype == کلید_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				برو bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			برای (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			اگر (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = کلید_UNSPEC;
			}
			اگر (lineinfo.keytype == کلید_UNSPEC) {
 bad:
				sshkey_free(lineinfo.کلید);
				lineinfo.کلید = پوچ;
				lineinfo.status = HKF_STATUS_INVALID;
				اگر ((r = callback(&lineinfo, ctx)) != 0)
					بشکن;
				ادامه;
			}
		}
		اگر ((r = callback(&lineinfo, ctx)) != 0)
			بشکن;
	}
	sshkey_free(lineinfo.کلید);
	آزاد(lineinfo.سطر);
	آزاد(سطر);
	بازگشت r;
}

صحیح
hostkeys_foreach(ثابت نویسه *path, hostkeys_foreach_fn *callback, تهی *ctx,
    ثابت نویسه *host, ثابت نویسه *ip, u_int options, u_int note)
{
	FILE *f;
	صحیح r, oerrno;

	اگر ((f = fopen(path, "r")) == پوچ)
		بازگشت SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	بازگشت r;
}
