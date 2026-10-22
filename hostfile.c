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

ساکن صحیح
نکالو_salt(ثابت حرف *s, u_int l, u_char *salt, سائز_t salt_len)
{
	حرف *p, *b64salt;
	u_int b64len;
	صحیح ret;

	اگر (l < حجم(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		واپس (-1);
	}
	اگر (لڑی_موازنہ(s, HASH_MAGIC, حجم(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		واپس (-1);
	}
	s += حجم(HASH_MAGIC) - 1;
	l -= حجم(HASH_MAGIC) - 1;
	اگر ((p = memchr(s, HASH_DELIM, l)) == تہی) {
		debug2("extract_salt: missing salt termination character");
		واپس (-1);
	}

	b64len = p - s;
	/* Sanity check */
	اگر (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		واپس (-1);
	}
	b64salt = xmalloc(1 + b64len);
	حافظہ_نقل(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	آزاد(b64salt);
	اگر (ret == -1) {
		debug2("extract_salt: salt decode error");
		واپس (-1);
	}
	اگر (ret != (صحیح)ssh_hmac_بائٹیں(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_بائٹیں(SSH_DIGEST_SHA1), ret);
		واپس (-1);
	}

	واپس (0);
}

حرف *
host_hash(ثابت حرف *host, ثابت حرف *name_from_hostfile, u_int src_len)
{
	ساخت ssh_hmac_ctx *ctx;
	u_char salt[256], نتیجہ[256];
	حرف uu_salt[512], uu_نتیجہ[512];
	حرف *encoded = تہی;
	u_int len;

	len = ssh_digest_بائٹیں(SSH_DIGEST_SHA1);

	اگر (name_from_hostfile == تہی) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} ورنہ {
		/* Extract salt from known host entry */
		اگر (نکالو_salt(name_from_hostfile, src_len, salt,
		    حجم(salt)) == -1)
			واپس (تہی);
	}

	اگر ((ctx = ssh_hmac_آغاز(SSH_DIGEST_SHA1)) == تہی ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, لڑی_لمبائی(host)) < 0 ||
	    ssh_hmac_final(ctx, نتیجہ, حجم(نتیجہ)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	اگر (__b64_ntop(salt, len, uu_salt, حجم(uu_salt)) == -1 ||
	    __b64_ntop(نتیجہ, len, uu_نتیجہ, حجم(uu_نتیجہ)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_نتیجہ);

	واپس (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

صحیح
hostfile_read_کلید(حرف **cpp, u_int *bitsp, ساخت sshkey *ret)
{
	حرف *cp;

	/* Skip leading whitespace. */
	برائے (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	اگر (sshkey_read(ret, &cp) != 0)
		واپس 0;

	/* Skip trailing whitespace. */
	برائے (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	اگر (bitsp != تہی)
		*bitsp = sshkey_سائز(ret);
	واپس 1;
}

ساکن HostkeyMarker
check_markers(حرف **cpp)
{
	حرف marker[32], *sp, *cp = *cpp;
	صحیح ret = MRK_NONE;

	جب (*cp == '@') {
		/* Only one marker is allowed */
		اگر (ret != MRK_NONE)
			واپس MRK_ERROR;
		/* Markers are terminated by whitespace */
		اگر ((sp = strchr(cp, ' ')) == تہی &&
		    (sp = strchr(cp, '\t')) == تہی)
			واپس MRK_ERROR;
		/* Extract marker for comparison */
		اگر (sp <= cp + 1 || sp >= cp + حجم(marker))
			واپس MRK_ERROR;
		حافظہ_نقل(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		اگر (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		ورنہ اگر (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		ورنہ
			واپس MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		برائے (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	واپس ret;
}

ساخت hostkeys *
init_hostkeys(خالی)
{
	ساخت hostkeys *ret = xcalloc(1, حجم(*ret));

	ret->entries = تہی;
	واپس ret;
}

ساخت بھرو_callback_ctx {
	ثابت حرف *host;
	u_long عدد_loaded;
	ساخت hostkeys *hostkeys;
};

ساکن صحیح
ریکارڈ_hostkey(ساخت hostkey_foreach_سطر *l, خالی *_ctx)
{
	ساخت بھرو_callback_ctx *ctx = (ساخت بھرو_callback_ctx *)_ctx;
	ساخت hostkeys *hostkeys = ctx->hostkeys;
	ساخت hostkey_اندراج *tmp;

	اگر (l->حالت_2 == HKF_حالت_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->راستہ, l->linenum);
		واپس 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->کلید), l->راستہ, l->linenum);
	اگر ((tmp = recallocarray(hostkeys->entries, hostkeys->عدد_entries,
	    hostkeys->عدد_entries + 1, حجم(*hostkeys->entries))) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->عدد_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->عدد_entries].file = xstrdup(l->راستہ);
	hostkeys->entries[hostkeys->عدد_entries].سطر = l->linenum;
	hostkeys->entries[hostkeys->عدد_entries].کلید = l->کلید;
	l->کلید = تہی; /* steal it */
	hostkeys->entries[hostkeys->عدد_entries].marker = l->marker;
	hostkeys->entries[hostkeys->عدد_entries].note = l->note;
	hostkeys->عدد_entries++;
	ctx->عدد_loaded++;

	واپس 0;
}

خالی
بھرو_hostkeys_file(ساخت hostkeys *hostkeys, ثابت حرف *host,
    ثابت حرف *راستہ, FILE *f, u_int note)
{
	صحیح r;
	ساخت بھرو_callback_ctx ctx;

	ctx.host = host;
	ctx.عدد_loaded = 0;
	ctx.hostkeys = hostkeys;

	اگر ((r = hostkeys_foreach_file(راستہ, f, ریکارڈ_hostkey, &ctx, host,
	    تہی, HKF_WANT_مطابقت|HKF_WANT_PARSE_کلید, note)) != 0) {
		اگر (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", راستہ);
	}
	اگر (ctx.عدد_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.عدد_loaded, host);
}

خالی
بھرو_hostkeys(ساخت hostkeys *hostkeys, ثابت حرف *host, ثابت حرف *راستہ,
    u_int note)
{
	FILE *f;

	اگر ((f = fopen(راستہ, "r")) == تہی) {
		debug_f("fopen %s: %s", راستہ, strerror(errno));
		واپس;
	}

	بھرو_hostkeys_file(hostkeys, host, راستہ, f, note);
	fclose(f);
}

خالی
free_hostkeys(ساخت hostkeys *hostkeys)
{
	u_int i;

	برائے (i = 0; i < hostkeys->عدد_entries; i++) {
		آزاد(hostkeys->entries[i].host);
		آزاد(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].کلید);
		explicit_bzero(hostkeys->entries + i, حجم(*hostkeys->entries));
	}
	آزاد(hostkeys->entries);
	freezero(hostkeys, حجم(*hostkeys));
}

ساکن صحیح
check_کلید_not_revoked(ساخت hostkeys *hostkeys, ساخت sshkey *k)
{
	صحیح is_cert = sshkey_is_cert(k);
	u_int i;

	برائے (i = 0; i < hostkeys->عدد_entries; i++) {
		اگر (hostkeys->entries[i].marker != MRK_REVOKE)
			جاری;
		اگر (sshkey_equal_عوامی(k, hostkeys->entries[i].کلید))
			واپس -1;
		اگر (is_cert && k != تہی &&
		    sshkey_equal_عوامی(k->cert->signature_کلید,
		    hostkeys->entries[i].کلید))
			واپس -1;
	}
	واپس 0;
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
ساکن Host_حالت
check_hostkeys_by_کلید_or_type(ساخت hostkeys *hostkeys,
    ساخت sshkey *k, صحیح keytype, صحیح nid, ثابت ساخت hostkey_اندراج **ملا)
{
	u_int i;
	Host_حالت انتہا_return = HOST_NEW;
	صحیح want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	اگر (ملا != تہی)
		*ملا = تہی;

	برائے (i = 0; i < hostkeys->عدد_entries; i++) {
		اگر (hostkeys->entries[i].marker != want_marker)
			جاری;
		اگر (k == تہی) {
			اگر (hostkeys->entries[i].کلید->type != keytype)
				جاری;
			اگر (nid != -1 &&
			    sshkey_type_plain(keytype) == کلید_ECDSA &&
			    hostkeys->entries[i].کلید->ecdsa_nid != nid)
				جاری;
			انتہا_return = HOST_ملا;
			اگر (ملا != تہی)
				*ملا = hostkeys->entries + i;
			k = hostkeys->entries[i].کلید;
			توڑو;
		}
		اگر (want_cert) {
			اگر (sshkey_equal_عوامی(k->cert->signature_کلید,
			    hostkeys->entries[i].کلید)) {
				/* A matching CA exists */
				انتہا_return = HOST_OK;
				اگر (ملا != تہی)
					*ملا = hostkeys->entries + i;
				توڑو;
			}
		} ورنہ {
			اگر (sshkey_equal(k, hostkeys->entries[i].کلید)) {
				انتہا_return = HOST_OK;
				اگر (ملا != تہی)
					*ملا = hostkeys->entries + i;
				توڑو;
			}
			/* A non-matching key exists */
			انتہا_return = HOST_بدلا;
			اگر (ملا != تہی)
				*ملا = hostkeys->entries + i;
		}
	}
	اگر (check_کلید_not_revoked(hostkeys, k) != 0) {
		انتہا_return = HOST_REVOKED;
		اگر (ملا != تہی)
			*ملا = تہی;
	}
	واپس انتہا_return;
}

Host_حالت
check_کلید_اندر_hostkeys(ساخت hostkeys *hostkeys, ساخت sshkey *کلید,
    ثابت ساخت hostkey_اندراج **ملا)
{
	اگر (کلید == تہی)
		fatal("no key to look up");
	واپس check_hostkeys_by_کلید_or_type(hostkeys, کلید, 0, -1, ملا);
}

صحیح
lookup_کلید_اندر_hostkeys_by_type(ساخت hostkeys *hostkeys, صحیح keytype, صحیح nid,
    ثابت ساخت hostkey_اندراج **ملا)
{
	واپس (check_hostkeys_by_کلید_or_type(hostkeys, تہی, keytype, nid,
	    ملا) == HOST_ملا);
}

صحیح
lookup_marker_اندر_hostkeys(ساخت hostkeys *hostkeys, صحیح want_marker)
{
	u_int i;

	برائے (i = 0; i < hostkeys->عدد_entries; i++) {
		اگر (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			واپس 1;
	}
	واپس 0;
}

ساکن صحیح
format_host_اندراج(ساخت sshbuf *اندراج_2, ثابت حرف *host, ثابت حرف *ip,
    ثابت ساخت sshkey *کلید, صحیح store_hash)
{
	صحیح r, success = 0;
	حرف *hashed_host = تہی, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	اگر (store_hash) {
		اگر ((hashed_host = host_hash(lhost, تہی, 0)) == تہی) {
			error_f("host_hash failed");
			آزاد(lhost);
			واپس 0;
		}
		اگر ((r = sshbuf_putf(اندراج_2, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ورنہ اگر (ip != تہی) {
		اگر ((r = sshbuf_putf(اندراج_2, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ورنہ {
		اگر ((r = sshbuf_putf(اندراج_2, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	آزاد(hashed_host);
	آزاد(lhost);
	اگر ((r = sshkey_format_متن(کلید, اندراج_2)) == 0)
		success = 1;
	ورنہ
		error_fr(r, "sshkey_write");
	اگر ((r = sshbuf_putf(اندراج_2, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	اگر (success && store_hash && ip != تہی)
		success = format_host_اندراج(اندراج_2, ip, تہی, کلید, 1);
	واپس success;
}

ساکن صحیح
write_host_اندراج(FILE *f, ثابت حرف *host, ثابت حرف *ip,
    ثابت ساخت sshkey *کلید, صحیح store_hash)
{
	صحیح r, success = 0;
	ساخت sshbuf *اندراج_2 = تہی;

	اگر ((اندراج_2 = sshbuf_new()) == تہی)
		fatal_f("allocation failed");
	اگر ((r = format_host_اندراج(اندراج_2, host, ip, کلید, store_hash)) != 1) {
		debug_f("failed to format host entry");
		جاؤ برآمد;
	}
	اگر ((r = fwrite(sshbuf_ptr(اندراج_2), sshbuf_len(اندراج_2), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		جاؤ برآمد;
	}
	success = 1;
 برآمد:
	sshbuf_free(اندراج_2);
	واپس success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
خالی
hostfile_create_user_ssh_dir(ثابت حرف *filename, صحیح notify)
{
	حرف *dotsshdir = تہی, *p;
	سائز_t len;
	ساخت stat st;

	اگر ((p = strrchr(filename, '/')) == تہی)
		واپس;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" راستہ_SSH_USER_DIR, getuid());
	اگر (لڑی_لمبائی(dotsshdir) > len || لڑی_موازنہ(filename, dotsshdir, len) != 0)
		جاؤ برآمد; /* not ~/.ssh prefixed */
	اگر (stat(dotsshdir, &st) == 0)
		جاؤ برآمد; /* dir already exists */
	ورنہ اگر (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	ورنہ {
#اگر_تعریف_شدہ WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#اگر_ختم
		اگر (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		ورنہ اگر (notify)
			logit("Created directory '%s'.", dotsshdir);
#اگر_تعریف_شدہ WITH_SELINUX
		ssh_selinux_setfscreatecon(تہی);
#اگر_ختم
	}
 برآمد:
	آزاد(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
صحیح
جوڑو_host_مقصد_hostfile(ثابت حرف *filename, ثابت حرف *host,
    ثابت ساخت sshkey *کلید, صحیح store_hash)
{
	FILE *f;
	صحیح success, addnl = 0;

	اگر (کلید == تہی)
		واپس 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	اگر ((f = fopen(filename, "a+")) == تہی)
		واپس 0;
	setvbuf(f, تہی, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	اگر (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	اگر (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		واپس 0;
	}
	success = write_host_اندراج(f, host, تہی, کلید, store_hash);
	fclose(f);
	واپس success;
}

ساخت host_delete_ctx {
	FILE *برآمد;
	صحیح quiet;
	ثابت حرف *host, *ip;
	u_int *مطابقت_کلیدیں;	/* mask of HKF_MATCH_* for this key */
	ساخت sshkey * ثابت *کلیدیں;
	سائز_t nkeys;
	صحیح modified;
};

ساکن صحیح
host_delete(ساخت hostkey_foreach_سطر *l, خالی *_ctx)
{
	ساخت host_delete_ctx *ctx = (ساخت host_delete_ctx *)_ctx;
	صحیح loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	سائز_t i;

	/* Don't remove CA and revocation lines */
	اگر (l->حالت_2 == HKF_حالت_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		برائے (i = 0; i < ctx->nkeys; i++) {
			اگر (!sshkey_equal(ctx->کلیدیں[i], l->کلید))
				جاری;
			ctx->مطابقت_کلیدیں[i] |= l->مطابقت;
			fprintf(ctx->برآمد, "%s\n", l->سطر);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->کلید), l->راستہ, l->linenum);
			واپس 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->راستہ, l->linenum, sshkey_type(l->کلید), ctx->host);
		ctx->modified = 1;
		واپس 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	اگر (l->حالت_2 == HKF_حالت_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->راستہ, l->linenum);
	}
	fprintf(ctx->برآمد, "%s\n", l->سطر);
	واپس 0;
}

صحیح
hostfile_replace_entries(ثابت حرف *filename, ثابت حرف *host, ثابت حرف *ip,
    ساخت sshkey **کلیدیں, سائز_t nkeys, صحیح store_hash, صحیح quiet, صحیح hash_alg)
{
	صحیح r, fd, oerrno = 0;
	صحیح loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	ساخت host_delete_ctx ctx;
	حرف *fp = تہی, *عارضی = تہی, *عقب = تہی;
	ثابت حرف *what;
	منوال_t omask;
	سائز_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, حجم(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	اگر ((ctx.مطابقت_کلیدیں = صفر_حافظہ_دو(nkeys, حجم(*ctx.مطابقت_کلیدیں))) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	ctx.کلیدیں = کلیدیں;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	اگر ((r = asprintf(&عارضی, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&عقب, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ fail;
	}

	اگر ((fd = mkstemp(عارضی)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		جاؤ fail;
	}
	اگر ((ctx.برآمد = fdopen(fd, "w")) == تہی) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		جاؤ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	اگر ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_کلید, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		جاؤ fail;
	}

	/* Re-add the requested keys */
	want = HKF_مطابقت_HOST | (ip == تہی ? 0 : HKF_مطابقت_IP);
	برائے (i = 0; i < nkeys; i++) {
		اگر (کلیدیں[i] == تہی || (want & ctx.مطابقت_کلیدیں[i]) == want)
			جاری;
		اگر ((fp = sshkey_fingerprint(کلیدیں[i], hash_alg,
		    SSH_FP_DEFAULT)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ fail;
		}
		/* write host/ip */
		what = "";
		اگر (ctx.مطابقت_کلیدیں[i] == 0) {
			what = "Adding new key";
			اگر (!write_host_اندراج(ctx.برآمد, host, ip,
			    کلیدیں[i], store_hash)) {
				r = SSH_ERR_اندرونی_ERROR;
				جاؤ fail;
			}
		} ورنہ اگر ((want & ~ctx.مطابقت_کلیدیں[i]) == HKF_مطابقت_HOST) {
			what = "Fixing match (hostname)";
			اگر (!write_host_اندراج(ctx.برآمد, host, تہی,
			    کلیدیں[i], store_hash)) {
				r = SSH_ERR_اندرونی_ERROR;
				جاؤ fail;
			}
		} ورنہ اگر ((want & ~ctx.مطابقت_کلیدیں[i]) == HKF_مطابقت_IP) {
			what = "Fixing match (address)";
			اگر (!write_host_اندراج(ctx.برآمد, ip, تہی,
			    کلیدیں[i], store_hash)) {
				r = SSH_ERR_اندرونی_ERROR;
				جاؤ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == تہی ? "" : ",", ip == تہی ? "" : ip, filename,
		    sshkey_ssh_name(کلیدیں[i]), fp);
		آزاد(fp);
		fp = تہی;
		ctx.modified = 1;
	}
	fclose(ctx.برآمد);
	ctx.برآمد = تہی;

	اگر (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		اگر (unlink(عقب) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", عقب, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			جاؤ fail;
		}
		اگر (link(filename, عقب) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    عقب, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			جاؤ fail;
		}
		اگر (rename(عارضی, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", عارضی,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			جاؤ fail;
		}
	} ورنہ {
		/* No changes made; just delete the temporary file */
		اگر (unlink(عارضی) != 0)
			error_f("unlink \"%s\": %s", عارضی, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	اگر (عارضی != تہی && r != 0)
		unlink(عارضی);
	آزاد(عارضی);
	آزاد(عقب);
	آزاد(fp);
	اگر (ctx.برآمد != تہی)
		fclose(ctx.برآمد);
	آزاد(ctx.مطابقت_کلیدیں);
	umask(omask);
	اگر (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	واپس r;
}

ساکن صحیح
مطابقت_maybe_hashed(ثابت حرف *host, ثابت حرف *نام, صحیح *was_hashed)
{
	صحیح hashed = *نام == HASH_DELIM, ret;
	حرف *hashed_host = تہی;
	سائز_t nlen = لڑی_لمبائی(نام);

	اگر (was_hashed != تہی)
		*was_hashed = hashed;
	اگر (hashed) {
		اگر ((hashed_host = host_hash(host, نام, nlen)) == تہی)
			واپس -1;
		ret = (nlen == لڑی_لمبائی(hashed_host) &&
		    لڑی_موازنہ(hashed_host, نام, nlen) == 0);
		آزاد(hashed_host);
		واپس ret;
	}
	واپس مطابقت_hostname(host, نام) == 1;
}

صحیح
hostkeys_foreach_file(ثابت حرف *راستہ, FILE *f, hostkeys_foreach_fn *callback,
    خالی *ctx, ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note)
{
	حرف *سطر = تہی, ktype[128];
	u_long linenum = 0;
	حرف *cp, *cp2;
	u_int kbits;
	صحیح hashed;
	صحیح s, r = 0;
	ساخت hostkey_foreach_سطر lineinfo;
	سائز_t linesize = 0, l;

	memset(&lineinfo, 0, حجم(lineinfo));
	اگر (host == تہی && (options & HKF_WANT_مطابقت) != 0)
		واپس SSH_ERR_INVALID_دلیل;

	جب (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		سطر[strcspn(سطر, "\n")] = '\0';

		آزاد(lineinfo.سطر);
		sshkey_free(lineinfo.کلید);
		memset(&lineinfo, 0, حجم(lineinfo));
		lineinfo.راستہ = راستہ;
		lineinfo.linenum = linenum;
		lineinfo.سطر = xstrdup(سطر);
		lineinfo.marker = MRK_NONE;
		lineinfo.حالت_2 = HKF_حالت_OK;
		lineinfo.keytype = کلید_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		برائے (cp = سطر; *cp == ' ' || *cp == '\t'; cp++)
			;
		اگر (!*cp || *cp == '#' || *cp == '\n') {
			اگر ((options & HKF_WANT_مطابقت) == 0) {
				lineinfo.حالت_2 = HKF_حالت_COMMENT;
				اگر ((r = callback(&lineinfo, ctx)) != 0)
					توڑو;
			}
			جاری;
		}

		اگر ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", راستہ, linenum);
			اگر ((options & HKF_WANT_مطابقت) == 0)
				جاؤ bad;
			جاری;
		}

		/* Find the end of the host name portion. */
		برائے (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		اگر (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", راستہ, linenum);
			اگر ((options & HKF_WANT_مطابقت) == 0)
				جاؤ bad;
			جاری;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		اگر (host != تہی) {
			اگر ((s = مطابقت_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    راستہ, linenum, lineinfo.hosts);
				جاؤ bad;
			}
			اگر (s == 1) {
				lineinfo.حالت_2 = HKF_حالت_MATCHED;
				lineinfo.مطابقت |= HKF_مطابقت_HOST |
				    (hashed ? HKF_مطابقت_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			اگر (ip != تہی) {
				اگر ((s = مطابقت_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", راستہ, linenum,
					    lineinfo.hosts);
					جاؤ bad;
				}
				اگر (s == 1) {
					lineinfo.حالت_2 = HKF_حالت_MATCHED;
					lineinfo.مطابقت |= HKF_مطابقت_IP |
					    (hashed ? HKF_مطابقت_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			اگر ((options & HKF_WANT_مطابقت) != 0 &&
			    lineinfo.حالت_2 != HKF_حالت_MATCHED)
				جاری;
		}

		/* Got a match.  Skip host name and any following whitespace */
		برائے (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		اگر (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    راستہ, linenum);
			جاؤ bad;
		}
		lineinfo.rawkey = cp = cp2;

		اگر ((options & HKF_WANT_PARSE_کلید) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			اگر ((lineinfo.کلید = sshkey_new(کلید_UNSPEC)) == تہی) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				توڑو;
			}
			اگر (!hostfile_read_کلید(&cp, &kbits, lineinfo.کلید)) {
				جاؤ bad;
			}
			lineinfo.keytype = lineinfo.کلید->type;
			lineinfo.comment = cp;
		} ورنہ {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			اگر (l <= 1 || l >= حجم(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				جاؤ bad;
			حافظہ_نقل(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			اگر (lineinfo.keytype == کلید_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				جاؤ bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			برائے (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			اگر (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    راستہ, linenum);
				lineinfo.keytype = کلید_UNSPEC;
			}
			اگر (lineinfo.keytype == کلید_UNSPEC) {
 bad:
				sshkey_free(lineinfo.کلید);
				lineinfo.کلید = تہی;
				lineinfo.حالت_2 = HKF_حالت_INVALID;
				اگر ((r = callback(&lineinfo, ctx)) != 0)
					توڑو;
				جاری;
			}
		}
		اگر ((r = callback(&lineinfo, ctx)) != 0)
			توڑو;
	}
	sshkey_free(lineinfo.کلید);
	آزاد(lineinfo.سطر);
	آزاد(سطر);
	واپس r;
}

صحیح
hostkeys_foreach(ثابت حرف *راستہ, hostkeys_foreach_fn *callback, خالی *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note)
{
	FILE *f;
	صحیح r, oerrno;

	اگر ((f = fopen(راستہ, "r")) == تہی)
		واپس SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", راستہ);
	r = hostkeys_foreach_file(راستہ, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	واپس r;
}
