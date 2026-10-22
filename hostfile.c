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
استخراج_salt(ثابت حرف *s, u_int l, u_char *salt, اندازه_t salt_len)
{
	حرف *p, *b64salt;
	u_int b64len;
	صحيح ret;

	إذا (l < حجم(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		أرجع (-1);
	}
	إذا (مقایسه_رشته(s, HASH_MAGIC, حجم(HASH_MAGIC) - 1) != 0) {
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
	کپی_حافظه(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	حرر(b64salt);
	إذا (ret == -1) {
		debug2("extract_salt: salt decode error");
		أرجع (-1);
	}
	إذا (ret != (صحيح)ssh_hmac_بایتها(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_بایتها(SSH_DIGEST_SHA1), ret);
		أرجع (-1);
	}

	أرجع (0);
}

حرف *
host_hash(ثابت حرف *host, ثابت حرف *name_from_hostfile, u_int src_len)
{
	بنية ssh_hmac_ctx *ctx;
	u_char salt[256], نتیجه[256];
	حرف uu_salt[512], uu_نتیجه[512];
	حرف *encoded = عدم;
	u_int len;

	len = ssh_digest_بایتها(SSH_DIGEST_SHA1);

	إذا (name_from_hostfile == عدم) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} وإلا {
		/* Extract salt from known host entry */
		إذا (استخراج_salt(name_from_hostfile, src_len, salt,
		    حجم(salt)) == -1)
			أرجع (عدم);
	}

	إذا ((ctx = ssh_hmac_شروع(SSH_DIGEST_SHA1)) == عدم ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, طول_رشته(host)) < 0 ||
	    ssh_hmac_final(ctx, نتیجه, حجم(نتیجه)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	إذا (__b64_ntop(salt, len, uu_salt, حجم(uu_salt)) == -1 ||
	    __b64_ntop(نتیجه, len, uu_نتیجه, حجم(uu_نتیجه)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_نتیجه);

	أرجع (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

صحيح
hostfile_read_کلید(حرف **cpp, u_int *bitsp, بنية sshkey *ret)
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
		*bitsp = sshkey_اندازه(ret);
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
		کپی_حافظه(marker, cp, sp - cp);
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

بنية بارگیری_callback_ctx {
	ثابت حرف *host;
	u_long رقم_loaded;
	بنية hostkeys *hostkeys;
};

ساكن صحيح
رکورد_hostkey(بنية hostkey_foreach_سطر *l, فراغ *_ctx)
{
	بنية بارگیری_callback_ctx *ctx = (بنية بارگیری_callback_ctx *)_ctx;
	بنية hostkeys *hostkeys = ctx->hostkeys;
	بنية hostkey_مدخل *tmp;

	إذا (l->وضعیت == HKF_وضعیت_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->مسیر, l->linenum);
		أرجع 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->کلید), l->مسیر, l->linenum);
	إذا ((tmp = recallocarray(hostkeys->entries, hostkeys->رقم_entries,
	    hostkeys->رقم_entries + 1, حجم(*hostkeys->entries))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->رقم_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->رقم_entries].file = xstrdup(l->مسیر);
	hostkeys->entries[hostkeys->رقم_entries].سطر = l->linenum;
	hostkeys->entries[hostkeys->رقم_entries].کلید = l->کلید;
	l->کلید = عدم; /* steal it */
	hostkeys->entries[hostkeys->رقم_entries].marker = l->marker;
	hostkeys->entries[hostkeys->رقم_entries].note = l->note;
	hostkeys->رقم_entries++;
	ctx->رقم_loaded++;

	أرجع 0;
}

فراغ
بارگیری_hostkeys_file(بنية hostkeys *hostkeys, ثابت حرف *host,
    ثابت حرف *مسیر, FILE *f, u_int note)
{
	صحيح r;
	بنية بارگیری_callback_ctx ctx;

	ctx.host = host;
	ctx.رقم_loaded = 0;
	ctx.hostkeys = hostkeys;

	إذا ((r = hostkeys_foreach_file(مسیر, f, رکورد_hostkey, &ctx, host,
	    عدم, HKF_WANT_تطابق|HKF_WANT_PARSE_کلید, note)) != 0) {
		إذا (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", مسیر);
	}
	إذا (ctx.رقم_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.رقم_loaded, host);
}

فراغ
بارگیری_hostkeys(بنية hostkeys *hostkeys, ثابت حرف *host, ثابت حرف *مسیر,
    u_int note)
{
	FILE *f;

	إذا ((f = fopen(مسیر, "r")) == عدم) {
		debug_f("fopen %s: %s", مسیر, strerror(errno));
		أرجع;
	}

	بارگیری_hostkeys_file(hostkeys, host, مسیر, f, note);
	fclose(f);
}

فراغ
free_hostkeys(بنية hostkeys *hostkeys)
{
	u_int i;

	لكل (i = 0; i < hostkeys->رقم_entries; i++) {
		حرر(hostkeys->entries[i].host);
		حرر(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].کلید);
		explicit_bzero(hostkeys->entries + i, حجم(*hostkeys->entries));
	}
	حرر(hostkeys->entries);
	freezero(hostkeys, حجم(*hostkeys));
}

ساكن صحيح
check_کلید_not_revoked(بنية hostkeys *hostkeys, بنية sshkey *k)
{
	صحيح is_cert = sshkey_is_cert(k);
	u_int i;

	لكل (i = 0; i < hostkeys->رقم_entries; i++) {
		إذا (hostkeys->entries[i].marker != MRK_REVOKE)
			استمر;
		إذا (sshkey_equal_عمومی(k, hostkeys->entries[i].کلید))
			أرجع -1;
		إذا (is_cert && k != عدم &&
		    sshkey_equal_عمومی(k->cert->signature_کلید,
		    hostkeys->entries[i].کلید))
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
ساكن Host_وضعیت
check_hostkeys_by_کلید_or_type(بنية hostkeys *hostkeys,
    بنية sshkey *k, صحيح keytype, صحيح nid, ثابت بنية hostkey_مدخل **یافت)
{
	u_int i;
	Host_وضعیت انتها_return = HOST_NEW;
	صحيح want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	إذا (یافت != عدم)
		*یافت = عدم;

	لكل (i = 0; i < hostkeys->رقم_entries; i++) {
		إذا (hostkeys->entries[i].marker != want_marker)
			استمر;
		إذا (k == عدم) {
			إذا (hostkeys->entries[i].کلید->type != keytype)
				استمر;
			إذا (nid != -1 &&
			    sshkey_type_plain(keytype) == کلید_ECDSA &&
			    hostkeys->entries[i].کلید->ecdsa_nid != nid)
				استمر;
			انتها_return = HOST_یافت;
			إذا (یافت != عدم)
				*یافت = hostkeys->entries + i;
			k = hostkeys->entries[i].کلید;
			اكسر;
		}
		إذا (want_cert) {
			إذا (sshkey_equal_عمومی(k->cert->signature_کلید,
			    hostkeys->entries[i].کلید)) {
				/* A matching CA exists */
				انتها_return = HOST_OK;
				إذا (یافت != عدم)
					*یافت = hostkeys->entries + i;
				اكسر;
			}
		} وإلا {
			إذا (sshkey_equal(k, hostkeys->entries[i].کلید)) {
				انتها_return = HOST_OK;
				إذا (یافت != عدم)
					*یافت = hostkeys->entries + i;
				اكسر;
			}
			/* A non-matching key exists */
			انتها_return = HOST_تغییریافته;
			إذا (یافت != عدم)
				*یافت = hostkeys->entries + i;
		}
	}
	إذا (check_کلید_not_revoked(hostkeys, k) != 0) {
		انتها_return = HOST_REVOKED;
		إذا (یافت != عدم)
			*یافت = عدم;
	}
	أرجع انتها_return;
}

Host_وضعیت
check_کلید_درون_hostkeys(بنية hostkeys *hostkeys, بنية sshkey *کلید,
    ثابت بنية hostkey_مدخل **یافت)
{
	إذا (کلید == عدم)
		fatal("no key to look up");
	أرجع check_hostkeys_by_کلید_or_type(hostkeys, کلید, 0, -1, یافت);
}

صحيح
lookup_کلید_درون_hostkeys_by_type(بنية hostkeys *hostkeys, صحيح keytype, صحيح nid,
    ثابت بنية hostkey_مدخل **یافت)
{
	أرجع (check_hostkeys_by_کلید_or_type(hostkeys, عدم, keytype, nid,
	    یافت) == HOST_یافت);
}

صحيح
lookup_marker_درون_hostkeys(بنية hostkeys *hostkeys, صحيح want_marker)
{
	u_int i;

	لكل (i = 0; i < hostkeys->رقم_entries; i++) {
		إذا (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			أرجع 1;
	}
	أرجع 0;
}

ساكن صحيح
format_host_مدخل(بنية sshbuf *مدخل, ثابت حرف *host, ثابت حرف *ip,
    ثابت بنية sshkey *کلید, صحيح store_hash)
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
		إذا ((r = sshbuf_putf(مدخل, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} وإلا إذا (ip != عدم) {
		إذا ((r = sshbuf_putf(مدخل, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} وإلا {
		إذا ((r = sshbuf_putf(مدخل, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	حرر(hashed_host);
	حرر(lhost);
	إذا ((r = sshkey_format_متن(کلید, مدخل)) == 0)
		success = 1;
	وإلا
		error_fr(r, "sshkey_write");
	إذا ((r = sshbuf_putf(مدخل, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	إذا (success && store_hash && ip != عدم)
		success = format_host_مدخل(مدخل, ip, عدم, کلید, 1);
	أرجع success;
}

ساكن صحيح
write_host_مدخل(FILE *f, ثابت حرف *host, ثابت حرف *ip,
    ثابت بنية sshkey *کلید, صحيح store_hash)
{
	صحيح r, success = 0;
	بنية sshbuf *مدخل = عدم;

	إذا ((مدخل = sshbuf_new()) == عدم)
		fatal_f("allocation failed");
	إذا ((r = format_host_مدخل(مدخل, host, ip, کلید, store_hash)) != 1) {
		debug_f("failed to format host entry");
		اذهب بیرون;
	}
	إذا ((r = fwrite(sshbuf_ptr(مدخل), sshbuf_len(مدخل), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		اذهب بیرون;
	}
	success = 1;
 بیرون:
	sshbuf_free(مدخل);
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
	اندازه_t len;
	بنية stat st;

	إذا ((p = strrchr(filename, '/')) == عدم)
		أرجع;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" مسیر_SSH_USER_DIR, getuid());
	إذا (طول_رشته(dotsshdir) > len || مقایسه_رشته(filename, dotsshdir, len) != 0)
		اذهب بیرون; /* not ~/.ssh prefixed */
	إذا (stat(dotsshdir, &st) == 0)
		اذهب بیرون; /* dir already exists */
	وإلا إذا (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	وإلا {
#اگر_تعریف_شده WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#پایان_اگر
		إذا (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		وإلا إذا (notify)
			logit("Created directory '%s'.", dotsshdir);
#اگر_تعریف_شده WITH_SELINUX
		ssh_selinux_setfscreatecon(عدم);
#پایان_اگر
	}
 بیرون:
	حرر(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
صحيح
جمع_کن_host_مقصد_hostfile(ثابت حرف *filename, ثابت حرف *host,
    ثابت بنية sshkey *کلید, صحيح store_hash)
{
	FILE *f;
	صحيح success, addnl = 0;

	إذا (کلید == عدم)
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
	success = write_host_مدخل(f, host, عدم, کلید, store_hash);
	fclose(f);
	أرجع success;
}

بنية host_delete_ctx {
	FILE *بیرون;
	صحيح quiet;
	ثابت حرف *host, *ip;
	u_int *تطابق_کلیدها;	/* mask of HKF_MATCH_* for this key */
	بنية sshkey * ثابت *کلیدها;
	اندازه_t nkeys;
	صحيح modified;
};

ساكن صحيح
host_delete(بنية hostkey_foreach_سطر *l, فراغ *_ctx)
{
	بنية host_delete_ctx *ctx = (بنية host_delete_ctx *)_ctx;
	صحيح loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	اندازه_t i;

	/* Don't remove CA and revocation lines */
	إذا (l->وضعیت == HKF_وضعیت_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		لكل (i = 0; i < ctx->nkeys; i++) {
			إذا (!sshkey_equal(ctx->کلیدها[i], l->کلید))
				استمر;
			ctx->تطابق_کلیدها[i] |= l->تطابق;
			fprintf(ctx->بیرون, "%s\n", l->سطر);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->کلید), l->مسیر, l->linenum);
			أرجع 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->مسیر, l->linenum, sshkey_type(l->کلید), ctx->host);
		ctx->modified = 1;
		أرجع 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	إذا (l->وضعیت == HKF_وضعیت_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->مسیر, l->linenum);
	}
	fprintf(ctx->بیرون, "%s\n", l->سطر);
	أرجع 0;
}

صحيح
hostfile_replace_entries(ثابت حرف *filename, ثابت حرف *host, ثابت حرف *ip,
    بنية sshkey **کلیدها, اندازه_t nkeys, صحيح store_hash, صحيح quiet, صحيح hash_alg)
{
	صحيح r, fd, oerrno = 0;
	صحيح loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	بنية host_delete_ctx ctx;
	حرف *fp = عدم, *موقت = عدم, *پشت = عدم;
	ثابت حرف *what;
	نما_t omask;
	اندازه_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, حجم(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	إذا ((ctx.تطابق_کلیدها = حافظه_صفر_بده(nkeys, حجم(*ctx.تطابق_کلیدها))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	ctx.کلیدها = کلیدها;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	إذا ((r = asprintf(&موقت, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&پشت, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب fail;
	}

	إذا ((fd = mkstemp(موقت)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}
	إذا ((ctx.بیرون = fdopen(fd, "w")) == عدم) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	إذا ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_کلید, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		اذهب fail;
	}

	/* Re-add the requested keys */
	want = HKF_تطابق_HOST | (ip == عدم ? 0 : HKF_تطابق_IP);
	لكل (i = 0; i < nkeys; i++) {
		إذا (کلیدها[i] == عدم || (want & ctx.تطابق_کلیدها[i]) == want)
			استمر;
		إذا ((fp = sshkey_fingerprint(کلیدها[i], hash_alg,
		    SSH_FP_DEFAULT)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب fail;
		}
		/* write host/ip */
		what = "";
		إذا (ctx.تطابق_کلیدها[i] == 0) {
			what = "Adding new key";
			إذا (!write_host_مدخل(ctx.بیرون, host, ip,
			    کلیدها[i], store_hash)) {
				r = SSH_ERR_داخلی_ERROR;
				اذهب fail;
			}
		} وإلا إذا ((want & ~ctx.تطابق_کلیدها[i]) == HKF_تطابق_HOST) {
			what = "Fixing match (hostname)";
			إذا (!write_host_مدخل(ctx.بیرون, host, عدم,
			    کلیدها[i], store_hash)) {
				r = SSH_ERR_داخلی_ERROR;
				اذهب fail;
			}
		} وإلا إذا ((want & ~ctx.تطابق_کلیدها[i]) == HKF_تطابق_IP) {
			what = "Fixing match (address)";
			إذا (!write_host_مدخل(ctx.بیرون, ip, عدم,
			    کلیدها[i], store_hash)) {
				r = SSH_ERR_داخلی_ERROR;
				اذهب fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == عدم ? "" : ",", ip == عدم ? "" : ip, filename,
		    sshkey_ssh_name(کلیدها[i]), fp);
		حرر(fp);
		fp = عدم;
		ctx.modified = 1;
	}
	fclose(ctx.بیرون);
	ctx.بیرون = عدم;

	إذا (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		إذا (unlink(پشت) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", پشت, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
		إذا (link(filename, پشت) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    پشت, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
		إذا (rename(موقت, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", موقت,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
	} وإلا {
		/* No changes made; just delete the temporary file */
		إذا (unlink(موقت) != 0)
			error_f("unlink \"%s\": %s", موقت, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	إذا (موقت != عدم && r != 0)
		unlink(موقت);
	حرر(موقت);
	حرر(پشت);
	حرر(fp);
	إذا (ctx.بیرون != عدم)
		fclose(ctx.بیرون);
	حرر(ctx.تطابق_کلیدها);
	umask(omask);
	إذا (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	أرجع r;
}

ساكن صحيح
تطابق_maybe_hashed(ثابت حرف *host, ثابت حرف *نامها, صحيح *was_hashed)
{
	صحيح hashed = *نامها == HASH_DELIM, ret;
	حرف *hashed_host = عدم;
	اندازه_t nlen = طول_رشته(نامها);

	إذا (was_hashed != عدم)
		*was_hashed = hashed;
	إذا (hashed) {
		إذا ((hashed_host = host_hash(host, نامها, nlen)) == عدم)
			أرجع -1;
		ret = (nlen == طول_رشته(hashed_host) &&
		    مقایسه_رشته(hashed_host, نامها, nlen) == 0);
		حرر(hashed_host);
		أرجع ret;
	}
	أرجع تطابق_hostname(host, نامها) == 1;
}

صحيح
hostkeys_foreach_file(ثابت حرف *مسیر, FILE *f, hostkeys_foreach_fn *callback,
    فراغ *ctx, ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note)
{
	حرف *سطر = عدم, ktype[128];
	u_long linenum = 0;
	حرف *cp, *cp2;
	u_int kbits;
	صحيح hashed;
	صحيح s, r = 0;
	بنية hostkey_foreach_سطر lineinfo;
	اندازه_t linesize = 0, l;

	memset(&lineinfo, 0, حجم(lineinfo));
	إذا (host == عدم && (options & HKF_WANT_تطابق) != 0)
		أرجع SSH_ERR_INVALID_آرگومان;

	طالما (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		سطر[strcspn(سطر, "\n")] = '\0';

		حرر(lineinfo.سطر);
		sshkey_free(lineinfo.کلید);
		memset(&lineinfo, 0, حجم(lineinfo));
		lineinfo.مسیر = مسیر;
		lineinfo.linenum = linenum;
		lineinfo.سطر = xstrdup(سطر);
		lineinfo.marker = MRK_NONE;
		lineinfo.وضعیت = HKF_وضعیت_OK;
		lineinfo.keytype = کلید_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		لكل (cp = سطر; *cp == ' ' || *cp == '\t'; cp++)
			;
		إذا (!*cp || *cp == '#' || *cp == '\n') {
			إذا ((options & HKF_WANT_تطابق) == 0) {
				lineinfo.وضعیت = HKF_وضعیت_COMMENT;
				إذا ((r = callback(&lineinfo, ctx)) != 0)
					اكسر;
			}
			استمر;
		}

		إذا ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", مسیر, linenum);
			إذا ((options & HKF_WANT_تطابق) == 0)
				اذهب bad;
			استمر;
		}

		/* Find the end of the host name portion. */
		لكل (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		إذا (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", مسیر, linenum);
			إذا ((options & HKF_WANT_تطابق) == 0)
				اذهب bad;
			استمر;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		إذا (host != عدم) {
			إذا ((s = تطابق_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    مسیر, linenum, lineinfo.hosts);
				اذهب bad;
			}
			إذا (s == 1) {
				lineinfo.وضعیت = HKF_وضعیت_MATCHED;
				lineinfo.تطابق |= HKF_تطابق_HOST |
				    (hashed ? HKF_تطابق_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			إذا (ip != عدم) {
				إذا ((s = تطابق_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", مسیر, linenum,
					    lineinfo.hosts);
					اذهب bad;
				}
				إذا (s == 1) {
					lineinfo.وضعیت = HKF_وضعیت_MATCHED;
					lineinfo.تطابق |= HKF_تطابق_IP |
					    (hashed ? HKF_تطابق_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			إذا ((options & HKF_WANT_تطابق) != 0 &&
			    lineinfo.وضعیت != HKF_وضعیت_MATCHED)
				استمر;
		}

		/* Got a match.  Skip host name and any following whitespace */
		لكل (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		إذا (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    مسیر, linenum);
			اذهب bad;
		}
		lineinfo.rawkey = cp = cp2;

		إذا ((options & HKF_WANT_PARSE_کلید) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			إذا ((lineinfo.کلید = sshkey_new(کلید_UNSPEC)) == عدم) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				اكسر;
			}
			إذا (!hostfile_read_کلید(&cp, &kbits, lineinfo.کلید)) {
				اذهب bad;
			}
			lineinfo.keytype = lineinfo.کلید->type;
			lineinfo.comment = cp;
		} وإلا {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			إذا (l <= 1 || l >= حجم(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				اذهب bad;
			کپی_حافظه(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			إذا (lineinfo.keytype == کلید_UNSPEC && l < 8 &&
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
				    مسیر, linenum);
				lineinfo.keytype = کلید_UNSPEC;
			}
			إذا (lineinfo.keytype == کلید_UNSPEC) {
 bad:
				sshkey_free(lineinfo.کلید);
				lineinfo.کلید = عدم;
				lineinfo.وضعیت = HKF_وضعیت_INVALID;
				إذا ((r = callback(&lineinfo, ctx)) != 0)
					اكسر;
				استمر;
			}
		}
		إذا ((r = callback(&lineinfo, ctx)) != 0)
			اكسر;
	}
	sshkey_free(lineinfo.کلید);
	حرر(lineinfo.سطر);
	حرر(سطر);
	أرجع r;
}

صحيح
hostkeys_foreach(ثابت حرف *مسیر, hostkeys_foreach_fn *callback, فراغ *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note)
{
	FILE *f;
	صحيح r, oerrno;

	إذا ((f = fopen(مسیر, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", مسیر);
	r = hostkeys_foreach_file(مسیر, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	أرجع r;
}
