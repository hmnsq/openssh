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
ڪڍو_salt(ثابت حرف *s, u_int l, u_char *salt, سائيز_t salt_len)
{
	حرف *p, *b64salt;
	u_int b64len;
	صحيح ret;

	إذا (l < حجم(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		أرجع (-1);
	}
	إذا (لڙي_ڀيٽ(s, HASH_MAGIC, حجم(HASH_MAGIC) - 1) != 0) {
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
	يادگيري_نقل(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	حرر(b64salt);
	إذا (ret == -1) {
		debug2("extract_salt: salt decode error");
		أرجع (-1);
	}
	إذا (ret != (صحيح)ssh_hmac_بائيٽون(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_بائيٽون(SSH_DIGEST_SHA1), ret);
		أرجع (-1);
	}

	أرجع (0);
}

حرف *
host_hash(ثابت حرف *host, ثابت حرف *name_from_hostfile, u_int src_len)
{
	بنية ssh_hmac_ctx *ctx;
	u_char salt[256], نتيجو[256];
	حرف uu_salt[512], uu_نتيجو[512];
	حرف *encoded = عدم;
	u_int len;

	len = ssh_digest_بائيٽون(SSH_DIGEST_SHA1);

	إذا (name_from_hostfile == عدم) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} وإلا {
		/* Extract salt from known host entry */
		إذا (ڪڍو_salt(name_from_hostfile, src_len, salt,
		    حجم(salt)) == -1)
			أرجع (عدم);
	}

	إذا ((ctx = ssh_hmac_شروعات(SSH_DIGEST_SHA1)) == عدم ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, لڙي_ڊيگهه(host)) < 0 ||
	    ssh_hmac_final(ctx, نتيجو, حجم(نتيجو)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	إذا (__b64_ntop(salt, len, uu_salt, حجم(uu_salt)) == -1 ||
	    __b64_ntop(نتيجو, len, uu_نتيجو, حجم(uu_نتيجو)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_نتيجو);

	أرجع (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

صحيح
hostfile_read_ڪنجي(حرف **cpp, u_int *bitsp, بنية sshkey *ret)
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
		*bitsp = sshkey_سائيز(ret);
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
		يادگيري_نقل(marker, cp, sp - cp);
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

بنية ڀريو_callback_ctx {
	ثابت حرف *host;
	u_long انگ_loaded;
	بنية hostkeys *hostkeys;
};

ساكن صحيح
رڪارڊ_hostkey(بنية hostkey_foreach_سٽ *l, فراغ *_ctx)
{
	بنية ڀريو_callback_ctx *ctx = (بنية ڀريو_callback_ctx *)_ctx;
	بنية hostkeys *hostkeys = ctx->hostkeys;
	بنية hostkey_داخلا *tmp;

	إذا (l->حالت == HKF_حالت_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->رستو, l->linenum);
		أرجع 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->ڪنجي), l->رستو, l->linenum);
	إذا ((tmp = recallocarray(hostkeys->entries, hostkeys->انگ_entries,
	    hostkeys->انگ_entries + 1, حجم(*hostkeys->entries))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->انگ_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->انگ_entries].file = xstrdup(l->رستو);
	hostkeys->entries[hostkeys->انگ_entries].سٽ = l->linenum;
	hostkeys->entries[hostkeys->انگ_entries].ڪنجي = l->ڪنجي;
	l->ڪنجي = عدم; /* steal it */
	hostkeys->entries[hostkeys->انگ_entries].marker = l->marker;
	hostkeys->entries[hostkeys->انگ_entries].note = l->note;
	hostkeys->انگ_entries++;
	ctx->انگ_loaded++;

	أرجع 0;
}

فراغ
ڀريو_hostkeys_file(بنية hostkeys *hostkeys, ثابت حرف *host,
    ثابت حرف *رستو, FILE *f, u_int note)
{
	صحيح r;
	بنية ڀريو_callback_ctx ctx;

	ctx.host = host;
	ctx.انگ_loaded = 0;
	ctx.hostkeys = hostkeys;

	إذا ((r = hostkeys_foreach_file(رستو, f, رڪارڊ_hostkey, &ctx, host,
	    عدم, HKF_WANT_ميلاپ|HKF_WANT_PARSE_ڪنجي, note)) != 0) {
		إذا (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", رستو);
	}
	إذا (ctx.انگ_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.انگ_loaded, host);
}

فراغ
ڀريو_hostkeys(بنية hostkeys *hostkeys, ثابت حرف *host, ثابت حرف *رستو,
    u_int note)
{
	FILE *f;

	إذا ((f = fopen(رستو, "r")) == عدم) {
		debug_f("fopen %s: %s", رستو, strerror(errno));
		أرجع;
	}

	ڀريو_hostkeys_file(hostkeys, host, رستو, f, note);
	fclose(f);
}

فراغ
free_hostkeys(بنية hostkeys *hostkeys)
{
	u_int i;

	لكل (i = 0; i < hostkeys->انگ_entries; i++) {
		حرر(hostkeys->entries[i].host);
		حرر(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].ڪنجي);
		explicit_bzero(hostkeys->entries + i, حجم(*hostkeys->entries));
	}
	حرر(hostkeys->entries);
	freezero(hostkeys, حجم(*hostkeys));
}

ساكن صحيح
check_ڪنجي_not_revoked(بنية hostkeys *hostkeys, بنية sshkey *k)
{
	صحيح is_cert = sshkey_is_cert(k);
	u_int i;

	لكل (i = 0; i < hostkeys->انگ_entries; i++) {
		إذا (hostkeys->entries[i].marker != MRK_REVOKE)
			استمر;
		إذا (sshkey_equal_عوامي(k, hostkeys->entries[i].ڪنجي))
			أرجع -1;
		إذا (is_cert && k != عدم &&
		    sshkey_equal_عوامي(k->cert->signature_ڪنجي,
		    hostkeys->entries[i].ڪنجي))
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
ساكن Host_حالت
check_hostkeys_by_ڪنجي_or_type(بنية hostkeys *hostkeys,
    بنية sshkey *k, صحيح keytype, صحيح nid, ثابت بنية hostkey_داخلا **مليو)
{
	u_int i;
	Host_حالت پڇاڙي_return = HOST_NEW;
	صحيح want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	إذا (مليو != عدم)
		*مليو = عدم;

	لكل (i = 0; i < hostkeys->انگ_entries; i++) {
		إذا (hostkeys->entries[i].marker != want_marker)
			استمر;
		إذا (k == عدم) {
			إذا (hostkeys->entries[i].ڪنجي->type != keytype)
				استمر;
			إذا (nid != -1 &&
			    sshkey_type_plain(keytype) == ڪنجي_ECDSA &&
			    hostkeys->entries[i].ڪنجي->ecdsa_nid != nid)
				استمر;
			پڇاڙي_return = HOST_مليو;
			إذا (مليو != عدم)
				*مليو = hostkeys->entries + i;
			k = hostkeys->entries[i].ڪنجي;
			اكسر;
		}
		إذا (want_cert) {
			إذا (sshkey_equal_عوامي(k->cert->signature_ڪنجي,
			    hostkeys->entries[i].ڪنجي)) {
				/* A matching CA exists */
				پڇاڙي_return = HOST_OK;
				إذا (مليو != عدم)
					*مليو = hostkeys->entries + i;
				اكسر;
			}
		} وإلا {
			إذا (sshkey_equal(k, hostkeys->entries[i].ڪنجي)) {
				پڇاڙي_return = HOST_OK;
				إذا (مليو != عدم)
					*مليو = hostkeys->entries + i;
				اكسر;
			}
			/* A non-matching key exists */
			پڇاڙي_return = HOST_بدليو;
			إذا (مليو != عدم)
				*مليو = hostkeys->entries + i;
		}
	}
	إذا (check_ڪنجي_not_revoked(hostkeys, k) != 0) {
		پڇاڙي_return = HOST_REVOKED;
		إذا (مليو != عدم)
			*مليو = عدم;
	}
	أرجع پڇاڙي_return;
}

Host_حالت
check_ڪنجي_اندريون_hostkeys(بنية hostkeys *hostkeys, بنية sshkey *ڪنجي,
    ثابت بنية hostkey_داخلا **مليو)
{
	إذا (ڪنجي == عدم)
		fatal("no key to look up");
	أرجع check_hostkeys_by_ڪنجي_or_type(hostkeys, ڪنجي, 0, -1, مليو);
}

صحيح
lookup_ڪنجي_اندريون_hostkeys_by_type(بنية hostkeys *hostkeys, صحيح keytype, صحيح nid,
    ثابت بنية hostkey_داخلا **مليو)
{
	أرجع (check_hostkeys_by_ڪنجي_or_type(hostkeys, عدم, keytype, nid,
	    مليو) == HOST_مليو);
}

صحيح
lookup_marker_اندريون_hostkeys(بنية hostkeys *hostkeys, صحيح want_marker)
{
	u_int i;

	لكل (i = 0; i < hostkeys->انگ_entries; i++) {
		إذا (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			أرجع 1;
	}
	أرجع 0;
}

ساكن صحيح
format_host_داخلا(بنية sshbuf *داخلا, ثابت حرف *host, ثابت حرف *ip,
    ثابت بنية sshkey *ڪنجي, صحيح store_hash)
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
		إذا ((r = sshbuf_putf(داخلا, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} وإلا إذا (ip != عدم) {
		إذا ((r = sshbuf_putf(داخلا, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} وإلا {
		إذا ((r = sshbuf_putf(داخلا, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	حرر(hashed_host);
	حرر(lhost);
	إذا ((r = sshkey_format_متن(ڪنجي, داخلا)) == 0)
		success = 1;
	وإلا
		error_fr(r, "sshkey_write");
	إذا ((r = sshbuf_putf(داخلا, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	إذا (success && store_hash && ip != عدم)
		success = format_host_داخلا(داخلا, ip, عدم, ڪنجي, 1);
	أرجع success;
}

ساكن صحيح
write_host_داخلا(FILE *f, ثابت حرف *host, ثابت حرف *ip,
    ثابت بنية sshkey *ڪنجي, صحيح store_hash)
{
	صحيح r, success = 0;
	بنية sshbuf *داخلا = عدم;

	إذا ((داخلا = sshbuf_new()) == عدم)
		fatal_f("allocation failed");
	إذا ((r = format_host_داخلا(داخلا, host, ip, ڪنجي, store_hash)) != 1) {
		debug_f("failed to format host entry");
		اذهب ٻاهريون;
	}
	إذا ((r = fwrite(sshbuf_ptr(داخلا), sshbuf_len(داخلا), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		اذهب ٻاهريون;
	}
	success = 1;
 ٻاهريون:
	sshbuf_free(داخلا);
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
	سائيز_t len;
	بنية stat st;

	إذا ((p = strrchr(filename, '/')) == عدم)
		أرجع;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" رستو_SSH_USER_DIR, getuid());
	إذا (لڙي_ڊيگهه(dotsshdir) > len || لڙي_ڀيٽ(filename, dotsshdir, len) != 0)
		اذهب ٻاهريون; /* not ~/.ssh prefixed */
	إذا (stat(dotsshdir, &st) == 0)
		اذهب ٻاهريون; /* dir already exists */
	وإلا إذا (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	وإلا {
#جيڪڏهن_وصف_ٿيل WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#جيڪڏهن_پورو
		إذا (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		وإلا إذا (notify)
			logit("Created directory '%s'.", dotsshdir);
#جيڪڏهن_وصف_ٿيل WITH_SELINUX
		ssh_selinux_setfscreatecon(عدم);
#جيڪڏهن_پورو
	}
 ٻاهريون:
	حرر(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
صحيح
جوڙيو_host_منزل_hostfile(ثابت حرف *filename, ثابت حرف *host,
    ثابت بنية sshkey *ڪنجي, صحيح store_hash)
{
	FILE *f;
	صحيح success, addnl = 0;

	إذا (ڪنجي == عدم)
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
	success = write_host_داخلا(f, host, عدم, ڪنجي, store_hash);
	fclose(f);
	أرجع success;
}

بنية host_delete_ctx {
	FILE *ٻاهريون;
	صحيح quiet;
	ثابت حرف *host, *ip;
	u_int *ميلاپ_ڪنجيون;	/* mask of HKF_MATCH_* for this key */
	بنية sshkey * ثابت *ڪنجيون;
	سائيز_t nkeys;
	صحيح modified;
};

ساكن صحيح
host_delete(بنية hostkey_foreach_سٽ *l, فراغ *_ctx)
{
	بنية host_delete_ctx *ctx = (بنية host_delete_ctx *)_ctx;
	صحيح loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	سائيز_t i;

	/* Don't remove CA and revocation lines */
	إذا (l->حالت == HKF_حالت_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		لكل (i = 0; i < ctx->nkeys; i++) {
			إذا (!sshkey_equal(ctx->ڪنجيون[i], l->ڪنجي))
				استمر;
			ctx->ميلاپ_ڪنجيون[i] |= l->ميلاپ;
			fprintf(ctx->ٻاهريون, "%s\n", l->سٽ);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->ڪنجي), l->رستو, l->linenum);
			أرجع 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->رستو, l->linenum, sshkey_type(l->ڪنجي), ctx->host);
		ctx->modified = 1;
		أرجع 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	إذا (l->حالت == HKF_حالت_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->رستو, l->linenum);
	}
	fprintf(ctx->ٻاهريون, "%s\n", l->سٽ);
	أرجع 0;
}

صحيح
hostfile_replace_entries(ثابت حرف *filename, ثابت حرف *host, ثابت حرف *ip,
    بنية sshkey **ڪنجيون, سائيز_t nkeys, صحيح store_hash, صحيح quiet, صحيح hash_alg)
{
	صحيح r, fd, oerrno = 0;
	صحيح loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	بنية host_delete_ctx ctx;
	حرف *fp = عدم, *عارضي = عدم, *پٺ = عدم;
	ثابت حرف *what;
	گهڻائي_t omask;
	سائيز_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, حجم(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	إذا ((ctx.ميلاپ_ڪنجيون = صفر_يادگيري_ڏيو(nkeys, حجم(*ctx.ميلاپ_ڪنجيون))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	ctx.ڪنجيون = ڪنجيون;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	إذا ((r = asprintf(&عارضي, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&پٺ, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب fail;
	}

	إذا ((fd = mkstemp(عارضي)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}
	إذا ((ctx.ٻاهريون = fdopen(fd, "w")) == عدم) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	إذا ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_ڪنجي, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		اذهب fail;
	}

	/* Re-add the requested keys */
	want = HKF_ميلاپ_HOST | (ip == عدم ? 0 : HKF_ميلاپ_IP);
	لكل (i = 0; i < nkeys; i++) {
		إذا (ڪنجيون[i] == عدم || (want & ctx.ميلاپ_ڪنجيون[i]) == want)
			استمر;
		إذا ((fp = sshkey_fingerprint(ڪنجيون[i], hash_alg,
		    SSH_FP_DEFAULT)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب fail;
		}
		/* write host/ip */
		what = "";
		إذا (ctx.ميلاپ_ڪنجيون[i] == 0) {
			what = "Adding new key";
			إذا (!write_host_داخلا(ctx.ٻاهريون, host, ip,
			    ڪنجيون[i], store_hash)) {
				r = SSH_ERR_اندروني_ERROR;
				اذهب fail;
			}
		} وإلا إذا ((want & ~ctx.ميلاپ_ڪنجيون[i]) == HKF_ميلاپ_HOST) {
			what = "Fixing match (hostname)";
			إذا (!write_host_داخلا(ctx.ٻاهريون, host, عدم,
			    ڪنجيون[i], store_hash)) {
				r = SSH_ERR_اندروني_ERROR;
				اذهب fail;
			}
		} وإلا إذا ((want & ~ctx.ميلاپ_ڪنجيون[i]) == HKF_ميلاپ_IP) {
			what = "Fixing match (address)";
			إذا (!write_host_داخلا(ctx.ٻاهريون, ip, عدم,
			    ڪنجيون[i], store_hash)) {
				r = SSH_ERR_اندروني_ERROR;
				اذهب fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == عدم ? "" : ",", ip == عدم ? "" : ip, filename,
		    sshkey_ssh_name(ڪنجيون[i]), fp);
		حرر(fp);
		fp = عدم;
		ctx.modified = 1;
	}
	fclose(ctx.ٻاهريون);
	ctx.ٻاهريون = عدم;

	إذا (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		إذا (unlink(پٺ) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", پٺ, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
		إذا (link(filename, پٺ) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    پٺ, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
		إذا (rename(عارضي, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", عارضي,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب fail;
		}
	} وإلا {
		/* No changes made; just delete the temporary file */
		إذا (unlink(عارضي) != 0)
			error_f("unlink \"%s\": %s", عارضي, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	إذا (عارضي != عدم && r != 0)
		unlink(عارضي);
	حرر(عارضي);
	حرر(پٺ);
	حرر(fp);
	إذا (ctx.ٻاهريون != عدم)
		fclose(ctx.ٻاهريون);
	حرر(ctx.ميلاپ_ڪنجيون);
	umask(omask);
	إذا (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	أرجع r;
}

ساكن صحيح
ميلاپ_maybe_hashed(ثابت حرف *host, ثابت حرف *نالا, صحيح *was_hashed)
{
	صحيح hashed = *نالا == HASH_DELIM, ret;
	حرف *hashed_host = عدم;
	سائيز_t nlen = لڙي_ڊيگهه(نالا);

	إذا (was_hashed != عدم)
		*was_hashed = hashed;
	إذا (hashed) {
		إذا ((hashed_host = host_hash(host, نالا, nlen)) == عدم)
			أرجع -1;
		ret = (nlen == لڙي_ڊيگهه(hashed_host) &&
		    لڙي_ڀيٽ(hashed_host, نالا, nlen) == 0);
		حرر(hashed_host);
		أرجع ret;
	}
	أرجع ميلاپ_hostname(host, نالا) == 1;
}

صحيح
hostkeys_foreach_file(ثابت حرف *رستو, FILE *f, hostkeys_foreach_fn *callback,
    فراغ *ctx, ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note)
{
	حرف *سٽ = عدم, ktype[128];
	u_long linenum = 0;
	حرف *cp, *cp2;
	u_int kbits;
	صحيح hashed;
	صحيح s, r = 0;
	بنية hostkey_foreach_سٽ lineinfo;
	سائيز_t linesize = 0, l;

	memset(&lineinfo, 0, حجم(lineinfo));
	إذا (host == عدم && (options & HKF_WANT_ميلاپ) != 0)
		أرجع SSH_ERR_INVALID_دليل;

	طالما (getline(&سٽ, &linesize, f) != -1) {
		linenum++;
		سٽ[strcspn(سٽ, "\n")] = '\0';

		حرر(lineinfo.سٽ);
		sshkey_free(lineinfo.ڪنجي);
		memset(&lineinfo, 0, حجم(lineinfo));
		lineinfo.رستو = رستو;
		lineinfo.linenum = linenum;
		lineinfo.سٽ = xstrdup(سٽ);
		lineinfo.marker = MRK_NONE;
		lineinfo.حالت = HKF_حالت_OK;
		lineinfo.keytype = ڪنجي_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		لكل (cp = سٽ; *cp == ' ' || *cp == '\t'; cp++)
			;
		إذا (!*cp || *cp == '#' || *cp == '\n') {
			إذا ((options & HKF_WANT_ميلاپ) == 0) {
				lineinfo.حالت = HKF_حالت_COMMENT;
				إذا ((r = callback(&lineinfo, ctx)) != 0)
					اكسر;
			}
			استمر;
		}

		إذا ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", رستو, linenum);
			إذا ((options & HKF_WANT_ميلاپ) == 0)
				اذهب bad;
			استمر;
		}

		/* Find the end of the host name portion. */
		لكل (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		إذا (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", رستو, linenum);
			إذا ((options & HKF_WANT_ميلاپ) == 0)
				اذهب bad;
			استمر;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		إذا (host != عدم) {
			إذا ((s = ميلاپ_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    رستو, linenum, lineinfo.hosts);
				اذهب bad;
			}
			إذا (s == 1) {
				lineinfo.حالت = HKF_حالت_MATCHED;
				lineinfo.ميلاپ |= HKF_ميلاپ_HOST |
				    (hashed ? HKF_ميلاپ_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			إذا (ip != عدم) {
				إذا ((s = ميلاپ_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", رستو, linenum,
					    lineinfo.hosts);
					اذهب bad;
				}
				إذا (s == 1) {
					lineinfo.حالت = HKF_حالت_MATCHED;
					lineinfo.ميلاپ |= HKF_ميلاپ_IP |
					    (hashed ? HKF_ميلاپ_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			إذا ((options & HKF_WANT_ميلاپ) != 0 &&
			    lineinfo.حالت != HKF_حالت_MATCHED)
				استمر;
		}

		/* Got a match.  Skip host name and any following whitespace */
		لكل (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		إذا (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    رستو, linenum);
			اذهب bad;
		}
		lineinfo.rawkey = cp = cp2;

		إذا ((options & HKF_WANT_PARSE_ڪنجي) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			إذا ((lineinfo.ڪنجي = sshkey_new(ڪنجي_UNSPEC)) == عدم) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				اكسر;
			}
			إذا (!hostfile_read_ڪنجي(&cp, &kbits, lineinfo.ڪنجي)) {
				اذهب bad;
			}
			lineinfo.keytype = lineinfo.ڪنجي->type;
			lineinfo.comment = cp;
		} وإلا {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			إذا (l <= 1 || l >= حجم(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				اذهب bad;
			يادگيري_نقل(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			إذا (lineinfo.keytype == ڪنجي_UNSPEC && l < 8 &&
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
				    رستو, linenum);
				lineinfo.keytype = ڪنجي_UNSPEC;
			}
			إذا (lineinfo.keytype == ڪنجي_UNSPEC) {
 bad:
				sshkey_free(lineinfo.ڪنجي);
				lineinfo.ڪنجي = عدم;
				lineinfo.حالت = HKF_حالت_INVALID;
				إذا ((r = callback(&lineinfo, ctx)) != 0)
					اكسر;
				استمر;
			}
		}
		إذا ((r = callback(&lineinfo, ctx)) != 0)
			اكسر;
	}
	sshkey_free(lineinfo.ڪنجي);
	حرر(lineinfo.سٽ);
	حرر(سٽ);
	أرجع r;
}

صحيح
hostkeys_foreach(ثابت حرف *رستو, hostkeys_foreach_fn *callback, فراغ *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note)
{
	FILE *f;
	صحيح r, oerrno;

	إذا ((f = fopen(رستو, "r")) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", رستو);
	r = hostkeys_foreach_file(رستو, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	أرجع r;
}
