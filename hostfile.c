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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <netinet/in.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <resolv.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "hmac.h"
#अन्तर्भाव "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

स्थिर पूर्णाङ्क
extract_salt(ध्रुव वर्ण *s, u_int l, u_char *salt, आकार_t salt_len)
{
	वर्ण *p, *b64salt;
	u_int b64len;
	पूर्णाङ्क ret;

	यदि (l < परिमाण(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		प्रत्यागम (-1);
	}
	यदि (वाक्ये_तुलय(s, HASH_MAGIC, परिमाण(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		प्रत्यागम (-1);
	}
	s += परिमाण(HASH_MAGIC) - 1;
	l -= परिमाण(HASH_MAGIC) - 1;
	यदि ((p = memchr(s, HASH_DELIM, l)) == रिक्त) {
		debug2("extract_salt: missing salt termination character");
		प्रत्यागम (-1);
	}

	b64len = p - s;
	/* Sanity check */
	यदि (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		प्रत्यागम (-1);
	}
	b64salt = xmalloc(1 + b64len);
	स्मृतिं_प्रतिलिख(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	मुक्त(b64salt);
	यदि (ret == -1) {
		debug2("extract_salt: salt decode error");
		प्रत्यागम (-1);
	}
	यदि (ret != (पूर्णाङ्क)ssh_hmac_अष्टकानि(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_अष्टकानि(SSH_DIGEST_SHA1), ret);
		प्रत्यागम (-1);
	}

	प्रत्यागम (0);
}

वर्ण *
host_hash(ध्रुव वर्ण *host, ध्रुव वर्ण *name_from_hostfile, u_int src_len)
{
	संरचना ssh_hmac_ctx *ctx;
	u_char salt[256], परिणाम[256];
	वर्ण uu_salt[512], uu_परिणाम[512];
	वर्ण *encoded = रिक्त;
	u_int len;

	len = ssh_digest_अष्टकानि(SSH_DIGEST_SHA1);

	यदि (name_from_hostfile == रिक्त) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} अन्यथा {
		/* Extract salt from known host entry */
		यदि (extract_salt(name_from_hostfile, src_len, salt,
		    परिमाण(salt)) == -1)
			प्रत्यागम (रिक्त);
	}

	यदि ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == रिक्त ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, वाक्यदैर्घ्यम्(host)) < 0 ||
	    ssh_hmac_final(ctx, परिणाम, परिमाण(परिणाम)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	यदि (__b64_ntop(salt, len, uu_salt, परिमाण(uu_salt)) == -1 ||
	    __b64_ntop(परिणाम, len, uu_परिणाम, परिमाण(uu_परिणाम)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_परिणाम);

	प्रत्यागम (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

पूर्णाङ्क
hostfile_read_कुञ्चिका(वर्ण **cpp, u_int *bitsp, संरचना sshkey *ret)
{
	वर्ण *cp;

	/* Skip leading whitespace. */
	प्रति (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	यदि (sshkey_read(ret, &cp) != 0)
		प्रत्यागम 0;

	/* Skip trailing whitespace. */
	प्रति (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	यदि (bitsp != रिक्त)
		*bitsp = sshkey_आकार(ret);
	प्रत्यागम 1;
}

स्थिर HostkeyMarker
check_markers(वर्ण **cpp)
{
	वर्ण marker[32], *sp, *cp = *cpp;
	पूर्णाङ्क ret = MRK_NONE;

	यावत् (*cp == '@') {
		/* Only one marker is allowed */
		यदि (ret != MRK_NONE)
			प्रत्यागम MRK_ERROR;
		/* Markers are terminated by whitespace */
		यदि ((sp = strchr(cp, ' ')) == रिक्त &&
		    (sp = strchr(cp, '\t')) == रिक्त)
			प्रत्यागम MRK_ERROR;
		/* Extract marker for comparison */
		यदि (sp <= cp + 1 || sp >= cp + परिमाण(marker))
			प्रत्यागम MRK_ERROR;
		स्मृतिं_प्रतिलिख(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		यदि (वाक्यं_तुलय(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		अन्यथा यदि (वाक्यं_तुलय(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		अन्यथा
			प्रत्यागम MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		प्रति (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	प्रत्यागम ret;
}

संरचना hostkeys *
init_hostkeys(शून्य)
{
	संरचना hostkeys *ret = xcalloc(1, परिमाण(*ret));

	ret->entries = रिक्त;
	प्रत्यागम ret;
}

संरचना आरोपय_callback_ctx {
	ध्रुव वर्ण *host;
	u_long अङ्कः_loaded;
	संरचना hostkeys *hostkeys;
};

स्थिर पूर्णाङ्क
लेखः_hostkey(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना आरोपय_callback_ctx *ctx = (संरचना आरोपय_callback_ctx *)_ctx;
	संरचना hostkeys *hostkeys = ctx->hostkeys;
	संरचना hostkey_प्रविष्टिः *tmp;

	यदि (l->स्थितिः == HKF_स्थितिः_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->मार्गः, l->linenum);
		प्रत्यागम 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->कुञ्चिका), l->मार्गः, l->linenum);
	यदि ((tmp = recallocarray(hostkeys->entries, hostkeys->अङ्कः_entries,
	    hostkeys->अङ्कः_entries + 1, परिमाण(*hostkeys->entries))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->अङ्कः_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->अङ्कः_entries].file = xstrdup(l->मार्गः);
	hostkeys->entries[hostkeys->अङ्कः_entries].पङ्क्तिः = l->linenum;
	hostkeys->entries[hostkeys->अङ्कः_entries].कुञ्चिका = l->कुञ्चिका;
	l->कुञ्चिका = रिक्त; /* steal it */
	hostkeys->entries[hostkeys->अङ्कः_entries].marker = l->marker;
	hostkeys->entries[hostkeys->अङ्कः_entries].note = l->note;
	hostkeys->अङ्कः_entries++;
	ctx->अङ्कः_loaded++;

	प्रत्यागम 0;
}

शून्य
आरोपय_hostkeys_file(संरचना hostkeys *hostkeys, ध्रुव वर्ण *host,
    ध्रुव वर्ण *मार्गः, FILE *f, u_int note)
{
	पूर्णाङ्क r;
	संरचना आरोपय_callback_ctx ctx;

	ctx.host = host;
	ctx.अङ्कः_loaded = 0;
	ctx.hostkeys = hostkeys;

	यदि ((r = hostkeys_foreach_file(मार्गः, f, लेखः_hostkey, &ctx, host,
	    रिक्त, HKF_WANT_मेलनम्|HKF_WANT_PARSE_कुञ्चिका, note)) != 0) {
		यदि (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", मार्गः);
	}
	यदि (ctx.अङ्कः_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.अङ्कः_loaded, host);
}

शून्य
आरोपय_hostkeys(संरचना hostkeys *hostkeys, ध्रुव वर्ण *host, ध्रुव वर्ण *मार्गः,
    u_int note)
{
	FILE *f;

	यदि ((f = fopen(मार्गः, "r")) == रिक्त) {
		debug_f("fopen %s: %s", मार्गः, strerror(errno));
		प्रत्यागम;
	}

	आरोपय_hostkeys_file(hostkeys, host, मार्गः, f, note);
	fclose(f);
}

शून्य
free_hostkeys(संरचना hostkeys *hostkeys)
{
	u_int i;

	प्रति (i = 0; i < hostkeys->अङ्कः_entries; i++) {
		मुक्त(hostkeys->entries[i].host);
		मुक्त(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].कुञ्चिका);
		explicit_bzero(hostkeys->entries + i, परिमाण(*hostkeys->entries));
	}
	मुक्त(hostkeys->entries);
	freezero(hostkeys, परिमाण(*hostkeys));
}

स्थिर पूर्णाङ्क
check_कुञ्चिका_not_revoked(संरचना hostkeys *hostkeys, संरचना sshkey *k)
{
	पूर्णाङ्क is_cert = sshkey_is_cert(k);
	u_int i;

	प्रति (i = 0; i < hostkeys->अङ्कः_entries; i++) {
		यदि (hostkeys->entries[i].marker != MRK_REVOKE)
			अनुवर्त;
		यदि (sshkey_equal_लौकिकम्(k, hostkeys->entries[i].कुञ्चिका))
			प्रत्यागम -1;
		यदि (is_cert && k != रिक्त &&
		    sshkey_equal_लौकिकम्(k->cert->signature_कुञ्चिका,
		    hostkeys->entries[i].कुञ्चिका))
			प्रत्यागम -1;
	}
	प्रत्यागम 0;
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
स्थिर Host_स्थितिः
check_hostkeys_by_कुञ्चिका_or_type(संरचना hostkeys *hostkeys,
    संरचना sshkey *k, पूर्णाङ्क keytype, पूर्णाङ्क nid, ध्रुव संरचना hostkey_प्रविष्टिः **प्राप्तम्)
{
	u_int i;
	Host_स्थितिः अन्तः_return = HOST_NEW;
	पूर्णाङ्क want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	यदि (प्राप्तम् != रिक्त)
		*प्राप्तम् = रिक्त;

	प्रति (i = 0; i < hostkeys->अङ्कः_entries; i++) {
		यदि (hostkeys->entries[i].marker != want_marker)
			अनुवर्त;
		यदि (k == रिक्त) {
			यदि (hostkeys->entries[i].कुञ्चिका->type != keytype)
				अनुवर्त;
			यदि (nid != -1 &&
			    sshkey_type_plain(keytype) == कुञ्चिका_ECDSA &&
			    hostkeys->entries[i].कुञ्चिका->ecdsa_nid != nid)
				अनुवर्त;
			अन्तः_return = HOST_प्राप्तम्;
			यदि (प्राप्तम् != रिक्त)
				*प्राप्तम् = hostkeys->entries + i;
			k = hostkeys->entries[i].कुञ्चिका;
			भङ्ग;
		}
		यदि (want_cert) {
			यदि (sshkey_equal_लौकिकम्(k->cert->signature_कुञ्चिका,
			    hostkeys->entries[i].कुञ्चिका)) {
				/* A matching CA exists */
				अन्तः_return = HOST_OK;
				यदि (प्राप्तम् != रिक्त)
					*प्राप्तम् = hostkeys->entries + i;
				भङ्ग;
			}
		} अन्यथा {
			यदि (sshkey_equal(k, hostkeys->entries[i].कुञ्चिका)) {
				अन्तः_return = HOST_OK;
				यदि (प्राप्तम् != रिक्त)
					*प्राप्तम् = hostkeys->entries + i;
				भङ्ग;
			}
			/* A non-matching key exists */
			अन्तः_return = HOST_परिवर्तितम्;
			यदि (प्राप्तम् != रिक्त)
				*प्राप्तम् = hostkeys->entries + i;
		}
	}
	यदि (check_कुञ्चिका_not_revoked(hostkeys, k) != 0) {
		अन्तः_return = HOST_REVOKED;
		यदि (प्राप्तम् != रिक्त)
			*प्राप्तम् = रिक्त;
	}
	प्रत्यागम अन्तः_return;
}

Host_स्थितिः
check_कुञ्चिका_अन्तर्_hostkeys(संरचना hostkeys *hostkeys, संरचना sshkey *कुञ्चिका,
    ध्रुव संरचना hostkey_प्रविष्टिः **प्राप्तम्)
{
	यदि (कुञ्चिका == रिक्त)
		fatal("no key to look up");
	प्रत्यागम check_hostkeys_by_कुञ्चिका_or_type(hostkeys, कुञ्चिका, 0, -1, प्राप्तम्);
}

पूर्णाङ्क
lookup_कुञ्चिका_अन्तर्_hostkeys_by_type(संरचना hostkeys *hostkeys, पूर्णाङ्क keytype, पूर्णाङ्क nid,
    ध्रुव संरचना hostkey_प्रविष्टिः **प्राप्तम्)
{
	प्रत्यागम (check_hostkeys_by_कुञ्चिका_or_type(hostkeys, रिक्त, keytype, nid,
	    प्राप्तम्) == HOST_प्राप्तम्);
}

पूर्णाङ्क
lookup_marker_अन्तर्_hostkeys(संरचना hostkeys *hostkeys, पूर्णाङ्क want_marker)
{
	u_int i;

	प्रति (i = 0; i < hostkeys->अङ्कः_entries; i++) {
		यदि (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			प्रत्यागम 1;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
format_host_प्रविष्टिः(संरचना sshbuf *प्रविष्टिः, ध्रुव वर्ण *host, ध्रुव वर्ण *ip,
    ध्रुव संरचना sshkey *कुञ्चिका, पूर्णाङ्क store_hash)
{
	पूर्णाङ्क r, success = 0;
	वर्ण *hashed_host = रिक्त, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	यदि (store_hash) {
		यदि ((hashed_host = host_hash(lhost, रिक्त, 0)) == रिक्त) {
			error_f("host_hash failed");
			मुक्त(lhost);
			प्रत्यागम 0;
		}
		यदि ((r = sshbuf_putf(प्रविष्टिः, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} अन्यथा यदि (ip != रिक्त) {
		यदि ((r = sshbuf_putf(प्रविष्टिः, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} अन्यथा {
		यदि ((r = sshbuf_putf(प्रविष्टिः, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	मुक्त(hashed_host);
	मुक्त(lhost);
	यदि ((r = sshkey_format_text(कुञ्चिका, प्रविष्टिः)) == 0)
		success = 1;
	अन्यथा
		error_fr(r, "sshkey_write");
	यदि ((r = sshbuf_putf(प्रविष्टिः, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	यदि (success && store_hash && ip != रिक्त)
		success = format_host_प्रविष्टिः(प्रविष्टिः, ip, रिक्त, कुञ्चिका, 1);
	प्रत्यागम success;
}

स्थिर पूर्णाङ्क
write_host_प्रविष्टिः(FILE *f, ध्रुव वर्ण *host, ध्रुव वर्ण *ip,
    ध्रुव संरचना sshkey *कुञ्चिका, पूर्णाङ्क store_hash)
{
	पूर्णाङ्क r, success = 0;
	संरचना sshbuf *प्रविष्टिः = रिक्त;

	यदि ((प्रविष्टिः = sshbuf_new()) == रिक्त)
		fatal_f("allocation failed");
	यदि ((r = format_host_प्रविष्टिः(प्रविष्टिः, host, ip, कुञ्चिका, store_hash)) != 1) {
		debug_f("failed to format host entry");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = fwrite(sshbuf_ptr(प्रविष्टिः), sshbuf_len(प्रविष्टिः), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		गच्छ बहिर्गमनम्;
	}
	success = 1;
 बहिर्गमनम्:
	sshbuf_free(प्रविष्टिः);
	प्रत्यागम success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
शून्य
hostfile_create_user_ssh_dir(ध्रुव वर्ण *filename, पूर्णाङ्क notify)
{
	वर्ण *dotsshdir = रिक्त, *p;
	आकार_t len;
	संरचना stat st;

	यदि ((p = strrchr(filename, '/')) == रिक्त)
		प्रत्यागम;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" मार्गः_SSH_USER_DIR, getuid());
	यदि (वाक्यदैर्घ्यम्(dotsshdir) > len || वाक्ये_तुलय(filename, dotsshdir, len) != 0)
		गच्छ बहिर्गमनम्; /* not ~/.ssh prefixed */
	यदि (stat(dotsshdir, &st) == 0)
		गच्छ बहिर्गमनम्; /* dir already exists */
	अन्यथा यदि (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	अन्यथा {
#यदि_परिभाषितम् WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#यदि_अन्तः
		यदि (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		अन्यथा यदि (notify)
			logit("Created directory '%s'.", dotsshdir);
#यदि_परिभाषितम् WITH_SELINUX
		ssh_selinux_setfscreatecon(रिक्त);
#यदि_अन्तः
	}
 बहिर्गमनम्:
	मुक्त(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
पूर्णाङ्क
सङ्कलय_host_गन्तव्यम्_hostfile(ध्रुव वर्ण *filename, ध्रुव वर्ण *host,
    ध्रुव संरचना sshkey *कुञ्चिका, पूर्णाङ्क store_hash)
{
	FILE *f;
	पूर्णाङ्क success, addnl = 0;

	यदि (कुञ्चिका == रिक्त)
		प्रत्यागम 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	यदि ((f = fopen(filename, "a+")) == रिक्त)
		प्रत्यागम 0;
	setvbuf(f, रिक्त, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	यदि (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	यदि (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		प्रत्यागम 0;
	}
	success = write_host_प्रविष्टिः(f, host, रिक्त, कुञ्चिका, store_hash);
	fclose(f);
	प्रत्यागम success;
}

संरचना host_delete_ctx {
	FILE *बहिर्गमनम्;
	पूर्णाङ्क quiet;
	ध्रुव वर्ण *host, *ip;
	u_int *मेलनम्_कुञ्चिकाः;	/* mask of HKF_MATCH_* for this key */
	संरचना sshkey * ध्रुव *कुञ्चिकाः;
	आकार_t nkeys;
	पूर्णाङ्क modified;
};

स्थिर पूर्णाङ्क
host_delete(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना host_delete_ctx *ctx = (संरचना host_delete_ctx *)_ctx;
	पूर्णाङ्क loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	आकार_t i;

	/* Don't remove CA and revocation lines */
	यदि (l->स्थितिः == HKF_स्थितिः_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		प्रति (i = 0; i < ctx->nkeys; i++) {
			यदि (!sshkey_equal(ctx->कुञ्चिकाः[i], l->कुञ्चिका))
				अनुवर्त;
			ctx->मेलनम्_कुञ्चिकाः[i] |= l->मेलनम्;
			fprintf(ctx->बहिर्गमनम्, "%s\n", l->पङ्क्तिः);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->कुञ्चिका), l->मार्गः, l->linenum);
			प्रत्यागम 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->मार्गः, l->linenum, sshkey_type(l->कुञ्चिका), ctx->host);
		ctx->modified = 1;
		प्रत्यागम 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	यदि (l->स्थितिः == HKF_स्थितिः_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->मार्गः, l->linenum);
	}
	fprintf(ctx->बहिर्गमनम्, "%s\n", l->पङ्क्तिः);
	प्रत्यागम 0;
}

पूर्णाङ्क
hostfile_replace_entries(ध्रुव वर्ण *filename, ध्रुव वर्ण *host, ध्रुव वर्ण *ip,
    संरचना sshkey **कुञ्चिकाः, आकार_t nkeys, पूर्णाङ्क store_hash, पूर्णाङ्क quiet, पूर्णाङ्क hash_alg)
{
	पूर्णाङ्क r, fd, oerrno = 0;
	पूर्णाङ्क loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	संरचना host_delete_ctx ctx;
	वर्ण *fp = रिक्त, *अस्थायी = रिक्त, *पृष्ठभागः = रिक्त;
	ध्रुव वर्ण *what;
	बहुलकम्_t omask;
	आकार_t i;
	u_int want;

	omask = umask(077);

	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	यदि ((ctx.मेलनम्_कुञ्चिकाः = शून्यस्मृतिं_देहि(nkeys, परिमाण(*ctx.मेलनम्_कुञ्चिकाः))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	ctx.कुञ्चिकाः = कुञ्चिकाः;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	यदि ((r = asprintf(&अस्थायी, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&पृष्ठभागः, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ fail;
	}

	यदि ((fd = mkstemp(अस्थायी)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ fail;
	}
	यदि ((ctx.बहिर्गमनम् = fdopen(fd, "w")) == रिक्त) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	यदि ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_कुञ्चिका, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		गच्छ fail;
	}

	/* Re-add the requested keys */
	want = HKF_मेलनम्_HOST | (ip == रिक्त ? 0 : HKF_मेलनम्_IP);
	प्रति (i = 0; i < nkeys; i++) {
		यदि (कुञ्चिकाः[i] == रिक्त || (want & ctx.मेलनम्_कुञ्चिकाः[i]) == want)
			अनुवर्त;
		यदि ((fp = sshkey_fingerprint(कुञ्चिकाः[i], hash_alg,
		    SSH_FP_DEFAULT)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ fail;
		}
		/* write host/ip */
		what = "";
		यदि (ctx.मेलनम्_कुञ्चिकाः[i] == 0) {
			what = "Adding new key";
			यदि (!write_host_प्रविष्टिः(ctx.बहिर्गमनम्, host, ip,
			    कुञ्चिकाः[i], store_hash)) {
				r = SSH_ERR_आन्तरिकम्_ERROR;
				गच्छ fail;
			}
		} अन्यथा यदि ((want & ~ctx.मेलनम्_कुञ्चिकाः[i]) == HKF_मेलनम्_HOST) {
			what = "Fixing match (hostname)";
			यदि (!write_host_प्रविष्टिः(ctx.बहिर्गमनम्, host, रिक्त,
			    कुञ्चिकाः[i], store_hash)) {
				r = SSH_ERR_आन्तरिकम्_ERROR;
				गच्छ fail;
			}
		} अन्यथा यदि ((want & ~ctx.मेलनम्_कुञ्चिकाः[i]) == HKF_मेलनम्_IP) {
			what = "Fixing match (address)";
			यदि (!write_host_प्रविष्टिः(ctx.बहिर्गमनम्, ip, रिक्त,
			    कुञ्चिकाः[i], store_hash)) {
				r = SSH_ERR_आन्तरिकम्_ERROR;
				गच्छ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == रिक्त ? "" : ",", ip == रिक्त ? "" : ip, filename,
		    sshkey_ssh_name(कुञ्चिकाः[i]), fp);
		मुक्त(fp);
		fp = रिक्त;
		ctx.modified = 1;
	}
	fclose(ctx.बहिर्गमनम्);
	ctx.बहिर्गमनम् = रिक्त;

	यदि (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		यदि (unlink(पृष्ठभागः) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", पृष्ठभागः, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ fail;
		}
		यदि (link(filename, पृष्ठभागः) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    पृष्ठभागः, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ fail;
		}
		यदि (rename(अस्थायी, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", अस्थायी,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ fail;
		}
	} अन्यथा {
		/* No changes made; just delete the temporary file */
		यदि (unlink(अस्थायी) != 0)
			error_f("unlink \"%s\": %s", अस्थायी, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	यदि (अस्थायी != रिक्त && r != 0)
		unlink(अस्थायी);
	मुक्त(अस्थायी);
	मुक्त(पृष्ठभागः);
	मुक्त(fp);
	यदि (ctx.बहिर्गमनम् != रिक्त)
		fclose(ctx.बहिर्गमनम्);
	मुक्त(ctx.मेलनम्_कुञ्चिकाः);
	umask(omask);
	यदि (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
मेलनम्_maybe_hashed(ध्रुव वर्ण *host, ध्रुव वर्ण *नामानि, पूर्णाङ्क *was_hashed)
{
	पूर्णाङ्क hashed = *नामानि == HASH_DELIM, ret;
	वर्ण *hashed_host = रिक्त;
	आकार_t nlen = वाक्यदैर्घ्यम्(नामानि);

	यदि (was_hashed != रिक्त)
		*was_hashed = hashed;
	यदि (hashed) {
		यदि ((hashed_host = host_hash(host, नामानि, nlen)) == रिक्त)
			प्रत्यागम -1;
		ret = (nlen == वाक्यदैर्घ्यम्(hashed_host) &&
		    वाक्ये_तुलय(hashed_host, नामानि, nlen) == 0);
		मुक्त(hashed_host);
		प्रत्यागम ret;
	}
	प्रत्यागम मेलनम्_hostname(host, नामानि) == 1;
}

पूर्णाङ्क
hostkeys_foreach_file(ध्रुव वर्ण *मार्गः, FILE *f, hostkeys_foreach_fn *callback,
    शून्य *ctx, ध्रुव वर्ण *host, ध्रुव वर्ण *ip, u_int options, u_int note)
{
	वर्ण *पङ्क्तिः = रिक्त, ktype[128];
	u_long linenum = 0;
	वर्ण *cp, *cp2;
	u_int kbits;
	पूर्णाङ्क hashed;
	पूर्णाङ्क s, r = 0;
	संरचना hostkey_foreach_पङ्क्तिः lineinfo;
	आकार_t linesize = 0, l;

	स्मृतिं_पूरय(&lineinfo, 0, परिमाण(lineinfo));
	यदि (host == रिक्त && (options & HKF_WANT_मेलनम्) != 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;

	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		पङ्क्तिः[strcspn(पङ्क्तिः, "\n")] = '\0';

		मुक्त(lineinfo.पङ्क्तिः);
		sshkey_free(lineinfo.कुञ्चिका);
		स्मृतिं_पूरय(&lineinfo, 0, परिमाण(lineinfo));
		lineinfo.मार्गः = मार्गः;
		lineinfo.linenum = linenum;
		lineinfo.पङ्क्तिः = xstrdup(पङ्क्तिः);
		lineinfo.marker = MRK_NONE;
		lineinfo.स्थितिः = HKF_स्थितिः_OK;
		lineinfo.keytype = कुञ्चिका_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		प्रति (cp = पङ्क्तिः; *cp == ' ' || *cp == '\t'; cp++)
			;
		यदि (!*cp || *cp == '#' || *cp == '\n') {
			यदि ((options & HKF_WANT_मेलनम्) == 0) {
				lineinfo.स्थितिः = HKF_स्थितिः_COMMENT;
				यदि ((r = callback(&lineinfo, ctx)) != 0)
					भङ्ग;
			}
			अनुवर्त;
		}

		यदि ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", मार्गः, linenum);
			यदि ((options & HKF_WANT_मेलनम्) == 0)
				गच्छ bad;
			अनुवर्त;
		}

		/* Find the end of the host name portion. */
		प्रति (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		यदि (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", मार्गः, linenum);
			यदि ((options & HKF_WANT_मेलनम्) == 0)
				गच्छ bad;
			अनुवर्त;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		यदि (host != रिक्त) {
			यदि ((s = मेलनम्_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    मार्गः, linenum, lineinfo.hosts);
				गच्छ bad;
			}
			यदि (s == 1) {
				lineinfo.स्थितिः = HKF_स्थितिः_MATCHED;
				lineinfo.मेलनम् |= HKF_मेलनम्_HOST |
				    (hashed ? HKF_मेलनम्_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			यदि (ip != रिक्त) {
				यदि ((s = मेलनम्_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", मार्गः, linenum,
					    lineinfo.hosts);
					गच्छ bad;
				}
				यदि (s == 1) {
					lineinfo.स्थितिः = HKF_स्थितिः_MATCHED;
					lineinfo.मेलनम् |= HKF_मेलनम्_IP |
					    (hashed ? HKF_मेलनम्_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			यदि ((options & HKF_WANT_मेलनम्) != 0 &&
			    lineinfo.स्थितिः != HKF_स्थितिः_MATCHED)
				अनुवर्त;
		}

		/* Got a match.  Skip host name and any following whitespace */
		प्रति (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		यदि (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    मार्गः, linenum);
			गच्छ bad;
		}
		lineinfo.rawkey = cp = cp2;

		यदि ((options & HKF_WANT_PARSE_कुञ्चिका) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			यदि ((lineinfo.कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				भङ्ग;
			}
			यदि (!hostfile_read_कुञ्चिका(&cp, &kbits, lineinfo.कुञ्चिका)) {
				गच्छ bad;
			}
			lineinfo.keytype = lineinfo.कुञ्चिका->type;
			lineinfo.comment = cp;
		} अन्यथा {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			यदि (l <= 1 || l >= परिमाण(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				गच्छ bad;
			स्मृतिं_प्रतिलिख(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			यदि (lineinfo.keytype == कुञ्चिका_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				गच्छ bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			प्रति (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			यदि (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    मार्गः, linenum);
				lineinfo.keytype = कुञ्चिका_UNSPEC;
			}
			यदि (lineinfo.keytype == कुञ्चिका_UNSPEC) {
 bad:
				sshkey_free(lineinfo.कुञ्चिका);
				lineinfo.कुञ्चिका = रिक्त;
				lineinfo.स्थितिः = HKF_स्थितिः_INVALID;
				यदि ((r = callback(&lineinfo, ctx)) != 0)
					भङ्ग;
				अनुवर्त;
			}
		}
		यदि ((r = callback(&lineinfo, ctx)) != 0)
			भङ्ग;
	}
	sshkey_free(lineinfo.कुञ्चिका);
	मुक्त(lineinfo.पङ्क्तिः);
	मुक्त(पङ्क्तिः);
	प्रत्यागम r;
}

पूर्णाङ्क
hostkeys_foreach(ध्रुव वर्ण *मार्गः, hostkeys_foreach_fn *callback, शून्य *ctx,
    ध्रुव वर्ण *host, ध्रुव वर्ण *ip, u_int options, u_int note)
{
	FILE *f;
	पूर्णाङ्क r, oerrno;

	यदि ((f = fopen(मार्गः, "r")) == रिक्त)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", मार्गः);
	r = hostkeys_foreach_file(मार्गः, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	प्रत्यागम r;
}
