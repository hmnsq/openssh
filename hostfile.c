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
extract_salt(ध्रुव वर्ण *s, u_int l, u_char *salt, माप_प्रकार salt_len)
{
	वर्ण *p, *b64salt;
	u_int b64len;
	पूर्णाङ्क ret;

	यदि (l < परिमाण(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		प्रत्यागम (-1);
	}
	यदि (म_भेदन(s, HASH_MAGIC, परिमाण(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		प्रत्यागम (-1);
	}
	s += परिमाण(HASH_MAGIC) - 1;
	l -= परिमाण(HASH_MAGIC) - 1;
	यदि ((p = स_प्रथम(s, HASH_DELIM, l)) == रिक्त) {
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
	स_नकल(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	मुक्त(b64salt);
	यदि (ret == -1) {
		debug2("extract_salt: salt decode error");
		प्रत्यागम (-1);
	}
	यदि (ret != (पूर्णाङ्क)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		प्रत्यागम (-1);
	}

	प्रत्यागम (0);
}

वर्ण *
host_hash(ध्रुव वर्ण *host, ध्रुव वर्ण *name_from_hostfile, u_int src_len)
{
	संरचना ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	वर्ण uu_salt[512], uu_result[512];
	वर्ण *encoded = रिक्त;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

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
	    ssh_hmac_update(ctx, host, म_माप(host)) < 0 ||
	    ssh_hmac_final(ctx, result, परिमाण(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	यदि (__b64_ntop(salt, len, uu_salt, परिमाण(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, परिमाण(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	प्रत्यागम (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

पूर्णाङ्क
hostfile_read_कुंजी(वर्ण **cpp, u_int *bitsp, संरचना sshkey *ret)
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
		*bitsp = sshkey_size(ret);
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
		यदि ((sp = म_अक्षर(cp, ' ')) == रिक्त &&
		    (sp = म_अक्षर(cp, '\t')) == रिक्त)
			प्रत्यागम MRK_ERROR;
		/* Extract marker for comparison */
		यदि (sp <= cp + 1 || sp >= cp + परिमाण(marker))
			प्रत्यागम MRK_ERROR;
		स_नकल(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		यदि (म_भेद(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		अन्यथा यदि (म_भेद(marker, REVOKE_MARKER) == 0)
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

संरचना load_callback_ctx {
	ध्रुव वर्ण *host;
	u_long अंक_loaded;
	संरचना hostkeys *hostkeys;
};

स्थिर पूर्णाङ्क
record_hostkey(संरचना hostkey_foreach_पंक्ति *l, शून्य *_ctx)
{
	संरचना load_callback_ctx *ctx = (संरचना load_callback_ctx *)_ctx;
	संरचना hostkeys *hostkeys = ctx->hostkeys;
	संरचना hostkey_entry *tmp;

	यदि (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		प्रत्यागम 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->कुंजी), l->path, l->linenum);
	यदि ((tmp = recallocarray(hostkeys->entries, hostkeys->अंक_entries,
	    hostkeys->अंक_entries + 1, परिमाण(*hostkeys->entries))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->अंक_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->अंक_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->अंक_entries].पंक्ति = l->linenum;
	hostkeys->entries[hostkeys->अंक_entries].कुंजी = l->कुंजी;
	l->कुंजी = रिक्त; /* steal it */
	hostkeys->entries[hostkeys->अंक_entries].marker = l->marker;
	hostkeys->entries[hostkeys->अंक_entries].note = l->note;
	hostkeys->अंक_entries++;
	ctx->अंक_loaded++;

	प्रत्यागम 0;
}

शून्य
load_hostkeys_file(संरचना hostkeys *hostkeys, ध्रुव वर्ण *host,
    ध्रुव वर्ण *path, खाता *f, u_int note)
{
	पूर्णाङ्क r;
	संरचना load_callback_ctx ctx;

	ctx.host = host;
	ctx.अंक_loaded = 0;
	ctx.hostkeys = hostkeys;

	यदि ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    रिक्त, HKF_WANT_MATCH|HKF_WANT_PARSE_कुंजी, note)) != 0) {
		यदि (r != SSH_ERR_SYSTEM_ERROR && त्रुटि_सं != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	यदि (ctx.अंक_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.अंक_loaded, host);
}

शून्य
load_hostkeys(संरचना hostkeys *hostkeys, ध्रुव वर्ण *host, ध्रुव वर्ण *path,
    u_int note)
{
	खाता *f;

	यदि ((f = ख_खोलो(path, "r")) == रिक्त) {
		debug_f("fopen %s: %s", path, म_त्रुटि(त्रुटि_सं));
		प्रत्यागम;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	ख_बंद(f);
}

शून्य
free_hostkeys(संरचना hostkeys *hostkeys)
{
	u_int i;

	प्रति (i = 0; i < hostkeys->अंक_entries; i++) {
		मुक्त(hostkeys->entries[i].host);
		मुक्त(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].कुंजी);
		explicit_bzero(hostkeys->entries + i, परिमाण(*hostkeys->entries));
	}
	मुक्त(hostkeys->entries);
	freezero(hostkeys, परिमाण(*hostkeys));
}

स्थिर पूर्णाङ्क
check_कुंजी_not_revoked(संरचना hostkeys *hostkeys, संरचना sshkey *k)
{
	पूर्णाङ्क is_cert = sshkey_is_cert(k);
	u_int i;

	प्रति (i = 0; i < hostkeys->अंक_entries; i++) {
		यदि (hostkeys->entries[i].marker != MRK_REVOKE)
			अनुवर्त;
		यदि (sshkey_equal_public(k, hostkeys->entries[i].कुंजी))
			प्रत्यागम -1;
		यदि (is_cert && k != रिक्त &&
		    sshkey_equal_public(k->cert->signature_कुंजी,
		    hostkeys->entries[i].कुंजी))
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
स्थिर HostStatus
check_hostkeys_by_कुंजी_or_type(संरचना hostkeys *hostkeys,
    संरचना sshkey *k, पूर्णाङ्क keytype, पूर्णाङ्क nid, ध्रुव संरचना hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	पूर्णाङ्क want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	यदि (found != रिक्त)
		*found = रिक्त;

	प्रति (i = 0; i < hostkeys->अंक_entries; i++) {
		यदि (hostkeys->entries[i].marker != want_marker)
			अनुवर्त;
		यदि (k == रिक्त) {
			यदि (hostkeys->entries[i].कुंजी->type != keytype)
				अनुवर्त;
			यदि (nid != -1 &&
			    sshkey_type_plain(keytype) == कुंजी_ECDSA &&
			    hostkeys->entries[i].कुंजी->ecdsa_nid != nid)
				अनुवर्त;
			end_return = HOST_FOUND;
			यदि (found != रिक्त)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].कुंजी;
			भङ्ग;
		}
		यदि (want_cert) {
			यदि (sshkey_equal_public(k->cert->signature_कुंजी,
			    hostkeys->entries[i].कुंजी)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				यदि (found != रिक्त)
					*found = hostkeys->entries + i;
				भङ्ग;
			}
		} अन्यथा {
			यदि (sshkey_equal(k, hostkeys->entries[i].कुंजी)) {
				end_return = HOST_OK;
				यदि (found != रिक्त)
					*found = hostkeys->entries + i;
				भङ्ग;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			यदि (found != रिक्त)
				*found = hostkeys->entries + i;
		}
	}
	यदि (check_कुंजी_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		यदि (found != रिक्त)
			*found = रिक्त;
	}
	प्रत्यागम end_return;
}

HostStatus
check_कुंजी_in_hostkeys(संरचना hostkeys *hostkeys, संरचना sshkey *कुंजी,
    ध्रुव संरचना hostkey_entry **found)
{
	यदि (कुंजी == रिक्त)
		fatal("no key to look up");
	प्रत्यागम check_hostkeys_by_कुंजी_or_type(hostkeys, कुंजी, 0, -1, found);
}

पूर्णाङ्क
lookup_कुंजी_in_hostkeys_by_type(संरचना hostkeys *hostkeys, पूर्णाङ्क keytype, पूर्णाङ्क nid,
    ध्रुव संरचना hostkey_entry **found)
{
	प्रत्यागम (check_hostkeys_by_कुंजी_or_type(hostkeys, रिक्त, keytype, nid,
	    found) == HOST_FOUND);
}

पूर्णाङ्क
lookup_marker_in_hostkeys(संरचना hostkeys *hostkeys, पूर्णाङ्क want_marker)
{
	u_int i;

	प्रति (i = 0; i < hostkeys->अंक_entries; i++) {
		यदि (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			प्रत्यागम 1;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
format_host_entry(संरचना sshbuf *entry, ध्रुव वर्ण *host, ध्रुव वर्ण *ip,
    ध्रुव संरचना sshkey *कुंजी, पूर्णाङ्क store_hash)
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
		यदि ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} अन्यथा यदि (ip != रिक्त) {
		यदि ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} अन्यथा {
		यदि ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	मुक्त(hashed_host);
	मुक्त(lhost);
	यदि ((r = sshkey_format_text(कुंजी, entry)) == 0)
		success = 1;
	अन्यथा
		error_fr(r, "sshkey_write");
	यदि ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	यदि (success && store_hash && ip != रिक्त)
		success = format_host_entry(entry, ip, रिक्त, कुंजी, 1);
	प्रत्यागम success;
}

स्थिर पूर्णाङ्क
write_host_entry(खाता *f, ध्रुव वर्ण *host, ध्रुव वर्ण *ip,
    ध्रुव संरचना sshkey *कुंजी, पूर्णाङ्क store_hash)
{
	पूर्णाङ्क r, success = 0;
	संरचना sshbuf *entry = रिक्त;

	यदि ((entry = sshbuf_new()) == रिक्त)
		fatal_f("allocation failed");
	यदि ((r = format_host_entry(entry, host, ip, कुंजी, store_hash)) != 1) {
		debug_f("failed to format host entry");
		गच्छ out;
	}
	यदि ((r = ख_डालो(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", म_त्रुटि(त्रुटि_सं));
		गच्छ out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
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
	माप_प्रकार len;
	संरचना stat st;

	यदि ((p = म_खोजप(filename, '/')) == रिक्त)
		प्रत्यागम;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	यदि (म_माप(dotsshdir) > len || म_भेदन(filename, dotsshdir, len) != 0)
		गच्छ out; /* not ~/.ssh prefixed */
	यदि (stat(dotsshdir, &st) == 0)
		गच्छ out; /* dir already exists */
	अन्यथा यदि (त्रुटि_सं != ENOENT)
		error("Could not stat %s: %s", dotsshdir, म_त्रुटि(त्रुटि_सं));
	अन्यथा {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		यदि (सूची_गढ़ो(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, म_त्रुटि(त्रुटि_सं));
		अन्यथा यदि (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(रिक्त);
#endif
	}
 out:
	मुक्त(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
पूर्णाङ्क
add_host_to_hostfile(ध्रुव वर्ण *filename, ध्रुव वर्ण *host,
    ध्रुव संरचना sshkey *कुंजी, पूर्णाङ्क store_hash)
{
	खाता *f;
	पूर्णाङ्क success, addnl = 0;

	यदि (कुंजी == रिक्त)
		प्रत्यागम 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	यदि ((f = ख_खोलो(filename, "a+")) == रिक्त)
		प्रत्यागम 0;
	रखो_भबफ(f, रिक्त, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	यदि (ख_जाओ(f, -1L, अंत_से) == 0 && ख_अक्षर_लो(f) != '\n')
		addnl = 1;
	यदि (ख_जाओ(f, 0L, अंत_से) != 0 || (addnl && ख_अक्षर_दो('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, म_त्रुटि(त्रुटि_सं));
		ख_बंद(f);
		प्रत्यागम 0;
	}
	success = write_host_entry(f, host, रिक्त, कुंजी, store_hash);
	ख_बंद(f);
	प्रत्यागम success;
}

संरचना host_delete_ctx {
	खाता *out;
	पूर्णाङ्क quiet;
	ध्रुव वर्ण *host, *ip;
	u_int *match_कुंजियाँ;	/* mask of HKF_MATCH_* for this key */
	संरचना sshkey * ध्रुव *कुंजियाँ;
	माप_प्रकार nkeys;
	पूर्णाङ्क modified;
};

स्थिर पूर्णाङ्क
host_delete(संरचना hostkey_foreach_पंक्ति *l, शून्य *_ctx)
{
	संरचना host_delete_ctx *ctx = (संरचना host_delete_ctx *)_ctx;
	पूर्णाङ्क loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	माप_प्रकार i;

	/* Don't remove CA and revocation lines */
	यदि (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		प्रति (i = 0; i < ctx->nkeys; i++) {
			यदि (!sshkey_equal(ctx->कुंजियाँ[i], l->कुंजी))
				अनुवर्त;
			ctx->match_कुंजियाँ[i] |= l->match;
			ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->कुंजी), l->path, l->linenum);
			प्रत्यागम 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->कुंजी), ctx->host);
		ctx->modified = 1;
		प्रत्यागम 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	यदि (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	ख_लिखो(ctx->out, "%s\n", l->पंक्ति);
	प्रत्यागम 0;
}

पूर्णाङ्क
hostfile_replace_entries(ध्रुव वर्ण *filename, ध्रुव वर्ण *host, ध्रुव वर्ण *ip,
    संरचना sshkey **कुंजियाँ, माप_प्रकार nkeys, पूर्णाङ्क store_hash, पूर्णाङ्क quiet, पूर्णाङ्क hash_alg)
{
	पूर्णाङ्क r, fd, oerrno = 0;
	पूर्णाङ्क loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	संरचना host_delete_ctx ctx;
	वर्ण *fp = रिक्त, *temp = रिक्त, *back = रिक्त;
	ध्रुव वर्ण *what;
	mode_t omask;
	माप_प्रकार i;
	u_int want;

	omask = umask(077);

	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	यदि ((ctx.match_कुंजियाँ = सुस्मृति(nkeys, परिमाण(*ctx.match_कुंजियाँ))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	ctx.कुंजियाँ = कुंजियाँ;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	यदि ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ fail;
	}

	यदि ((fd = mkstemp(temp)) == -1) {
		oerrno = त्रुटि_सं;
		error_f("mkstemp: %s", म_त्रुटि(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ fail;
	}
	यदि ((ctx.out = fdopen(fd, "w")) == रिक्त) {
		oerrno = त्रुटि_सं;
		बंद(fd);
		error_f("fdopen: %s", म_त्रुटि(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	यदि ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_कुंजी, 0)) != 0) {
		oerrno = त्रुटि_सं;
		error_fr(r, "hostkeys_foreach");
		गच्छ fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == रिक्त ? 0 : HKF_MATCH_IP);
	प्रति (i = 0; i < nkeys; i++) {
		यदि (कुंजियाँ[i] == रिक्त || (want & ctx.match_कुंजियाँ[i]) == want)
			अनुवर्त;
		यदि ((fp = sshkey_fingerprint(कुंजियाँ[i], hash_alg,
		    SSH_FP_DEFAULT)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ fail;
		}
		/* write host/ip */
		what = "";
		यदि (ctx.match_कुंजियाँ[i] == 0) {
			what = "Adding new key";
			यदि (!write_host_entry(ctx.out, host, ip,
			    कुंजियाँ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				गच्छ fail;
			}
		} अन्यथा यदि ((want & ~ctx.match_कुंजियाँ[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			यदि (!write_host_entry(ctx.out, host, रिक्त,
			    कुंजियाँ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				गच्छ fail;
			}
		} अन्यथा यदि ((want & ~ctx.match_कुंजियाँ[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			यदि (!write_host_entry(ctx.out, ip, रिक्त,
			    कुंजियाँ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				गच्छ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == रिक्त ? "" : ",", ip == रिक्त ? "" : ip, filename,
		    sshkey_ssh_name(कुंजियाँ[i]), fp);
		मुक्त(fp);
		fp = रिक्त;
		ctx.modified = 1;
	}
	ख_बंद(ctx.out);
	ctx.out = रिक्त;

	यदि (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		यदि (unlink(back) == -1 && त्रुटि_सं != ENOENT) {
			oerrno = त्रुटि_सं;
			error_f("unlink %.100s: %s", back, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ fail;
		}
		यदि (link(filename, back) == -1) {
			oerrno = त्रुटि_सं;
			error_f("link %.100s to %.100s: %s", filename,
			    back, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ fail;
		}
		यदि (नाम(temp, filename) == -1) {
			oerrno = त्रुटि_सं;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ fail;
		}
	} अन्यथा {
		/* No changes made; just delete the temporary file */
		यदि (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, म_त्रुटि(त्रुटि_सं));
	}

	/* success */
	r = 0;
 fail:
	यदि (temp != रिक्त && r != 0)
		unlink(temp);
	मुक्त(temp);
	मुक्त(back);
	मुक्त(fp);
	यदि (ctx.out != रिक्त)
		ख_बंद(ctx.out);
	मुक्त(ctx.match_कुंजियाँ);
	umask(omask);
	यदि (r == SSH_ERR_SYSTEM_ERROR)
		त्रुटि_सं = oerrno;
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
match_maybe_hashed(ध्रुव वर्ण *host, ध्रुव वर्ण *names, पूर्णाङ्क *was_hashed)
{
	पूर्णाङ्क hashed = *names == HASH_DELIM, ret;
	वर्ण *hashed_host = रिक्त;
	माप_प्रकार nlen = म_माप(names);

	यदि (was_hashed != रिक्त)
		*was_hashed = hashed;
	यदि (hashed) {
		यदि ((hashed_host = host_hash(host, names, nlen)) == रिक्त)
			प्रत्यागम -1;
		ret = (nlen == म_माप(hashed_host) &&
		    म_भेदन(hashed_host, names, nlen) == 0);
		मुक्त(hashed_host);
		प्रत्यागम ret;
	}
	प्रत्यागम match_hostname(host, names) == 1;
}

पूर्णाङ्क
hostkeys_foreach_file(ध्रुव वर्ण *path, खाता *f, hostkeys_foreach_fn *callback,
    शून्य *ctx, ध्रुव वर्ण *host, ध्रुव वर्ण *ip, u_int options, u_int note)
{
	वर्ण *पंक्ति = रिक्त, ktype[128];
	u_long linenum = 0;
	वर्ण *cp, *cp2;
	u_int kbits;
	पूर्णाङ्क hashed;
	पूर्णाङ्क s, r = 0;
	संरचना hostkey_foreach_पंक्ति lineinfo;
	माप_प्रकार linesize = 0, l;

	स_रखो(&lineinfo, 0, परिमाण(lineinfo));
	यदि (host == रिक्त && (options & HKF_WANT_MATCH) != 0)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	यावत् (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		पंक्ति[म_खोज(पंक्ति, "\n")] = '\0';

		मुक्त(lineinfo.पंक्ति);
		sshkey_free(lineinfo.कुंजी);
		स_रखो(&lineinfo, 0, परिमाण(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.पंक्ति = xstrdup(पंक्ति);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = कुंजी_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		प्रति (cp = पंक्ति; *cp == ' ' || *cp == '\t'; cp++)
			;
		यदि (!*cp || *cp == '#' || *cp == '\n') {
			यदि ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				यदि ((r = callback(&lineinfo, ctx)) != 0)
					भङ्ग;
			}
			अनुवर्त;
		}

		यदि ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			यदि ((options & HKF_WANT_MATCH) == 0)
				गच्छ bad;
			अनुवर्त;
		}

		/* Find the end of the host name portion. */
		प्रति (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		यदि (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			यदि ((options & HKF_WANT_MATCH) == 0)
				गच्छ bad;
			अनुवर्त;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		यदि (host != रिक्त) {
			यदि ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				गच्छ bad;
			}
			यदि (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			यदि (ip != रिक्त) {
				यदि ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					गच्छ bad;
				}
				यदि (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			यदि ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				अनुवर्त;
		}

		/* Got a match.  Skip host name and any following whitespace */
		प्रति (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		यदि (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			गच्छ bad;
		}
		lineinfo.rawkey = cp = cp2;

		यदि ((options & HKF_WANT_PARSE_कुंजी) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			यदि ((lineinfo.कुंजी = sshkey_new(कुंजी_UNSPEC)) == रिक्त) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				भङ्ग;
			}
			यदि (!hostfile_read_कुंजी(&cp, &kbits, lineinfo.कुंजी)) {
				गच्छ bad;
			}
			lineinfo.keytype = lineinfo.कुंजी->type;
			lineinfo.comment = cp;
		} अन्यथा {
			/* Extract and parse key type */
			l = म_खोज(lineinfo.rawkey, " \t");
			यदि (l <= 1 || l >= परिमाण(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				गच्छ bad;
			स_नकल(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			यदि (lineinfo.keytype == कुंजी_UNSPEC && l < 8 &&
			    म_अखोज(ktype, "0123456789") == l)
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
				    path, linenum);
				lineinfo.keytype = कुंजी_UNSPEC;
			}
			यदि (lineinfo.keytype == कुंजी_UNSPEC) {
 bad:
				sshkey_free(lineinfo.कुंजी);
				lineinfo.कुंजी = रिक्त;
				lineinfo.status = HKF_STATUS_INVALID;
				यदि ((r = callback(&lineinfo, ctx)) != 0)
					भङ्ग;
				अनुवर्त;
			}
		}
		यदि ((r = callback(&lineinfo, ctx)) != 0)
			भङ्ग;
	}
	sshkey_free(lineinfo.कुंजी);
	मुक्त(lineinfo.पंक्ति);
	मुक्त(पंक्ति);
	प्रत्यागम r;
}

पूर्णाङ्क
hostkeys_foreach(ध्रुव वर्ण *path, hostkeys_foreach_fn *callback, शून्य *ctx,
    ध्रुव वर्ण *host, ध्रुव वर्ण *ip, u_int options, u_int note)
{
	खाता *f;
	पूर्णाङ्क r, oerrno;

	यदि ((f = ख_खोलो(path, "r")) == रिक्त)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = त्रुटि_सं;
	ख_बंद(f);
	त्रुटि_सं = oerrno;
	प्रत्यागम r;
}
