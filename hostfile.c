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

स्थिर पूर्णांक
extract_salt(स्थिरांक अक्षर *s, u_int l, u_char *salt, माप_प्रकार salt_len)
{
	अक्षर *p, *b64salt;
	u_int b64len;
	पूर्णांक ret;

	जर (l < आकार(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		परत (-1);
	}
	जर (म_भेदन(s, HASH_MAGIC, आकार(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		परत (-1);
	}
	s += आकार(HASH_MAGIC) - 1;
	l -= आकार(HASH_MAGIC) - 1;
	जर ((p = स_प्रथम(s, HASH_DELIM, l)) == रिक्त) {
		debug2("extract_salt: missing salt termination character");
		परत (-1);
	}

	b64len = p - s;
	/* Sanity check */
	जर (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		परत (-1);
	}
	b64salt = xmalloc(1 + b64len);
	स_नकल(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	मुक्त(b64salt);
	जर (ret == -1) {
		debug2("extract_salt: salt decode error");
		परत (-1);
	}
	जर (ret != (पूर्णांक)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		परत (-1);
	}

	परत (0);
}

अक्षर *
host_hash(स्थिरांक अक्षर *host, स्थिरांक अक्षर *name_from_hostfile, u_int src_len)
{
	संरचना ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	अक्षर uu_salt[512], uu_result[512];
	अक्षर *encoded = रिक्त;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	जर (name_from_hostfile == रिक्त) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} अन्यथा {
		/* Extract salt from known host entry */
		जर (extract_salt(name_from_hostfile, src_len, salt,
		    आकार(salt)) == -1)
			परत (रिक्त);
	}

	जर ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == रिक्त ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, म_माप(host)) < 0 ||
	    ssh_hmac_final(ctx, result, आकार(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	जर (__b64_ntop(salt, len, uu_salt, आकार(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, आकार(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	परत (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

पूर्णांक
hostfile_read_किल्ली(अक्षर **cpp, u_int *bitsp, संरचना sshkey *ret)
{
	अक्षर *cp;

	/* Skip leading whitespace. */
	साठी (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	जर (sshkey_read(ret, &cp) != 0)
		परत 0;

	/* Skip trailing whitespace. */
	साठी (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	जर (bitsp != रिक्त)
		*bitsp = sshkey_size(ret);
	परत 1;
}

स्थिर HostkeyMarker
check_markers(अक्षर **cpp)
{
	अक्षर marker[32], *sp, *cp = *cpp;
	पूर्णांक ret = MRK_NONE;

	पर्यंत (*cp == '@') {
		/* Only one marker is allowed */
		जर (ret != MRK_NONE)
			परत MRK_ERROR;
		/* Markers are terminated by whitespace */
		जर ((sp = म_अक्षर(cp, ' ')) == रिक्त &&
		    (sp = म_अक्षर(cp, '\t')) == रिक्त)
			परत MRK_ERROR;
		/* Extract marker for comparison */
		जर (sp <= cp + 1 || sp >= cp + आकार(marker))
			परत MRK_ERROR;
		स_नकल(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		जर (म_भेद(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		अन्यथा जर (म_भेद(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		अन्यथा
			परत MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		साठी (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	परत ret;
}

संरचना hostkeys *
init_hostkeys(शून्य)
{
	संरचना hostkeys *ret = xcalloc(1, आकार(*ret));

	ret->entries = रिक्त;
	परत ret;
}

संरचना load_callback_ctx {
	स्थिरांक अक्षर *host;
	u_long अंक_loaded;
	संरचना hostkeys *hostkeys;
};

स्थिर पूर्णांक
record_hostkey(संरचना hostkey_foreach_ओळ *l, शून्य *_ctx)
{
	संरचना load_callback_ctx *ctx = (संरचना load_callback_ctx *)_ctx;
	संरचना hostkeys *hostkeys = ctx->hostkeys;
	संरचना hostkey_entry *tmp;

	जर (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		परत 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->किल्ली), l->path, l->linenum);
	जर ((tmp = recallocarray(hostkeys->entries, hostkeys->अंक_entries,
	    hostkeys->अंक_entries + 1, आकार(*hostkeys->entries))) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->अंक_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->अंक_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->अंक_entries].ओळ = l->linenum;
	hostkeys->entries[hostkeys->अंक_entries].किल्ली = l->किल्ली;
	l->किल्ली = रिक्त; /* steal it */
	hostkeys->entries[hostkeys->अंक_entries].marker = l->marker;
	hostkeys->entries[hostkeys->अंक_entries].note = l->note;
	hostkeys->अंक_entries++;
	ctx->अंक_loaded++;

	परत 0;
}

शून्य
load_hostkeys_file(संरचना hostkeys *hostkeys, स्थिरांक अक्षर *host,
    स्थिरांक अक्षर *path, खाता *f, u_int note)
{
	पूर्णांक r;
	संरचना load_callback_ctx ctx;

	ctx.host = host;
	ctx.अंक_loaded = 0;
	ctx.hostkeys = hostkeys;

	जर ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    रिक्त, HKF_WANT_MATCH|HKF_WANT_PARSE_किल्ली, note)) != 0) {
		जर (r != SSH_ERR_SYSTEM_ERROR && त्रुटि_सं != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	जर (ctx.अंक_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.अंक_loaded, host);
}

शून्य
load_hostkeys(संरचना hostkeys *hostkeys, स्थिरांक अक्षर *host, स्थिरांक अक्षर *path,
    u_int note)
{
	खाता *f;

	जर ((f = ख_खोलो(path, "r")) == रिक्त) {
		debug_f("fopen %s: %s", path, म_त्रुटि(त्रुटि_सं));
		परत;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	ख_बंद(f);
}

शून्य
free_hostkeys(संरचना hostkeys *hostkeys)
{
	u_int i;

	साठी (i = 0; i < hostkeys->अंक_entries; i++) {
		मुक्त(hostkeys->entries[i].host);
		मुक्त(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].किल्ली);
		explicit_bzero(hostkeys->entries + i, आकार(*hostkeys->entries));
	}
	मुक्त(hostkeys->entries);
	freezero(hostkeys, आकार(*hostkeys));
}

स्थिर पूर्णांक
check_किल्ली_not_revoked(संरचना hostkeys *hostkeys, संरचना sshkey *k)
{
	पूर्णांक is_cert = sshkey_is_cert(k);
	u_int i;

	साठी (i = 0; i < hostkeys->अंक_entries; i++) {
		जर (hostkeys->entries[i].marker != MRK_REVOKE)
			सुरूठेवा;
		जर (sshkey_equal_public(k, hostkeys->entries[i].किल्ली))
			परत -1;
		जर (is_cert && k != रिक्त &&
		    sshkey_equal_public(k->cert->signature_किल्ली,
		    hostkeys->entries[i].किल्ली))
			परत -1;
	}
	परत 0;
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
check_hostkeys_by_किल्ली_or_type(संरचना hostkeys *hostkeys,
    संरचना sshkey *k, पूर्णांक keytype, पूर्णांक nid, स्थिरांक संरचना hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	पूर्णांक want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	जर (found != रिक्त)
		*found = रिक्त;

	साठी (i = 0; i < hostkeys->अंक_entries; i++) {
		जर (hostkeys->entries[i].marker != want_marker)
			सुरूठेवा;
		जर (k == रिक्त) {
			जर (hostkeys->entries[i].किल्ली->type != keytype)
				सुरूठेवा;
			जर (nid != -1 &&
			    sshkey_type_plain(keytype) == किल्ली_ECDSA &&
			    hostkeys->entries[i].किल्ली->ecdsa_nid != nid)
				सुरूठेवा;
			end_return = HOST_FOUND;
			जर (found != रिक्त)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].किल्ली;
			थांबा;
		}
		जर (want_cert) {
			जर (sshkey_equal_public(k->cert->signature_किल्ली,
			    hostkeys->entries[i].किल्ली)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				जर (found != रिक्त)
					*found = hostkeys->entries + i;
				थांबा;
			}
		} अन्यथा {
			जर (sshkey_equal(k, hostkeys->entries[i].किल्ली)) {
				end_return = HOST_OK;
				जर (found != रिक्त)
					*found = hostkeys->entries + i;
				थांबा;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			जर (found != रिक्त)
				*found = hostkeys->entries + i;
		}
	}
	जर (check_किल्ली_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		जर (found != रिक्त)
			*found = रिक्त;
	}
	परत end_return;
}

HostStatus
check_किल्ली_in_hostkeys(संरचना hostkeys *hostkeys, संरचना sshkey *किल्ली,
    स्थिरांक संरचना hostkey_entry **found)
{
	जर (किल्ली == रिक्त)
		fatal("no key to look up");
	परत check_hostkeys_by_किल्ली_or_type(hostkeys, किल्ली, 0, -1, found);
}

पूर्णांक
lookup_किल्ली_in_hostkeys_by_type(संरचना hostkeys *hostkeys, पूर्णांक keytype, पूर्णांक nid,
    स्थिरांक संरचना hostkey_entry **found)
{
	परत (check_hostkeys_by_किल्ली_or_type(hostkeys, रिक्त, keytype, nid,
	    found) == HOST_FOUND);
}

पूर्णांक
lookup_marker_in_hostkeys(संरचना hostkeys *hostkeys, पूर्णांक want_marker)
{
	u_int i;

	साठी (i = 0; i < hostkeys->अंक_entries; i++) {
		जर (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			परत 1;
	}
	परत 0;
}

स्थिर पूर्णांक
format_host_entry(संरचना sshbuf *entry, स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip,
    स्थिरांक संरचना sshkey *किल्ली, पूर्णांक store_hash)
{
	पूर्णांक r, success = 0;
	अक्षर *hashed_host = रिक्त, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	जर (store_hash) {
		जर ((hashed_host = host_hash(lhost, रिक्त, 0)) == रिक्त) {
			error_f("host_hash failed");
			मुक्त(lhost);
			परत 0;
		}
		जर ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} अन्यथा जर (ip != रिक्त) {
		जर ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} अन्यथा {
		जर ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	मुक्त(hashed_host);
	मुक्त(lhost);
	जर ((r = sshkey_format_text(किल्ली, entry)) == 0)
		success = 1;
	अन्यथा
		error_fr(r, "sshkey_write");
	जर ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	जर (success && store_hash && ip != रिक्त)
		success = format_host_entry(entry, ip, रिक्त, किल्ली, 1);
	परत success;
}

स्थिर पूर्णांक
write_host_entry(खाता *f, स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip,
    स्थिरांक संरचना sshkey *किल्ली, पूर्णांक store_hash)
{
	पूर्णांक r, success = 0;
	संरचना sshbuf *entry = रिक्त;

	जर ((entry = sshbuf_new()) == रिक्त)
		fatal_f("allocation failed");
	जर ((r = format_host_entry(entry, host, ip, किल्ली, store_hash)) != 1) {
		debug_f("failed to format host entry");
		जा out;
	}
	जर ((r = ख_डालो(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	परत success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
शून्य
hostfile_create_user_ssh_dir(स्थिरांक अक्षर *filename, पूर्णांक notify)
{
	अक्षर *dotsshdir = रिक्त, *p;
	माप_प्रकार len;
	संरचना stat st;

	जर ((p = म_खोजप(filename, '/')) == रिक्त)
		परत;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	जर (म_माप(dotsshdir) > len || म_भेदन(filename, dotsshdir, len) != 0)
		जा out; /* not ~/.ssh prefixed */
	जर (stat(dotsshdir, &st) == 0)
		जा out; /* dir already exists */
	अन्यथा जर (त्रुटि_सं != ENOENT)
		error("Could not stat %s: %s", dotsshdir, म_त्रुटि(त्रुटि_सं));
	अन्यथा {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		जर (सूची_गढ़ो(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, म_त्रुटि(त्रुटि_सं));
		अन्यथा जर (notify)
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
पूर्णांक
add_host_to_hostfile(स्थिरांक अक्षर *filename, स्थिरांक अक्षर *host,
    स्थिरांक संरचना sshkey *किल्ली, पूर्णांक store_hash)
{
	खाता *f;
	पूर्णांक success, addnl = 0;

	जर (किल्ली == रिक्त)
		परत 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	जर ((f = ख_खोलो(filename, "a+")) == रिक्त)
		परत 0;
	रखो_भबफ(f, रिक्त, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	जर (ख_जाओ(f, -1L, अंत_से) == 0 && ख_अक्षर_लो(f) != '\n')
		addnl = 1;
	जर (ख_जाओ(f, 0L, अंत_से) != 0 || (addnl && ख_अक्षर_दो('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, म_त्रुटि(त्रुटि_सं));
		ख_बंद(f);
		परत 0;
	}
	success = write_host_entry(f, host, रिक्त, किल्ली, store_hash);
	ख_बंद(f);
	परत success;
}

संरचना host_delete_ctx {
	खाता *out;
	पूर्णांक quiet;
	स्थिरांक अक्षर *host, *ip;
	u_int *match_किल्ल्या;	/* mask of HKF_MATCH_* for this key */
	संरचना sshkey * स्थिरांक *किल्ल्या;
	माप_प्रकार nkeys;
	पूर्णांक modified;
};

स्थिर पूर्णांक
host_delete(संरचना hostkey_foreach_ओळ *l, शून्य *_ctx)
{
	संरचना host_delete_ctx *ctx = (संरचना host_delete_ctx *)_ctx;
	पूर्णांक loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	माप_प्रकार i;

	/* Don't remove CA and revocation lines */
	जर (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		साठी (i = 0; i < ctx->nkeys; i++) {
			जर (!sshkey_equal(ctx->किल्ल्या[i], l->किल्ली))
				सुरूठेवा;
			ctx->match_किल्ल्या[i] |= l->match;
			ख_लिखो(ctx->out, "%s\n", l->ओळ);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->किल्ली), l->path, l->linenum);
			परत 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->किल्ली), ctx->host);
		ctx->modified = 1;
		परत 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	जर (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	ख_लिखो(ctx->out, "%s\n", l->ओळ);
	परत 0;
}

पूर्णांक
hostfile_replace_entries(स्थिरांक अक्षर *filename, स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip,
    संरचना sshkey **किल्ल्या, माप_प्रकार nkeys, पूर्णांक store_hash, पूर्णांक quiet, पूर्णांक hash_alg)
{
	पूर्णांक r, fd, oerrno = 0;
	पूर्णांक loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	संरचना host_delete_ctx ctx;
	अक्षर *fp = रिक्त, *temp = रिक्त, *back = रिक्त;
	स्थिरांक अक्षर *what;
	mode_t omask;
	माप_प्रकार i;
	u_int want;

	omask = umask(077);

	स_रखो(&ctx, 0, आकार(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	जर ((ctx.match_किल्ल्या = सुस्मृति(nkeys, आकार(*ctx.match_किल्ल्या))) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	ctx.किल्ल्या = किल्ल्या;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	जर ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		जा fail;
	}

	जर ((fd = mkstemp(temp)) == -1) {
		oerrno = त्रुटि_सं;
		error_f("mkstemp: %s", म_त्रुटि(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		जा fail;
	}
	जर ((ctx.out = fdopen(fd, "w")) == रिक्त) {
		oerrno = त्रुटि_सं;
		बंद(fd);
		error_f("fdopen: %s", म_त्रुटि(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		जा fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	जर ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_किल्ली, 0)) != 0) {
		oerrno = त्रुटि_सं;
		error_fr(r, "hostkeys_foreach");
		जा fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == रिक्त ? 0 : HKF_MATCH_IP);
	साठी (i = 0; i < nkeys; i++) {
		जर (किल्ल्या[i] == रिक्त || (want & ctx.match_किल्ल्या[i]) == want)
			सुरूठेवा;
		जर ((fp = sshkey_fingerprint(किल्ल्या[i], hash_alg,
		    SSH_FP_DEFAULT)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा fail;
		}
		/* write host/ip */
		what = "";
		जर (ctx.match_किल्ल्या[i] == 0) {
			what = "Adding new key";
			जर (!write_host_entry(ctx.out, host, ip,
			    किल्ल्या[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				जा fail;
			}
		} अन्यथा जर ((want & ~ctx.match_किल्ल्या[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			जर (!write_host_entry(ctx.out, host, रिक्त,
			    किल्ल्या[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				जा fail;
			}
		} अन्यथा जर ((want & ~ctx.match_किल्ल्या[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			जर (!write_host_entry(ctx.out, ip, रिक्त,
			    किल्ल्या[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				जा fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == रिक्त ? "" : ",", ip == रिक्त ? "" : ip, filename,
		    sshkey_ssh_name(किल्ल्या[i]), fp);
		मुक्त(fp);
		fp = रिक्त;
		ctx.modified = 1;
	}
	ख_बंद(ctx.out);
	ctx.out = रिक्त;

	जर (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		जर (unlink(back) == -1 && त्रुटि_सं != ENOENT) {
			oerrno = त्रुटि_सं;
			error_f("unlink %.100s: %s", back, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			जा fail;
		}
		जर (link(filename, back) == -1) {
			oerrno = त्रुटि_सं;
			error_f("link %.100s to %.100s: %s", filename,
			    back, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			जा fail;
		}
		जर (नाम(temp, filename) == -1) {
			oerrno = त्रुटि_सं;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, म_त्रुटि(त्रुटि_सं));
			r = SSH_ERR_SYSTEM_ERROR;
			जा fail;
		}
	} अन्यथा {
		/* No changes made; just delete the temporary file */
		जर (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, म_त्रुटि(त्रुटि_सं));
	}

	/* success */
	r = 0;
 fail:
	जर (temp != रिक्त && r != 0)
		unlink(temp);
	मुक्त(temp);
	मुक्त(back);
	मुक्त(fp);
	जर (ctx.out != रिक्त)
		ख_बंद(ctx.out);
	मुक्त(ctx.match_किल्ल्या);
	umask(omask);
	जर (r == SSH_ERR_SYSTEM_ERROR)
		त्रुटि_सं = oerrno;
	परत r;
}

स्थिर पूर्णांक
match_maybe_hashed(स्थिरांक अक्षर *host, स्थिरांक अक्षर *names, पूर्णांक *was_hashed)
{
	पूर्णांक hashed = *names == HASH_DELIM, ret;
	अक्षर *hashed_host = रिक्त;
	माप_प्रकार nlen = म_माप(names);

	जर (was_hashed != रिक्त)
		*was_hashed = hashed;
	जर (hashed) {
		जर ((hashed_host = host_hash(host, names, nlen)) == रिक्त)
			परत -1;
		ret = (nlen == म_माप(hashed_host) &&
		    म_भेदन(hashed_host, names, nlen) == 0);
		मुक्त(hashed_host);
		परत ret;
	}
	परत match_hostname(host, names) == 1;
}

पूर्णांक
hostkeys_foreach_file(स्थिरांक अक्षर *path, खाता *f, hostkeys_foreach_fn *callback,
    शून्य *ctx, स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip, u_int options, u_int note)
{
	अक्षर *ओळ = रिक्त, ktype[128];
	u_long linenum = 0;
	अक्षर *cp, *cp2;
	u_int kbits;
	पूर्णांक hashed;
	पूर्णांक s, r = 0;
	संरचना hostkey_foreach_ओळ lineinfo;
	माप_प्रकार linesize = 0, l;

	स_रखो(&lineinfo, 0, आकार(lineinfo));
	जर (host == रिक्त && (options & HKF_WANT_MATCH) != 0)
		परत SSH_ERR_INVALID_ARGUMENT;

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		linenum++;
		ओळ[म_खोज(ओळ, "\n")] = '\0';

		मुक्त(lineinfo.ओळ);
		sshkey_free(lineinfo.किल्ली);
		स_रखो(&lineinfo, 0, आकार(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.ओळ = xstrdup(ओळ);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = किल्ली_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		साठी (cp = ओळ; *cp == ' ' || *cp == '\t'; cp++)
			;
		जर (!*cp || *cp == '#' || *cp == '\n') {
			जर ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				जर ((r = callback(&lineinfo, ctx)) != 0)
					थांबा;
			}
			सुरूठेवा;
		}

		जर ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			जर ((options & HKF_WANT_MATCH) == 0)
				जा bad;
			सुरूठेवा;
		}

		/* Find the end of the host name portion. */
		साठी (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		जर (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			जर ((options & HKF_WANT_MATCH) == 0)
				जा bad;
			सुरूठेवा;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		जर (host != रिक्त) {
			जर ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				जा bad;
			}
			जर (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			जर (ip != रिक्त) {
				जर ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					जा bad;
				}
				जर (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			जर ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				सुरूठेवा;
		}

		/* Got a match.  Skip host name and any following whitespace */
		साठी (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		जर (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			जा bad;
		}
		lineinfo.rawkey = cp = cp2;

		जर ((options & HKF_WANT_PARSE_किल्ली) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			जर ((lineinfo.किल्ली = sshkey_new(किल्ली_UNSPEC)) == रिक्त) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				थांबा;
			}
			जर (!hostfile_read_किल्ली(&cp, &kbits, lineinfo.किल्ली)) {
				जा bad;
			}
			lineinfo.keytype = lineinfo.किल्ली->type;
			lineinfo.comment = cp;
		} अन्यथा {
			/* Extract and parse key type */
			l = म_खोज(lineinfo.rawkey, " \t");
			जर (l <= 1 || l >= आकार(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				जा bad;
			स_नकल(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			जर (lineinfo.keytype == किल्ली_UNSPEC && l < 8 &&
			    म_अखोज(ktype, "0123456789") == l)
				जा bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			साठी (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			जर (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = किल्ली_UNSPEC;
			}
			जर (lineinfo.keytype == किल्ली_UNSPEC) {
 bad:
				sshkey_free(lineinfo.किल्ली);
				lineinfo.किल्ली = रिक्त;
				lineinfo.status = HKF_STATUS_INVALID;
				जर ((r = callback(&lineinfo, ctx)) != 0)
					थांबा;
				सुरूठेवा;
			}
		}
		जर ((r = callback(&lineinfo, ctx)) != 0)
			थांबा;
	}
	sshkey_free(lineinfo.किल्ली);
	मुक्त(lineinfo.ओळ);
	मुक्त(ओळ);
	परत r;
}

पूर्णांक
hostkeys_foreach(स्थिरांक अक्षर *path, hostkeys_foreach_fn *callback, शून्य *ctx,
    स्थिरांक अक्षर *host, स्थिरांक अक्षर *ip, u_int options, u_int note)
{
	खाता *f;
	पूर्णांक r, oerrno;

	जर ((f = ख_खोलो(path, "r")) == रिक्त)
		परत SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = त्रुटि_सं;
	ख_बंद(f);
	त्रुटि_सं = oerrno;
	परत r;
}
