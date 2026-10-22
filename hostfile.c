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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <netinet/in.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <resolv.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "hmac.h"
#અન્તર્ભાવ "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

સ્થિર પૂર્ણાંક
extract_salt(અચલ અક્ષર *s, u_int l, u_char *salt, size_t salt_len)
{
	અક્ષર *p, *b64salt;
	u_int b64len;
	પૂર્ણાંક ret;

	જો (l < કદ(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		પાછા (-1);
	}
	જો (strncmp(s, HASH_MAGIC, કદ(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		પાછા (-1);
	}
	s += કદ(HASH_MAGIC) - 1;
	l -= કદ(HASH_MAGIC) - 1;
	જો ((p = memchr(s, HASH_DELIM, l)) == ખાલી) {
		debug2("extract_salt: missing salt termination character");
		પાછા (-1);
	}

	b64len = p - s;
	/* Sanity check */
	જો (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		પાછા (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	મુક્ત(b64salt);
	જો (ret == -1) {
		debug2("extract_salt: salt decode error");
		પાછા (-1);
	}
	જો (ret != (પૂર્ણાંક)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		પાછા (-1);
	}

	પાછા (0);
}

અક્ષર *
host_hash(અચલ અક્ષર *host, અચલ અક્ષર *name_from_hostfile, u_int src_len)
{
	સંરચના ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	અક્ષર uu_salt[512], uu_result[512];
	અક્ષર *encoded = ખાલી;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	જો (name_from_hostfile == ખાલી) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} નહીંતર {
		/* Extract salt from known host entry */
		જો (extract_salt(name_from_hostfile, src_len, salt,
		    કદ(salt)) == -1)
			પાછા (ખાલી);
	}

	જો ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == ખાલી ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, કદ(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	જો (__b64_ntop(salt, len, uu_salt, કદ(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, કદ(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	પાછા (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

પૂર્ણાંક
hostfile_read_ચાવી(અક્ષર **cpp, u_int *bitsp, સંરચના sshkey *ret)
{
	અક્ષર *cp;

	/* Skip leading whitespace. */
	માટે (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	જો (sshkey_read(ret, &cp) != 0)
		પાછા 0;

	/* Skip trailing whitespace. */
	માટે (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	જો (bitsp != ખાલી)
		*bitsp = sshkey_size(ret);
	પાછા 1;
}

સ્થિર HostkeyMarker
check_markers(અક્ષર **cpp)
{
	અક્ષર marker[32], *sp, *cp = *cpp;
	પૂર્ણાંક ret = MRK_NONE;

	જ્યારે (*cp == '@') {
		/* Only one marker is allowed */
		જો (ret != MRK_NONE)
			પાછા MRK_ERROR;
		/* Markers are terminated by whitespace */
		જો ((sp = strchr(cp, ' ')) == ખાલી &&
		    (sp = strchr(cp, '\t')) == ખાલી)
			પાછા MRK_ERROR;
		/* Extract marker for comparison */
		જો (sp <= cp + 1 || sp >= cp + કદ(marker))
			પાછા MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		જો (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		નહીંતર જો (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		નહીંતર
			પાછા MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		માટે (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	પાછા ret;
}

સંરચના hostkeys *
init_hostkeys(શૂન્ય)
{
	સંરચના hostkeys *ret = xcalloc(1, કદ(*ret));

	ret->entries = ખાલી;
	પાછા ret;
}

સંરચના load_callback_ctx {
	અચલ અક્ષર *host;
	u_long અંક_loaded;
	સંરચના hostkeys *hostkeys;
};

સ્થિર પૂર્ણાંક
record_hostkey(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *_ctx)
{
	સંરચના load_callback_ctx *ctx = (સંરચના load_callback_ctx *)_ctx;
	સંરચના hostkeys *hostkeys = ctx->hostkeys;
	સંરચના hostkey_entry *tmp;

	જો (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		પાછા 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->ચાવી), l->path, l->linenum);
	જો ((tmp = recallocarray(hostkeys->entries, hostkeys->અંક_entries,
	    hostkeys->અંક_entries + 1, કદ(*hostkeys->entries))) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->અંક_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->અંક_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->અંક_entries].લીટી = l->linenum;
	hostkeys->entries[hostkeys->અંક_entries].ચાવી = l->ચાવી;
	l->ચાવી = ખાલી; /* steal it */
	hostkeys->entries[hostkeys->અંક_entries].marker = l->marker;
	hostkeys->entries[hostkeys->અંક_entries].note = l->note;
	hostkeys->અંક_entries++;
	ctx->અંક_loaded++;

	પાછા 0;
}

શૂન્ય
load_hostkeys_file(સંરચના hostkeys *hostkeys, અચલ અક્ષર *host,
    અચલ અક્ષર *path, FILE *f, u_int note)
{
	પૂર્ણાંક r;
	સંરચના load_callback_ctx ctx;

	ctx.host = host;
	ctx.અંક_loaded = 0;
	ctx.hostkeys = hostkeys;

	જો ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    ખાલી, HKF_WANT_MATCH|HKF_WANT_PARSE_ચાવી, note)) != 0) {
		જો (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	જો (ctx.અંક_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.અંક_loaded, host);
}

શૂન્ય
load_hostkeys(સંરચના hostkeys *hostkeys, અચલ અક્ષર *host, અચલ અક્ષર *path,
    u_int note)
{
	FILE *f;

	જો ((f = fopen(path, "r")) == ખાલી) {
		debug_f("fopen %s: %s", path, strerror(errno));
		પાછા;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

શૂન્ય
free_hostkeys(સંરચના hostkeys *hostkeys)
{
	u_int i;

	માટે (i = 0; i < hostkeys->અંક_entries; i++) {
		મુક્ત(hostkeys->entries[i].host);
		મુક્ત(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].ચાવી);
		explicit_bzero(hostkeys->entries + i, કદ(*hostkeys->entries));
	}
	મુક્ત(hostkeys->entries);
	freezero(hostkeys, કદ(*hostkeys));
}

સ્થિર પૂર્ણાંક
check_ચાવી_not_revoked(સંરચના hostkeys *hostkeys, સંરચના sshkey *k)
{
	પૂર્ણાંક is_cert = sshkey_is_cert(k);
	u_int i;

	માટે (i = 0; i < hostkeys->અંક_entries; i++) {
		જો (hostkeys->entries[i].marker != MRK_REVOKE)
			ચાલુ;
		જો (sshkey_equal_public(k, hostkeys->entries[i].ચાવી))
			પાછા -1;
		જો (is_cert && k != ખાલી &&
		    sshkey_equal_public(k->cert->signature_ચાવી,
		    hostkeys->entries[i].ચાવી))
			પાછા -1;
	}
	પાછા 0;
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
સ્થિર HostStatus
check_hostkeys_by_ચાવી_or_type(સંરચના hostkeys *hostkeys,
    સંરચના sshkey *k, પૂર્ણાંક keytype, પૂર્ણાંક nid, અચલ સંરચના hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	પૂર્ણાંક want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	જો (found != ખાલી)
		*found = ખાલી;

	માટે (i = 0; i < hostkeys->અંક_entries; i++) {
		જો (hostkeys->entries[i].marker != want_marker)
			ચાલુ;
		જો (k == ખાલી) {
			જો (hostkeys->entries[i].ચાવી->type != keytype)
				ચાલુ;
			જો (nid != -1 &&
			    sshkey_type_plain(keytype) == ચાવી_ECDSA &&
			    hostkeys->entries[i].ચાવી->ecdsa_nid != nid)
				ચાલુ;
			end_return = HOST_FOUND;
			જો (found != ખાલી)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].ચાવી;
			તોડો;
		}
		જો (want_cert) {
			જો (sshkey_equal_public(k->cert->signature_ચાવી,
			    hostkeys->entries[i].ચાવી)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				જો (found != ખાલી)
					*found = hostkeys->entries + i;
				તોડો;
			}
		} નહીંતર {
			જો (sshkey_equal(k, hostkeys->entries[i].ચાવી)) {
				end_return = HOST_OK;
				જો (found != ખાલી)
					*found = hostkeys->entries + i;
				તોડો;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			જો (found != ખાલી)
				*found = hostkeys->entries + i;
		}
	}
	જો (check_ચાવી_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		જો (found != ખાલી)
			*found = ખાલી;
	}
	પાછા end_return;
}

HostStatus
check_ચાવી_in_hostkeys(સંરચના hostkeys *hostkeys, સંરચના sshkey *ચાવી,
    અચલ સંરચના hostkey_entry **found)
{
	જો (ચાવી == ખાલી)
		fatal("no key to look up");
	પાછા check_hostkeys_by_ચાવી_or_type(hostkeys, ચાવી, 0, -1, found);
}

પૂર્ણાંક
lookup_ચાવી_in_hostkeys_by_type(સંરચના hostkeys *hostkeys, પૂર્ણાંક keytype, પૂર્ણાંક nid,
    અચલ સંરચના hostkey_entry **found)
{
	પાછા (check_hostkeys_by_ચાવી_or_type(hostkeys, ખાલી, keytype, nid,
	    found) == HOST_FOUND);
}

પૂર્ણાંક
lookup_marker_in_hostkeys(સંરચના hostkeys *hostkeys, પૂર્ણાંક want_marker)
{
	u_int i;

	માટે (i = 0; i < hostkeys->અંક_entries; i++) {
		જો (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			પાછા 1;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
format_host_entry(સંરચના sshbuf *entry, અચલ અક્ષર *host, અચલ અક્ષર *ip,
    અચલ સંરચના sshkey *ચાવી, પૂર્ણાંક store_hash)
{
	પૂર્ણાંક r, success = 0;
	અક્ષર *hashed_host = ખાલી, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	જો (store_hash) {
		જો ((hashed_host = host_hash(lhost, ખાલી, 0)) == ખાલી) {
			error_f("host_hash failed");
			મુક્ત(lhost);
			પાછા 0;
		}
		જો ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} નહીંતર જો (ip != ખાલી) {
		જો ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} નહીંતર {
		જો ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	મુક્ત(hashed_host);
	મુક્ત(lhost);
	જો ((r = sshkey_format_text(ચાવી, entry)) == 0)
		success = 1;
	નહીંતર
		error_fr(r, "sshkey_write");
	જો ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	જો (success && store_hash && ip != ખાલી)
		success = format_host_entry(entry, ip, ખાલી, ચાવી, 1);
	પાછા success;
}

સ્થિર પૂર્ણાંક
write_host_entry(FILE *f, અચલ અક્ષર *host, અચલ અક્ષર *ip,
    અચલ સંરચના sshkey *ચાવી, પૂર્ણાંક store_hash)
{
	પૂર્ણાંક r, success = 0;
	સંરચના sshbuf *entry = ખાલી;

	જો ((entry = sshbuf_new()) == ખાલી)
		fatal_f("allocation failed");
	જો ((r = format_host_entry(entry, host, ip, ચાવી, store_hash)) != 1) {
		debug_f("failed to format host entry");
		જાઓ out;
	}
	જો ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		જાઓ out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	પાછા success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
શૂન્ય
hostfile_create_user_ssh_dir(અચલ અક્ષર *filename, પૂર્ણાંક notify)
{
	અક્ષર *dotsshdir = ખાલી, *p;
	size_t len;
	સંરચના stat st;

	જો ((p = strrchr(filename, '/')) == ખાલી)
		પાછા;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	જો (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		જાઓ out; /* not ~/.ssh prefixed */
	જો (stat(dotsshdir, &st) == 0)
		જાઓ out; /* dir already exists */
	નહીંતર જો (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	નહીંતર {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		જો (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		નહીંતર જો (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(ખાલી);
#endif
	}
 out:
	મુક્ત(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
પૂર્ણાંક
add_host_to_hostfile(અચલ અક્ષર *filename, અચલ અક્ષર *host,
    અચલ સંરચના sshkey *ચાવી, પૂર્ણાંક store_hash)
{
	FILE *f;
	પૂર્ણાંક success, addnl = 0;

	જો (ચાવી == ખાલી)
		પાછા 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	જો ((f = fopen(filename, "a+")) == ખાલી)
		પાછા 0;
	setvbuf(f, ખાલી, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	જો (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	જો (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		પાછા 0;
	}
	success = write_host_entry(f, host, ખાલી, ચાવી, store_hash);
	fclose(f);
	પાછા success;
}

સંરચના host_delete_ctx {
	FILE *out;
	પૂર્ણાંક quiet;
	અચલ અક્ષર *host, *ip;
	u_int *match_ચાવીઓ;	/* mask of HKF_MATCH_* for this key */
	સંરચના sshkey * અચલ *ચાવીઓ;
	size_t nkeys;
	પૂર્ણાંક modified;
};

સ્થિર પૂર્ણાંક
host_delete(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *_ctx)
{
	સંરચના host_delete_ctx *ctx = (સંરચના host_delete_ctx *)_ctx;
	પૂર્ણાંક loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	જો (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		માટે (i = 0; i < ctx->nkeys; i++) {
			જો (!sshkey_equal(ctx->ચાવીઓ[i], l->ચાવી))
				ચાલુ;
			ctx->match_ચાવીઓ[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->લીટી);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->ચાવી), l->path, l->linenum);
			પાછા 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->ચાવી), ctx->host);
		ctx->modified = 1;
		પાછા 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	જો (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->લીટી);
	પાછા 0;
}

પૂર્ણાંક
hostfile_replace_entries(અચલ અક્ષર *filename, અચલ અક્ષર *host, અચલ અક્ષર *ip,
    સંરચના sshkey **ચાવીઓ, size_t nkeys, પૂર્ણાંક store_hash, પૂર્ણાંક quiet, પૂર્ણાંક hash_alg)
{
	પૂર્ણાંક r, fd, oerrno = 0;
	પૂર્ણાંક loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	સંરચના host_delete_ctx ctx;
	અક્ષર *fp = ખાલી, *temp = ખાલી, *back = ખાલી;
	અચલ અક્ષર *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, કદ(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	જો ((ctx.match_ચાવીઓ = calloc(nkeys, કદ(*ctx.match_ચાવીઓ))) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	ctx.ચાવીઓ = ચાવીઓ;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	જો ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ fail;
	}

	જો ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		જાઓ fail;
	}
	જો ((ctx.out = fdopen(fd, "w")) == ખાલી) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		જાઓ fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	જો ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_ચાવી, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		જાઓ fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == ખાલી ? 0 : HKF_MATCH_IP);
	માટે (i = 0; i < nkeys; i++) {
		જો (ચાવીઓ[i] == ખાલી || (want & ctx.match_ચાવીઓ[i]) == want)
			ચાલુ;
		જો ((fp = sshkey_fingerprint(ચાવીઓ[i], hash_alg,
		    SSH_FP_DEFAULT)) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ fail;
		}
		/* write host/ip */
		what = "";
		જો (ctx.match_ચાવીઓ[i] == 0) {
			what = "Adding new key";
			જો (!write_host_entry(ctx.out, host, ip,
			    ચાવીઓ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				જાઓ fail;
			}
		} નહીંતર જો ((want & ~ctx.match_ચાવીઓ[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			જો (!write_host_entry(ctx.out, host, ખાલી,
			    ચાવીઓ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				જાઓ fail;
			}
		} નહીંતર જો ((want & ~ctx.match_ચાવીઓ[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			જો (!write_host_entry(ctx.out, ip, ખાલી,
			    ચાવીઓ[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				જાઓ fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == ખાલી ? "" : ",", ip == ખાલી ? "" : ip, filename,
		    sshkey_ssh_name(ચાવીઓ[i]), fp);
		મુક્ત(fp);
		fp = ખાલી;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = ખાલી;

	જો (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		જો (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			જાઓ fail;
		}
		જો (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			જાઓ fail;
		}
		જો (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			જાઓ fail;
		}
	} નહીંતર {
		/* No changes made; just delete the temporary file */
		જો (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	જો (temp != ખાલી && r != 0)
		unlink(temp);
	મુક્ત(temp);
	મુક્ત(back);
	મુક્ત(fp);
	જો (ctx.out != ખાલી)
		fclose(ctx.out);
	મુક્ત(ctx.match_ચાવીઓ);
	umask(omask);
	જો (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	પાછા r;
}

સ્થિર પૂર્ણાંક
match_maybe_hashed(અચલ અક્ષર *host, અચલ અક્ષર *names, પૂર્ણાંક *was_hashed)
{
	પૂર્ણાંક hashed = *names == HASH_DELIM, ret;
	અક્ષર *hashed_host = ખાલી;
	size_t nlen = strlen(names);

	જો (was_hashed != ખાલી)
		*was_hashed = hashed;
	જો (hashed) {
		જો ((hashed_host = host_hash(host, names, nlen)) == ખાલી)
			પાછા -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		મુક્ત(hashed_host);
		પાછા ret;
	}
	પાછા match_hostname(host, names) == 1;
}

પૂર્ણાંક
hostkeys_foreach_file(અચલ અક્ષર *path, FILE *f, hostkeys_foreach_fn *callback,
    શૂન્ય *ctx, અચલ અક્ષર *host, અચલ અક્ષર *ip, u_int options, u_int note)
{
	અક્ષર *લીટી = ખાલી, ktype[128];
	u_long linenum = 0;
	અક્ષર *cp, *cp2;
	u_int kbits;
	પૂર્ણાંક hashed;
	પૂર્ણાંક s, r = 0;
	સંરચના hostkey_foreach_લીટી lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, કદ(lineinfo));
	જો (host == ખાલી && (options & HKF_WANT_MATCH) != 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		linenum++;
		લીટી[strcspn(લીટી, "\n")] = '\0';

		મુક્ત(lineinfo.લીટી);
		sshkey_free(lineinfo.ચાવી);
		memset(&lineinfo, 0, કદ(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.લીટી = xstrdup(લીટી);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = ચાવી_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		માટે (cp = લીટી; *cp == ' ' || *cp == '\t'; cp++)
			;
		જો (!*cp || *cp == '#' || *cp == '\n') {
			જો ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				જો ((r = callback(&lineinfo, ctx)) != 0)
					તોડો;
			}
			ચાલુ;
		}

		જો ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			જો ((options & HKF_WANT_MATCH) == 0)
				જાઓ bad;
			ચાલુ;
		}

		/* Find the end of the host name portion. */
		માટે (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		જો (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			જો ((options & HKF_WANT_MATCH) == 0)
				જાઓ bad;
			ચાલુ;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		જો (host != ખાલી) {
			જો ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				જાઓ bad;
			}
			જો (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			જો (ip != ખાલી) {
				જો ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					જાઓ bad;
				}
				જો (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			જો ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				ચાલુ;
		}

		/* Got a match.  Skip host name and any following whitespace */
		માટે (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		જો (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			જાઓ bad;
		}
		lineinfo.rawkey = cp = cp2;

		જો ((options & HKF_WANT_PARSE_ચાવી) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			જો ((lineinfo.ચાવી = sshkey_new(ચાવી_UNSPEC)) == ખાલી) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				તોડો;
			}
			જો (!hostfile_read_ચાવી(&cp, &kbits, lineinfo.ચાવી)) {
				જાઓ bad;
			}
			lineinfo.keytype = lineinfo.ચાવી->type;
			lineinfo.comment = cp;
		} નહીંતર {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			જો (l <= 1 || l >= કદ(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				જાઓ bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			જો (lineinfo.keytype == ચાવી_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				જાઓ bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			માટે (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			જો (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = ચાવી_UNSPEC;
			}
			જો (lineinfo.keytype == ચાવી_UNSPEC) {
 bad:
				sshkey_free(lineinfo.ચાવી);
				lineinfo.ચાવી = ખાલી;
				lineinfo.status = HKF_STATUS_INVALID;
				જો ((r = callback(&lineinfo, ctx)) != 0)
					તોડો;
				ચાલુ;
			}
		}
		જો ((r = callback(&lineinfo, ctx)) != 0)
			તોડો;
	}
	sshkey_free(lineinfo.ચાવી);
	મુક્ત(lineinfo.લીટી);
	મુક્ત(લીટી);
	પાછા r;
}

પૂર્ણાંક
hostkeys_foreach(અચલ અક્ષર *path, hostkeys_foreach_fn *callback, શૂન્ય *ctx,
    અચલ અક્ષર *host, અચલ અક્ષર *ip, u_int options, u_int note)
{
	FILE *f;
	પૂર્ણાંક r, oerrno;

	જો ((f = fopen(path, "r")) == ખાલી)
		પાછા SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	પાછા r;
}
