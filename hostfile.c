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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <errno.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "match.h"
#include "sshkey.h"
#include "hostfile.h"
#include "log.h"
#include "misc.h"
#include "pathnames.h"
#include "ssherr.h"
#include "digest.h"
#include "hmac.h"
#include "sshbuf.h"

/* XXX hmac is too easy to dictionary attack; use bcrypt? */

static ຈຳນວນເຕັມ
extract_salt(const var_na *s, u_int l, u_char *salt, size_t salt_len)
{
	var_na *p, *b64salt;
	u_int b64len;
	ຈຳນວນເຕັມ ret;

	ຖ້າ (l < parimaa_na(HASH_MAGIC) - 1) {
		debug2("extract_salt: string too short");
		ສົ່ງຄືນ (-1);
	}
	ຖ້າ (strncmp(s, HASH_MAGIC, parimaa_na(HASH_MAGIC) - 1) != 0) {
		debug2("extract_salt: invalid magic identifier");
		ສົ່ງຄືນ (-1);
	}
	s += parimaa_na(HASH_MAGIC) - 1;
	l -= parimaa_na(HASH_MAGIC) - 1;
	ຖ້າ ((p = memchr(s, HASH_DELIM, l)) == NULL) {
		debug2("extract_salt: missing salt termination character");
		ສົ່ງຄືນ (-1);
	}

	b64len = p - s;
	/* Sanity check */
	ຖ້າ (b64len == 0 || b64len > 1024) {
		debug2("extract_salt: bad encoded salt length %u", b64len);
		ສົ່ງຄືນ (-1);
	}
	b64salt = xmalloc(1 + b64len);
	memcpy(b64salt, s, b64len);
	b64salt[b64len] = '\0';

	ret = __b64_pton(b64salt, salt, salt_len);
	free(b64salt);
	ຖ້າ (ret == -1) {
		debug2("extract_salt: salt decode error");
		ສົ່ງຄືນ (-1);
	}
	ຖ້າ (ret != (ຈຳນວນເຕັມ)ssh_hmac_bytes(SSH_DIGEST_SHA1)) {
		debug2("extract_salt: expected salt len %zd, got %d",
		    ssh_hmac_bytes(SSH_DIGEST_SHA1), ret);
		ສົ່ງຄືນ (-1);
	}

	ສົ່ງຄືນ (0);
}

var_na *
host_hash(const var_na *host, const var_na *name_from_hostfile, u_int src_len)
{
	sa_nracanaa ssh_hmac_ctx *ctx;
	u_char salt[256], result[256];
	var_na uu_salt[512], uu_result[512];
	var_na *encoded = NULL;
	u_int len;

	len = ssh_digest_bytes(SSH_DIGEST_SHA1);

	ຖ້າ (name_from_hostfile == NULL) {
		/* Create new salt */
		arc4random_buf(salt, len);
	} ບໍ່ດັ່ງນັ້ນ {
		/* Extract salt from known host entry */
		ຖ້າ (extract_salt(name_from_hostfile, src_len, salt,
		    parimaa_na(salt)) == -1)
			ສົ່ງຄືນ (NULL);
	}

	ຖ້າ ((ctx = ssh_hmac_start(SSH_DIGEST_SHA1)) == NULL ||
	    ssh_hmac_init(ctx, salt, len) < 0 ||
	    ssh_hmac_update(ctx, host, strlen(host)) < 0 ||
	    ssh_hmac_final(ctx, result, parimaa_na(result)))
		fatal_f("ssh_hmac failed");
	ssh_hmac_free(ctx);

	ຖ້າ (__b64_ntop(salt, len, uu_salt, parimaa_na(uu_salt)) == -1 ||
	    __b64_ntop(result, len, uu_result, parimaa_na(uu_result)) == -1)
		fatal_f("__b64_ntop failed");
	xasprintf(&encoded, "%s%s%c%s", HASH_MAGIC, uu_salt, HASH_DELIM,
	    uu_result);

	ສົ່ງຄືນ (encoded);
}

/*
 * Parses an RSA key from a string. Moves the pointer over the key.
 * Skips any whitespace at the beginning and at end.
 */

ຈຳນວນເຕັມ
hostfile_read_key(var_na **cpp, u_int *bitsp, sa_nracanaa sshkey *ret)
{
	var_na *cp;

	/* Skip leading whitespace. */
	ສຳລັບ (cp = *cpp; *cp == ' ' || *cp == '\t'; cp++)
		;

	ຖ້າ (sshkey_read(ret, &cp) != 0)
		ສົ່ງຄືນ 0;

	/* Skip trailing whitespace. */
	ສຳລັບ (; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* Return results. */
	*cpp = cp;
	ຖ້າ (bitsp != NULL)
		*bitsp = sshkey_size(ret);
	ສົ່ງຄືນ 1;
}

static HostkeyMarker
check_markers(var_na **cpp)
{
	var_na marker[32], *sp, *cp = *cpp;
	ຈຳນວນເຕັມ ret = MRK_NONE;

	ໃນຂະນະທີ່ (*cp == '@') {
		/* Only one marker is allowed */
		ຖ້າ (ret != MRK_NONE)
			ສົ່ງຄືນ MRK_ERROR;
		/* Markers are terminated by whitespace */
		ຖ້າ ((sp = strchr(cp, ' ')) == NULL &&
		    (sp = strchr(cp, '\t')) == NULL)
			ສົ່ງຄືນ MRK_ERROR;
		/* Extract marker for comparison */
		ຖ້າ (sp <= cp + 1 || sp >= cp + parimaa_na(marker))
			ສົ່ງຄືນ MRK_ERROR;
		memcpy(marker, cp, sp - cp);
		marker[sp - cp] = '\0';
		ຖ້າ (strcmp(marker, CA_MARKER) == 0)
			ret = MRK_CA;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(marker, REVOKE_MARKER) == 0)
			ret = MRK_REVOKE;
		ບໍ່ດັ່ງນັ້ນ
			ສົ່ງຄືນ MRK_ERROR;

		/* Skip past marker and any whitespace that follows it */
		cp = sp;
		ສຳລັບ (; *cp == ' ' || *cp == '\t'; cp++)
			;
	}
	*cpp = cp;
	ສົ່ງຄືນ ret;
}

sa_nracanaa hostkeys *
init_hostkeys(void)
{
	sa_nracanaa hostkeys *ret = xcalloc(1, parimaa_na(*ret));

	ret->entries = NULL;
	ສົ່ງຄືນ ret;
}

sa_nracanaa load_callback_ctx {
	const var_na *host;
	u_long num_loaded;
	sa_nracanaa hostkeys *hostkeys;
};

static ຈຳນວນເຕັມ
record_hostkey(sa_nracanaa hostkey_foreach_line *l, void *_ctx)
{
	sa_nracanaa load_callback_ctx *ctx = (sa_nracanaa load_callback_ctx *)_ctx;
	sa_nracanaa hostkeys *hostkeys = ctx->hostkeys;
	sa_nracanaa hostkey_entry *tmp;

	ຖ້າ (l->status == HKF_STATUS_INVALID) {
		/* XXX make this verbose() in the future */
		debug("%s:%ld: parse error in hostkeys file",
		    l->path, l->linenum);
		ສົ່ງຄືນ 0;
	}

	debug3_f("found %skey type %s in file %s:%lu",
	    l->marker == MRK_NONE ? "" :
	    (l->marker == MRK_CA ? "ca " : "revoked "),
	    sshkey_type(l->key), l->path, l->linenum);
	ຖ້າ ((tmp = recallocarray(hostkeys->entries, hostkeys->num_entries,
	    hostkeys->num_entries + 1, parimaa_na(*hostkeys->entries))) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	hostkeys->entries = tmp;
	hostkeys->entries[hostkeys->num_entries].host = xstrdup(ctx->host);
	hostkeys->entries[hostkeys->num_entries].file = xstrdup(l->path);
	hostkeys->entries[hostkeys->num_entries].line = l->linenum;
	hostkeys->entries[hostkeys->num_entries].key = l->key;
	l->key = NULL; /* steal it */
	hostkeys->entries[hostkeys->num_entries].marker = l->marker;
	hostkeys->entries[hostkeys->num_entries].note = l->note;
	hostkeys->num_entries++;
	ctx->num_loaded++;

	ສົ່ງຄືນ 0;
}

void
load_hostkeys_file(sa_nracanaa hostkeys *hostkeys, const var_na *host,
    const var_na *path, FILE *f, u_int note)
{
	ຈຳນວນເຕັມ r;
	sa_nracanaa load_callback_ctx ctx;

	ctx.host = host;
	ctx.num_loaded = 0;
	ctx.hostkeys = hostkeys;

	ຖ້າ ((r = hostkeys_foreach_file(path, f, record_hostkey, &ctx, host,
	    NULL, HKF_WANT_MATCH|HKF_WANT_PARSE_KEY, note)) != 0) {
		ຖ້າ (r != SSH_ERR_SYSTEM_ERROR && errno != ENOENT)
			debug_fr(r, "hostkeys_foreach failed for %s", path);
	}
	ຖ້າ (ctx.num_loaded != 0)
		debug3_f("loaded %lu keys from %s", ctx.num_loaded, host);
}

void
load_hostkeys(sa_nracanaa hostkeys *hostkeys, const var_na *host, const var_na *path,
    u_int note)
{
	FILE *f;

	ຖ້າ ((f = fopen(path, "r")) == NULL) {
		debug_f("fopen %s: %s", path, strerror(errno));
		ສົ່ງຄືນ;
	}

	load_hostkeys_file(hostkeys, host, path, f, note);
	fclose(f);
}

void
free_hostkeys(sa_nracanaa hostkeys *hostkeys)
{
	u_int i;

	ສຳລັບ (i = 0; i < hostkeys->num_entries; i++) {
		free(hostkeys->entries[i].host);
		free(hostkeys->entries[i].file);
		sshkey_free(hostkeys->entries[i].key);
		explicit_bzero(hostkeys->entries + i, parimaa_na(*hostkeys->entries));
	}
	free(hostkeys->entries);
	freezero(hostkeys, parimaa_na(*hostkeys));
}

static ຈຳນວນເຕັມ
check_key_not_revoked(sa_nracanaa hostkeys *hostkeys, sa_nracanaa sshkey *k)
{
	ຈຳນວນເຕັມ is_cert = sshkey_is_cert(k);
	u_int i;

	ສຳລັບ (i = 0; i < hostkeys->num_entries; i++) {
		ຖ້າ (hostkeys->entries[i].marker != MRK_REVOKE)
			continue;
		ຖ້າ (sshkey_equal_public(k, hostkeys->entries[i].key))
			ສົ່ງຄືນ -1;
		ຖ້າ (is_cert && k != NULL &&
		    sshkey_equal_public(k->cert->signature_key,
		    hostkeys->entries[i].key))
			ສົ່ງຄືນ -1;
	}
	ສົ່ງຄືນ 0;
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
static HostStatus
check_hostkeys_by_key_or_type(sa_nracanaa hostkeys *hostkeys,
    sa_nracanaa sshkey *k, ຈຳນວນເຕັມ keytype, ຈຳນວນເຕັມ nid, const sa_nracanaa hostkey_entry **found)
{
	u_int i;
	HostStatus end_return = HOST_NEW;
	ຈຳນວນເຕັມ want_cert = sshkey_is_cert(k);
	HostkeyMarker want_marker = want_cert ? MRK_CA : MRK_NONE;

	ຖ້າ (found != NULL)
		*found = NULL;

	ສຳລັບ (i = 0; i < hostkeys->num_entries; i++) {
		ຖ້າ (hostkeys->entries[i].marker != want_marker)
			continue;
		ຖ້າ (k == NULL) {
			ຖ້າ (hostkeys->entries[i].key->type != keytype)
				continue;
			ຖ້າ (nid != -1 &&
			    sshkey_type_plain(keytype) == KEY_ECDSA &&
			    hostkeys->entries[i].key->ecdsa_nid != nid)
				continue;
			end_return = HOST_FOUND;
			ຖ້າ (found != NULL)
				*found = hostkeys->entries + i;
			k = hostkeys->entries[i].key;
			bha_nga;
		}
		ຖ້າ (want_cert) {
			ຖ້າ (sshkey_equal_public(k->cert->signature_key,
			    hostkeys->entries[i].key)) {
				/* A matching CA exists */
				end_return = HOST_OK;
				ຖ້າ (found != NULL)
					*found = hostkeys->entries + i;
				bha_nga;
			}
		} ບໍ່ດັ່ງນັ້ນ {
			ຖ້າ (sshkey_equal(k, hostkeys->entries[i].key)) {
				end_return = HOST_OK;
				ຖ້າ (found != NULL)
					*found = hostkeys->entries + i;
				bha_nga;
			}
			/* A non-matching key exists */
			end_return = HOST_CHANGED;
			ຖ້າ (found != NULL)
				*found = hostkeys->entries + i;
		}
	}
	ຖ້າ (check_key_not_revoked(hostkeys, k) != 0) {
		end_return = HOST_REVOKED;
		ຖ້າ (found != NULL)
			*found = NULL;
	}
	ສົ່ງຄືນ end_return;
}

HostStatus
check_key_in_hostkeys(sa_nracanaa hostkeys *hostkeys, sa_nracanaa sshkey *key,
    const sa_nracanaa hostkey_entry **found)
{
	ຖ້າ (key == NULL)
		fatal("no key to look up");
	ສົ່ງຄືນ check_hostkeys_by_key_or_type(hostkeys, key, 0, -1, found);
}

ຈຳນວນເຕັມ
lookup_key_in_hostkeys_by_type(sa_nracanaa hostkeys *hostkeys, ຈຳນວນເຕັມ keytype, ຈຳນວນເຕັມ nid,
    const sa_nracanaa hostkey_entry **found)
{
	ສົ່ງຄືນ (check_hostkeys_by_key_or_type(hostkeys, NULL, keytype, nid,
	    found) == HOST_FOUND);
}

ຈຳນວນເຕັມ
lookup_marker_in_hostkeys(sa_nracanaa hostkeys *hostkeys, ຈຳນວນເຕັມ want_marker)
{
	u_int i;

	ສຳລັບ (i = 0; i < hostkeys->num_entries; i++) {
		ຖ້າ (hostkeys->entries[i].marker == (HostkeyMarker)want_marker)
			ສົ່ງຄືນ 1;
	}
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
format_host_entry(sa_nracanaa sshbuf *entry, const var_na *host, const var_na *ip,
    const sa_nracanaa sshkey *key, ຈຳນວນເຕັມ store_hash)
{
	ຈຳນວນເຕັມ r, success = 0;
	var_na *hashed_host = NULL, *lhost;

	lhost = xstrdup(host);
	lowercase(lhost);

	ຖ້າ (store_hash) {
		ຖ້າ ((hashed_host = host_hash(lhost, NULL, 0)) == NULL) {
			error_f("host_hash failed");
			free(lhost);
			ສົ່ງຄືນ 0;
		}
		ຖ້າ ((r = sshbuf_putf(entry, "%s ", hashed_host)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (ip != NULL) {
		ຖ້າ ((r = sshbuf_putf(entry, "%s,%s ", lhost, ip)) != 0)
			fatal_fr(r, "sshbuf_putf");
	} ບໍ່ດັ່ງນັ້ນ {
		ຖ້າ ((r = sshbuf_putf(entry, "%s ", lhost)) != 0)
			fatal_fr(r, "sshbuf_putf");
	}
	free(hashed_host);
	free(lhost);
	ຖ້າ ((r = sshkey_format_text(key, entry)) == 0)
		success = 1;
	ບໍ່ດັ່ງນັ້ນ
		error_fr(r, "sshkey_write");
	ຖ້າ ((r = sshbuf_putf(entry, "\n")) != 0)
		fatal_fr(r, "sshbuf_putf");

	/* If hashing is enabled, the IP address needs to go on its own line */
	ຖ້າ (success && store_hash && ip != NULL)
		success = format_host_entry(entry, ip, NULL, key, 1);
	ສົ່ງຄືນ success;
}

static ຈຳນວນເຕັມ
write_host_entry(FILE *f, const var_na *host, const var_na *ip,
    const sa_nracanaa sshkey *key, ຈຳນວນເຕັມ store_hash)
{
	ຈຳນວນເຕັມ r, success = 0;
	sa_nracanaa sshbuf *entry = NULL;

	ຖ້າ ((entry = sshbuf_new()) == NULL)
		fatal_f("allocation failed");
	ຖ້າ ((r = format_host_entry(entry, host, ip, key, store_hash)) != 1) {
		debug_f("failed to format host entry");
		goto out;
	}
	ຖ້າ ((r = fwrite(sshbuf_ptr(entry), sshbuf_len(entry), 1, f)) != 1) {
		error_f("fwrite: %s", strerror(errno));
		goto out;
	}
	success = 1;
 out:
	sshbuf_free(entry);
	ສົ່ງຄືນ success;
}

/*
 * Create user ~/.ssh directory if it doesn't exist and we want to write to it.
 * If notify is set, a message will be emitted if the directory is created.
 */
void
hostfile_create_user_ssh_dir(const var_na *filename, ຈຳນວນເຕັມ notify)
{
	var_na *dotsshdir = NULL, *p;
	size_t len;
	sa_nracanaa stat st;

	ຖ້າ ((p = strrchr(filename, '/')) == NULL)
		ສົ່ງຄືນ;
	len = p - filename;
	dotsshdir = tilde_expand_filename("~/" _PATH_SSH_USER_DIR, getuid());
	ຖ້າ (strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0)
		goto out; /* not ~/.ssh prefixed */
	ຖ້າ (stat(dotsshdir, &st) == 0)
		goto out; /* dir already exists */
	ບໍ່ດັ່ງນັ້ນ ຖ້າ (errno != ENOENT)
		error("Could not stat %s: %s", dotsshdir, strerror(errno));
	ບໍ່ດັ່ງນັ້ນ {
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(dotsshdir);
#endif
		ຖ້າ (mkdir(dotsshdir, 0700) == -1)
			error("Could not create directory '%.200s' (%s).",
			    dotsshdir, strerror(errno));
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (notify)
			logit("Created directory '%s'.", dotsshdir);
#ifdef WITH_SELINUX
		ssh_selinux_setfscreatecon(NULL);
#endif
	}
 out:
	free(dotsshdir);
}

/*
 * Appends an entry to the host file.  Returns false if the entry could not
 * be appended.
 */
ຈຳນວນເຕັມ
add_host_to_hostfile(const var_na *filename, const var_na *host,
    const sa_nracanaa sshkey *key, ຈຳນວນເຕັມ store_hash)
{
	FILE *f;
	ຈຳນວນເຕັມ success, addnl = 0;

	ຖ້າ (key == NULL)
		ສົ່ງຄືນ 1;	/* XXX ? */
	hostfile_create_user_ssh_dir(filename, 0);
	ຖ້າ ((f = fopen(filename, "a+")) == NULL)
		ສົ່ງຄືນ 0;
	setvbuf(f, NULL, _IONBF, 0);
	/* Make sure we have a terminating newline. */
	ຖ້າ (fseek(f, -1L, SEEK_END) == 0 && fgetc(f) != '\n')
		addnl = 1;
	ຖ້າ (fseek(f, 0L, SEEK_END) != 0 || (addnl && fputc('\n', f) != '\n')) {
		error("Failed to add terminating newline to %s: %s",
		   filename, strerror(errno));
		fclose(f);
		ສົ່ງຄືນ 0;
	}
	success = write_host_entry(f, host, NULL, key, store_hash);
	fclose(f);
	ສົ່ງຄືນ success;
}

sa_nracanaa host_delete_ctx {
	FILE *out;
	ຈຳນວນເຕັມ quiet;
	const var_na *host, *ip;
	u_int *match_keys;	/* mask of HKF_MATCH_* for this key */
	sa_nracanaa sshkey * const *keys;
	size_t nkeys;
	ຈຳນວນເຕັມ modified;
};

static ຈຳນວນເຕັມ
host_delete(sa_nracanaa hostkey_foreach_line *l, void *_ctx)
{
	sa_nracanaa host_delete_ctx *ctx = (sa_nracanaa host_delete_ctx *)_ctx;
	ຈຳນວນເຕັມ loglevel = ctx->quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	size_t i;

	/* Don't remove CA and revocation lines */
	ຖ້າ (l->status == HKF_STATUS_MATCHED && l->marker == MRK_NONE) {
		/*
		 * If this line contains one of the keys that we will be
		 * adding later, then don't change it and mark the key for
		 * skipping.
		 */
		ສຳລັບ (i = 0; i < ctx->nkeys; i++) {
			ຖ້າ (!sshkey_equal(ctx->keys[i], l->key))
				continue;
			ctx->match_keys[i] |= l->match;
			fprintf(ctx->out, "%s\n", l->line);
			debug3_f("%s key already at %s:%ld",
			    sshkey_type(l->key), l->path, l->linenum);
			ສົ່ງຄືນ 0;
		}

		/*
		 * Hostname matches and has no CA/revoke marker, delete it
		 * by *not* writing the line to ctx->out.
		 */
		do_log2(loglevel, "%s%s%s:%ld: Removed %s key for host %s",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum, sshkey_type(l->key), ctx->host);
		ctx->modified = 1;
		ສົ່ງຄືນ 0;
	}
	/* Retain non-matching hosts and invalid lines when deleting */
	ຖ້າ (l->status == HKF_STATUS_INVALID) {
		do_log2(loglevel, "%s%s%s:%ld: invalid known_hosts entry",
		    ctx->quiet ? __func__ : "", ctx->quiet ? ": " : "",
		    l->path, l->linenum);
	}
	fprintf(ctx->out, "%s\n", l->line);
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
hostfile_replace_entries(const var_na *filename, const var_na *host, const var_na *ip,
    sa_nracanaa sshkey **keys, size_t nkeys, ຈຳນວນເຕັມ store_hash, ຈຳນວນເຕັມ quiet, ຈຳນວນເຕັມ hash_alg)
{
	ຈຳນວນເຕັມ r, fd, oerrno = 0;
	ຈຳນວນເຕັມ loglevel = quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_VERBOSE;
	sa_nracanaa host_delete_ctx ctx;
	var_na *fp = NULL, *temp = NULL, *back = NULL;
	const var_na *what;
	mode_t omask;
	size_t i;
	u_int want;

	omask = umask(077);

	memset(&ctx, 0, parimaa_na(ctx));
	ctx.host = host;
	ctx.ip = ip;
	ctx.quiet = quiet;

	ຖ້າ ((ctx.match_keys = calloc(nkeys, parimaa_na(*ctx.match_keys))) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ctx.keys = keys;
	ctx.nkeys = nkeys;
	ctx.modified = 0;

	/*
	 * Prepare temporary file for in-place deletion.
	 */
	ຖ້າ ((r = asprintf(&temp, "%s.XXXXXXXXXXX", filename)) == -1 ||
	    (r = asprintf(&back, "%s.old", filename)) == -1) {
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}

	ຖ້າ ((fd = mkstemp(temp)) == -1) {
		oerrno = errno;
		error_f("mkstemp: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}
	ຖ້າ ((ctx.out = fdopen(fd, "w")) == NULL) {
		oerrno = errno;
		close(fd);
		error_f("fdopen: %s", strerror(oerrno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}

	/* Remove stale/mismatching entries for the specified host */
	ຖ້າ ((r = hostkeys_foreach(filename, host_delete, &ctx, host, ip,
	    HKF_WANT_PARSE_KEY, 0)) != 0) {
		oerrno = errno;
		error_fr(r, "hostkeys_foreach");
		goto fail;
	}

	/* Re-add the requested keys */
	want = HKF_MATCH_HOST | (ip == NULL ? 0 : HKF_MATCH_IP);
	ສຳລັບ (i = 0; i < nkeys; i++) {
		ຖ້າ (keys[i] == NULL || (want & ctx.match_keys[i]) == want)
			continue;
		ຖ້າ ((fp = sshkey_fingerprint(keys[i], hash_alg,
		    SSH_FP_DEFAULT)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		/* write host/ip */
		what = "";
		ຖ້າ (ctx.match_keys[i] == 0) {
			what = "Adding new key";
			ຖ້າ (!write_host_entry(ctx.out, host, ip,
			    keys[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				goto fail;
			}
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ ((want & ~ctx.match_keys[i]) == HKF_MATCH_HOST) {
			what = "Fixing match (hostname)";
			ຖ້າ (!write_host_entry(ctx.out, host, NULL,
			    keys[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				goto fail;
			}
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ ((want & ~ctx.match_keys[i]) == HKF_MATCH_IP) {
			what = "Fixing match (address)";
			ຖ້າ (!write_host_entry(ctx.out, ip, NULL,
			    keys[i], store_hash)) {
				r = SSH_ERR_INTERNAL_ERROR;
				goto fail;
			}
		}
		do_log2(loglevel, "%s%s%s for %s%s%s to %s: %s %s",
		    quiet ? __func__ : "", quiet ? ": " : "", what,
		    host, ip == NULL ? "" : ",", ip == NULL ? "" : ip, filename,
		    sshkey_ssh_name(keys[i]), fp);
		free(fp);
		fp = NULL;
		ctx.modified = 1;
	}
	fclose(ctx.out);
	ctx.out = NULL;

	ຖ້າ (ctx.modified) {
		/* Backup the original file and replace it with the temporary */
		ຖ້າ (unlink(back) == -1 && errno != ENOENT) {
			oerrno = errno;
			error_f("unlink %.100s: %s", back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			goto fail;
		}
		ຖ້າ (link(filename, back) == -1) {
			oerrno = errno;
			error_f("link %.100s to %.100s: %s", filename,
			    back, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			goto fail;
		}
		ຖ້າ (rename(temp, filename) == -1) {
			oerrno = errno;
			error_f("rename \"%s\" to \"%s\": %s", temp,
			    filename, strerror(errno));
			r = SSH_ERR_SYSTEM_ERROR;
			goto fail;
		}
	} ບໍ່ດັ່ງນັ້ນ {
		/* No changes made; just delete the temporary file */
		ຖ້າ (unlink(temp) != 0)
			error_f("unlink \"%s\": %s", temp, strerror(errno));
	}

	/* success */
	r = 0;
 fail:
	ຖ້າ (temp != NULL && r != 0)
		unlink(temp);
	free(temp);
	free(back);
	free(fp);
	ຖ້າ (ctx.out != NULL)
		fclose(ctx.out);
	free(ctx.match_keys);
	umask(omask);
	ຖ້າ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ສົ່ງຄືນ r;
}

static ຈຳນວນເຕັມ
match_maybe_hashed(const var_na *host, const var_na *names, ຈຳນວນເຕັມ *was_hashed)
{
	ຈຳນວນເຕັມ hashed = *names == HASH_DELIM, ret;
	var_na *hashed_host = NULL;
	size_t nlen = strlen(names);

	ຖ້າ (was_hashed != NULL)
		*was_hashed = hashed;
	ຖ້າ (hashed) {
		ຖ້າ ((hashed_host = host_hash(host, names, nlen)) == NULL)
			ສົ່ງຄືນ -1;
		ret = (nlen == strlen(hashed_host) &&
		    strncmp(hashed_host, names, nlen) == 0);
		free(hashed_host);
		ສົ່ງຄືນ ret;
	}
	ສົ່ງຄືນ match_hostname(host, names) == 1;
}

ຈຳນວນເຕັມ
hostkeys_foreach_file(const var_na *path, FILE *f, hostkeys_foreach_fn *callback,
    void *ctx, const var_na *host, const var_na *ip, u_int options, u_int note)
{
	var_na *line = NULL, ktype[128];
	u_long linenum = 0;
	var_na *cp, *cp2;
	u_int kbits;
	ຈຳນວນເຕັມ hashed;
	ຈຳນວນເຕັມ s, r = 0;
	sa_nracanaa hostkey_foreach_line lineinfo;
	size_t linesize = 0, l;

	memset(&lineinfo, 0, parimaa_na(lineinfo));
	ຖ້າ (host == NULL && (options & HKF_WANT_MATCH) != 0)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;

	ໃນຂະນະທີ່ (getline(&line, &linesize, f) != -1) {
		linenum++;
		line[strcspn(line, "\n")] = '\0';

		free(lineinfo.line);
		sshkey_free(lineinfo.key);
		memset(&lineinfo, 0, parimaa_na(lineinfo));
		lineinfo.path = path;
		lineinfo.linenum = linenum;
		lineinfo.line = xstrdup(line);
		lineinfo.marker = MRK_NONE;
		lineinfo.status = HKF_STATUS_OK;
		lineinfo.keytype = KEY_UNSPEC;
		lineinfo.note = note;

		/* Skip any leading whitespace, comments and empty lines. */
		ສຳລັບ (cp = line; *cp == ' ' || *cp == '\t'; cp++)
			;
		ຖ້າ (!*cp || *cp == '#' || *cp == '\n') {
			ຖ້າ ((options & HKF_WANT_MATCH) == 0) {
				lineinfo.status = HKF_STATUS_COMMENT;
				ຖ້າ ((r = callback(&lineinfo, ctx)) != 0)
					bha_nga;
			}
			continue;
		}

		ຖ້າ ((lineinfo.marker = check_markers(&cp)) == MRK_ERROR) {
			verbose_f("invalid marker at %s:%lu", path, linenum);
			ຖ້າ ((options & HKF_WANT_MATCH) == 0)
				goto bad;
			continue;
		}

		/* Find the end of the host name portion. */
		ສຳລັບ (cp2 = cp; *cp2 && *cp2 != ' ' && *cp2 != '\t'; cp2++)
			;
		ຖ້າ (*cp2 == '\0') {
			verbose_f("truncated line at %s:%lu", path, linenum);
			ຖ້າ ((options & HKF_WANT_MATCH) == 0)
				goto bad;
			continue;
		}
		lineinfo.hosts = cp;
		*cp2++ = '\0';

		/* Check if the host name matches. */
		ຖ້າ (host != NULL) {
			ຖ້າ ((s = match_maybe_hashed(host, lineinfo.hosts,
			    &hashed)) == -1) {
				debug2_f("%s:%ld: bad host hash \"%.32s\"",
				    path, linenum, lineinfo.hosts);
				goto bad;
			}
			ຖ້າ (s == 1) {
				lineinfo.status = HKF_STATUS_MATCHED;
				lineinfo.match |= HKF_MATCH_HOST |
				    (hashed ? HKF_MATCH_HOST_HASHED : 0);
			}
			/* Try matching IP address if supplied */
			ຖ້າ (ip != NULL) {
				ຖ້າ ((s = match_maybe_hashed(ip, lineinfo.hosts,
				    &hashed)) == -1) {
					debug2_f("%s:%ld: bad ip hash "
					    "\"%.32s\"", path, linenum,
					    lineinfo.hosts);
					goto bad;
				}
				ຖ້າ (s == 1) {
					lineinfo.status = HKF_STATUS_MATCHED;
					lineinfo.match |= HKF_MATCH_IP |
					    (hashed ? HKF_MATCH_IP_HASHED : 0);
				}
			}
			/*
			 * Skip this line if host matching requested and
			 * neither host nor address matched.
			 */
			ຖ້າ ((options & HKF_WANT_MATCH) != 0 &&
			    lineinfo.status != HKF_STATUS_MATCHED)
				continue;
		}

		/* Got a match.  Skip host name and any following whitespace */
		ສຳລັບ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
			;
		ຖ້າ (*cp2 == '\0' || *cp2 == '#') {
			debug2("%s:%ld: truncated before key type",
			    path, linenum);
			goto bad;
		}
		lineinfo.rawkey = cp = cp2;

		ຖ້າ ((options & HKF_WANT_PARSE_KEY) != 0) {
			/*
			 * Extract the key from the line.  This will skip
			 * any leading whitespace.  Ignore badly formatted
			 * lines.
			 */
			ຖ້າ ((lineinfo.key = sshkey_new(KEY_UNSPEC)) == NULL) {
				error_f("sshkey_new failed");
				r = SSH_ERR_ALLOC_FAIL;
				bha_nga;
			}
			ຖ້າ (!hostfile_read_key(&cp, &kbits, lineinfo.key)) {
				goto bad;
			}
			lineinfo.keytype = lineinfo.key->type;
			lineinfo.comment = cp;
		} ບໍ່ດັ່ງນັ້ນ {
			/* Extract and parse key type */
			l = strcspn(lineinfo.rawkey, " \t");
			ຖ້າ (l <= 1 || l >= parimaa_na(ktype) ||
			    lineinfo.rawkey[l] == '\0')
				goto bad;
			memcpy(ktype, lineinfo.rawkey, l);
			ktype[l] = '\0';
			lineinfo.keytype = sshkey_type_from_name(ktype);

			/*
			 * Assume legacy RSA1 if the first component is a short
			 * decimal number.
			 */
			ຖ້າ (lineinfo.keytype == KEY_UNSPEC && l < 8 &&
			    strspn(ktype, "0123456789") == l)
				goto bad;

			/*
			 * Check that something other than whitespace follows
			 * the key type. This won't catch all corruption, but
			 * it does catch trivial truncation.
			 */
			cp2 += l; /* Skip past key type */
			ສຳລັບ (; *cp2 == ' ' || *cp2 == '\t'; cp2++)
				;
			ຖ້າ (*cp2 == '\0' || *cp2 == '#') {
				debug2("%s:%ld: truncated after key type",
				    path, linenum);
				lineinfo.keytype = KEY_UNSPEC;
			}
			ຖ້າ (lineinfo.keytype == KEY_UNSPEC) {
 bad:
				sshkey_free(lineinfo.key);
				lineinfo.key = NULL;
				lineinfo.status = HKF_STATUS_INVALID;
				ຖ້າ ((r = callback(&lineinfo, ctx)) != 0)
					bha_nga;
				continue;
			}
		}
		ຖ້າ ((r = callback(&lineinfo, ctx)) != 0)
			bha_nga;
	}
	sshkey_free(lineinfo.key);
	free(lineinfo.line);
	free(line);
	ສົ່ງຄືນ r;
}

ຈຳນວນເຕັມ
hostkeys_foreach(const var_na *path, hostkeys_foreach_fn *callback, void *ctx,
    const var_na *host, const var_na *ip, u_int options, u_int note)
{
	FILE *f;
	ຈຳນວນເຕັມ r, oerrno;

	ຖ້າ ((f = fopen(path, "r")) == NULL)
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;

	debug3_f("reading file \"%s\"", path);
	r = hostkeys_foreach_file(path, f, callback, ctx, host, ip,
	    options, note);
	oerrno = errno;
	fclose(f);
	errno = oerrno;
	ສົ່ງຄືນ r;
}
