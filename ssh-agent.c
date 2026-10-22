/* $OpenBSD: ssh-agent.c,v 1.333 2026/09/22 22:30:27 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/resource.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#endif

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <util.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "version.h"

#ifndef DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#endif
#ifndef DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#endif

/* Maximum accepted message length */
#define AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#define AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#define AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#define AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#define AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#define AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#define AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

ಪ್ರಕಾರನಿರ್ದೇಶ ಗಣನಾ {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

ಸಂರಚನಾ hostkey_sid {
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	ಸಂರಚನಾ sshbuf *sid;
	ಪೂರ್ಣಾಙ್ಕ forwarded;
};

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ socket_entry {
	ಪೂರ್ಣಾಙ್ಕ fd;
	sock_type type;
	ಸಂರಚನಾ sshbuf *ಒಳಹರಿವು;
	ಸಂರಚನಾ sshbuf *output;
	ಸಂರಚನಾ sshbuf *request;
	size_t nsession_ids;
	ಸಂರಚನಾ hostkey_sid *session_ids;
	ಪೂರ್ಣಾಙ್ಕ session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = ರಿಕ್ತ;

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ identity {
	TAILQ_ENTRY(identity) next;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	ವರ್ಣ *comment;
	ವರ್ಣ *provider;
	time_t death;
	u_int confirm;
	ವರ್ಣ *sk_provider;
	ಸಂರಚನಾ dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

ಸಂರಚನಾ idtable {
	ಪೂರ್ಣಾಙ್ಕ nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
ಸಂರಚನಾ idtable *idtab;

ಪೂರ್ಣಾಙ್ಕ max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

ಸ್ಥಿರ sig_atomic_t signalled_exit;
ಸ್ಥಿರ sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
ಸ್ಥಿರ ವರ್ಣ *socket_name;
ಸ್ಥಿರ ವರ್ಣ *socket_dir;
ಸ್ಥಿರ ವರ್ಣ *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
ಸ್ಥಿರ ವರ್ಣ *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
ಪೂರ್ಣಾಙ್ಕ locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

ಬಾಹ್ಯ ವರ್ಣ *__progname;

/* Default lifetime in seconds (0 == forever) */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ lifetime = 0;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ restrict_websafe = 1;
ಸ್ಥಿರ ವರ್ಣ *websafe_allowlist;

ಸ್ಥಿರ ಶೂನ್ಯ
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->ಒಳಹರಿವು);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	ಪ್ರತಿ (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].ಕೀಲಿ);
		sshbuf_free(e->session_ids[i].sid);
	}
	ಮುಕ್ತ(e->session_ids);
	memset(e, '\0', ಪರಿಮಾಣ(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

ಸ್ಥಿರ ಶೂನ್ಯ
idtab_init(ಶೂನ್ಯ)
{
	idtab = xcalloc(1, ಪರಿಮಾಣ(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dest_constraint_hop(ಸಂರಚನಾ dest_constraint_hop *dch)
{
	u_int i;

	ಯದಿ (dch == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಮುಕ್ತ(dch->user);
	ಮುಕ್ತ(dch->hostname);
	ಪ್ರತಿ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ಕೀಲಿಗಳು[i]);
	ಮುಕ್ತ(dch->ಕೀಲಿಗಳು);
	ಮುಕ್ತ(dch->ಕೀಲಿ_is_ca);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dest_constraints(ಸಂರಚನಾ dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	ಪ್ರತಿ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	ಮುಕ್ತ(dcs);
}

#ifdef ENABLE_PKCS11
ಸ್ಥಿರ ಶೂನ್ಯ
dup_dest_constraint_hop(ಧ್ರುವ ಸಂರಚನಾ dest_constraint_hop *dch,
    ಸಂರಚನಾ dest_constraint_hop *out)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ r;

	out->user = dch->user == ರಿಕ್ತ ? ರಿಕ್ತ : xstrdup(dch->user);
	out->hostname = dch->hostname == ರಿಕ್ತ ? ರಿಕ್ತ : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->ಕೀಲಿಗಳು = out->nkeys == 0 ? ರಿಕ್ತ :
	    xcalloc(out->nkeys, ಪರಿಮಾಣ(*out->ಕೀಲಿಗಳು));
	out->ಕೀಲಿ_is_ca = out->nkeys == 0 ? ರಿಕ್ತ :
	    xcalloc(out->nkeys, ಪರಿಮಾಣ(*out->ಕೀಲಿ_is_ca));
	ಪ್ರತಿ (i = 0; i < dch->nkeys; i++) {
		ಯದಿ (dch->ಕೀಲಿಗಳು[i] != ರಿಕ್ತ &&
		    (r = sshkey_from_private(dch->ಕೀಲಿಗಳು[i],
		    &(out->ಕೀಲಿಗಳು[i]))) != 0)
			fatal_fr(r, "copy key");
		out->ಕೀಲಿ_is_ca[i] = dch->ಕೀಲಿ_is_ca[i];
	}
}

ಸ್ಥಿರ ಸಂರಚನಾ dest_constraint *
dup_dest_constraints(ಧ್ರುವ ಸಂರಚನಾ dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	ಸಂರಚನಾ dest_constraint *ret;

	ಯದಿ (ndcs == 0)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ret = xcalloc(ndcs, ಪರಿಮಾಣ(*ret));
	ಪ್ರತಿ (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
ಸ್ಥಿರ ಶೂನ್ಯ
dump_dest_constraint_hop(ಧ್ರುವ ಸಂರಚನಾ dest_constraint_hop *dch)
{
	u_int i;
	ವರ್ಣ *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == ರಿಕ್ತ ? "(null)" : dch->user,
	    dch->hostname == ರಿಕ್ತ ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	ಪ್ರತಿ (i = 0; i < dch->nkeys; i++) {
		fp = ರಿಕ್ತ;
		ಯದಿ (dch->ಕೀಲಿಗಳು[i] != ರಿಕ್ತ &&
		    (fp = sshkey_fingerprint(dch->ಕೀಲಿಗಳು[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->ಕೀಲಿಗಳು[i] == ರಿಕ್ತ ? "" : sshkey_ssh_name(dch->ಕೀಲಿಗಳು[i]),
		    dch->ಕೀಲಿಗಳು[i] == ರಿಕ್ತ ? "" : " ",
		    dch->ಕೀಲಿಗಳು[i] == ರಿಕ್ತ ? "none" : fp,
		    dch->ಕೀಲಿ_is_ca[i]);
		ಮುಕ್ತ(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

ಸ್ಥಿರ ಶೂನ್ಯ
dump_dest_constraints(ಧ್ರುವ ವರ್ಣ *context,
    ಧ್ರುವ ಸಂರಚನಾ dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	ಪ್ರತಿ (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_identity(Identity *id)
{
	sshkey_free(id->ಕೀಲಿ);
	ಮುಕ್ತ(id->provider);
	ಮುಕ್ತ(id->comment);
	ಮುಕ್ತ(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	ಮುಕ್ತ(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match_ಕೀಲಿ_hop(ಧ್ರುವ ವರ್ಣ *tag, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ಸಂರಚನಾ dest_constraint_hop *dch)
{
	ಧ್ರುವ ವರ್ಣ *reason = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	ವರ್ಣ *fp;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	/* XXX logspam */
	ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(ಕೀಲಿ), fp, dch->nkeys);
	ಮುಕ್ತ(fp);
	ಪ್ರತಿ (i = 0; i < dch->nkeys; i++) {
		ಯದಿ (dch->ಕೀಲಿಗಳು[i] == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ -1;
		/* XXX logspam */
		ಯದಿ ((fp = sshkey_fingerprint(dch->ಕೀಲಿಗಳು[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->ಕೀಲಿ_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->ಕೀಲಿಗಳು[i]), fp);
		ಮುಕ್ತ(fp);
		ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
			/* plain key */
			ಯದಿ (dch->ಕೀಲಿ_is_ca[i] ||
			    !sshkey_equal(ಕೀಲಿ, dch->ಕೀಲಿಗಳು[i]))
				ಅನುವರ್ತ;
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		/* certificate */
		ಯದಿ (!dch->ಕೀಲಿ_is_ca[i])
			ಅನುವರ್ತ;
		ಯದಿ (ಕೀಲಿ->cert == ರಿಕ್ತ || ಕೀಲಿ->cert->signature_ಕೀಲಿ == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ -1; /* shouldn't happen */
		ಯದಿ (!sshkey_equal(ಕೀಲಿ->cert->signature_ಕೀಲಿ, dch->ಕೀಲಿಗಳು[i]))
			ಅನುವರ್ತ;
		ಯದಿ (sshkey_cert_check_host(ಕೀಲಿ, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    ಕೀಲಿ->cert->ಕೀಲಿ_id, hostname, reason);
			ಅನುವರ್ತ;
		}
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

/* Check destination constraints on an identity against the hostkey/user */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
permitted_by_dest_constraints(ಧ್ರುವ ಸಂರಚನಾ sshkey *fromkey,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *tokey, Identity *id, ಧ್ರುವ ವರ್ಣ *user,
    ಧ್ರುವ ವರ್ಣ **hostnamep)
{
	size_t i;
	ಸಂರಚನಾ dest_constraint *d;

	ಯದಿ (hostnamep != ರಿಕ್ತ)
		*hostnamep = ರಿಕ್ತ;
	ಪ್ರತಿ (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->to.user ? d->to.user : "", d->to.user ? "@" : "",
		    d->to.hostname ? d->to.hostname : "(ANY)", d->to.nkeys);

		/* Match 'from' key */
		ಯದಿ (fromkey == ರಿಕ್ತ) {
			/* We are matching the first hop */
			ಯದಿ (d->from.hostname != ರಿಕ್ತ || d->from.nkeys != 0)
				ಅನುವರ್ತ;
		} ಅನ್ಯಥಾ ಯದಿ (match_ಕೀಲಿ_hop("from", fromkey, &d->from) != 0)
			ಅನುವರ್ತ;

		/* Match 'to' key */
		ಯದಿ (tokey != ರಿಕ್ತ && match_ಕೀಲಿ_hop("to", tokey, &d->to) != 0)
			ಅನುವರ್ತ;

		/* Match user if specified */
		ಯದಿ (d->to.user != ರಿಕ್ತ && user != ರಿಕ್ತ &&
		    !match_pattern(user, d->to.user))
			ಅನುವರ್ತ;

		/* successfully matched this constraint */
		ಯದಿ (hostnamep != ರಿಕ್ತ)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == ರಿಕ್ತ ? "*" : d->to.hostname);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->ಕೀಲಿ), id->comment);
	ಪ್ರತ್ಯಾಗಮ -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
identity_permitted(Identity *id, SocketEntry *e, ವರ್ಣ *user,
    ಧ್ರುವ ವರ್ಣ **forward_hostnamep, ಧ್ರುವ ವರ್ಣ **last_hostnamep)
{
	size_t i;
	ಧ್ರುವ ವರ್ಣ **hp;
	ಸಂರಚನಾ hostkey_sid *hks;
	ಧ್ರುವ ಸಂರಚನಾ sshkey *fromkey = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *test_user;
	ವರ್ಣ *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->ಕೀಲಿ), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	ಯದಿ (id->ndest_constraints == 0)
		ಪ್ರತ್ಯಾಗಮ 0; /* unconstrained */
	ಯದಿ (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (e->nsession_ids == 0)
		ಪ್ರತ್ಯಾಗಮ 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	ಪ್ರತಿ (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		ಯದಿ (hks->ಕೀಲಿ == ರಿಕ್ತ)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = ರಿಕ್ತ;
		ಯದಿ (fromkey != ರಿಕ್ತ &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("fingerprint failed");
		ಯದಿ ((fp2 = sshkey_fingerprint(hks->ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->ಕೀಲಿ), fp2);
		ಮುಕ್ತ(fp1);
		ಮುಕ್ತ(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = ರಿಕ್ತ;
		ಯದಿ (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		ಅನ್ಯಥಾ ಯದಿ (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = ರಿಕ್ತ;
		ಯದಿ (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			ಯದಿ (hks->forwarded && user != ರಿಕ್ತ) {
				error_f("tried to sign on forwarding hop");
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		} ಅನ್ಯಥಾ ಯದಿ (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		ಯದಿ (permitted_by_dest_constraints(fromkey, hks->ಕೀಲಿ, id,
		    test_user, hp) != 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		fromkey = hks->ಕೀಲಿ;
	}
	/*
	 * Another special case: if the last bound session ID was for a
	 * forwarding, and this function is not being called to check a sign
	 * request (i.e. no 'user' supplied), then only permit the key if
	 * there is a permission that would allow it to be used at another
	 * destination. This hides keys that are allowed to be used to
	 * authenticate *to* a host but not permitted for *use* beyond it.
	 */
	hks = &e->session_ids[e->nsession_ids - 1];
	ಯದಿ (hks->forwarded && user == ರಿಕ್ತ &&
	    permitted_by_dest_constraints(hks->ಕೀಲಿ, ರಿಕ್ತ, id,
	    ರಿಕ್ತ, ರಿಕ್ತ) != 0) {
		debug3_f("key permitted at host but not after");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* success */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
socket_is_remote(SocketEntry *e)
{
	ಪ್ರತ್ಯಾಗಮ e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
ಸ್ಥಿರ Identity *
lookup_identity(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		ಯದಿ (sshkey_equal(ಕೀಲಿ, id->ಕೀಲಿ))
			ಪ್ರತ್ಯಾಗಮ (id);
	}
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

/* Check confirmation of keysign request */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
confirm_ಕೀಲಿ(Identity *id, ಧ್ರುವ ವರ್ಣ *extra)
{
	ವರ್ಣ *p;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	p = sshkey_fingerprint(id->ಕೀಲಿ, fingerprint_hash, SSH_FP_DEFAULT);
	ಯದಿ (p != ರಿಕ್ತ &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == ರಿಕ್ತ ? "" : "\n", extra == ರಿಕ್ತ ? "" : extra))
		ret = 0;
	ಮುಕ್ತ(p);

	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_status_generic(SocketEntry *e, u_int code)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_status(SocketEntry *e, ಪೂರ್ಣಾಙ್ಕ success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
ಸ್ಥಿರ ಶೂನ್ಯ
process_request_identities(SocketEntry *e)
{
	Identity *id;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ, *ಕೀಲಿಗಳು;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i = 0, nentries = 0;
	ವರ್ಣ *fp;

	debug2_f("entering");

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ || (ಕೀಲಿಗಳು = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		ಯದಿ ((fp = sshkey_fingerprint(id->ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->ಕೀಲಿ), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		ಮುಕ್ತ(fp);
		/* identity not visible, don't include in response */
		ಯದಿ (identity_permitted(id, e, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ) != 0)
			ಅನುವರ್ತ;
		ಯದಿ ((r = sshkey_puts(id->ಕೀಲಿ, ಕೀಲಿಗಳು)) != 0 ||
		    (r = sshbuf_put_cstring(ಕೀಲಿಗಳು, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			ಅನುವರ್ತ;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, nentries)) != 0 ||
	    (r = sshbuf_putb(ಸಂದೇಶ, ಕೀಲಿಗಳು)) != 0)
		fatal_fr(r, "compose");
	ಯದಿ ((r = sshbuf_put_stringb(e->output, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ಸಂದೇಶ);
	sshbuf_free(ಕೀಲಿಗಳು);
}


ಸ್ಥಿರ ವರ್ಣ *
agent_decode_alg(ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_int flags)
{
	ಯದಿ (ಕೀಲಿ->type == ಕೀಲಿ_RSA) {
		ಯದಿ (flags & SSH_AGENT_RSA_SHA2_256)
			ಪ್ರತ್ಯಾಗಮ "rsa-sha2-256";
		ಅನ್ಯಥಾ ಯದಿ (flags & SSH_AGENT_RSA_SHA2_512)
			ಪ್ರತ್ಯಾಗಮ "rsa-sha2-512";
	} ಅನ್ಯಥಾ ಯದಿ (ಕೀಲಿ->type == ಕೀಲಿ_RSA_CERT) {
		ಯದಿ (flags & SSH_AGENT_RSA_SHA2_256)
			ಪ್ರತ್ಯಾಗಮ "rsa-sha2-256-cert-v01@openssh.com";
		ಅನ್ಯಥಾ ಯದಿ (flags & SSH_AGENT_RSA_SHA2_512)
			ಪ್ರತ್ಯಾಗಮ "rsa-sha2-512-cert-v01@openssh.com";
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_userauth_request(ಸಂರಚನಾ sshbuf *ಸಂದೇಶ, ಧ್ರುವ ಸಂರಚನಾ sshkey *expected_ಕೀಲಿ,
    ವರ್ಣ **userp, ಸಂರಚನಾ sshbuf **sess_idp, ಸಂರಚನಾ sshkey **hostkeyp)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ, *sess_id = ರಿಕ್ತ;
	ವರ್ಣ *user = ರಿಕ್ತ, *service = ರಿಕ್ತ, *method = ರಿಕ್ತ, *pkalg = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char t, sig_follows;
	ಸಂರಚನಾ sshkey *mkey = ರಿಕ್ತ, *hostkey = ರಿಕ್ತ;

	ಯದಿ (userp != ರಿಕ್ತ)
		*userp = ರಿಕ್ತ;
	ಯದಿ (sess_idp != ರಿಕ್ತ)
		*sess_idp = ರಿಕ್ತ;
	ಯದಿ (hostkeyp != ರಿಕ್ತ)
		*hostkeyp = ರಿಕ್ತ;
	ಯದಿ ((b = sshbuf_fromb(ಸಂದೇಶ)) == ರಿಕ್ತ)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	ಯದಿ ((r = sshbuf_froms(b, &sess_id)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, ರಿಕ್ತ)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, ರಿಕ್ತ)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, ರಿಕ್ತ)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, ರಿಕ್ತ)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*ಕೀಲಿ*/
		ಗಚ್ಛ out;
	ಯದಿ (t != SSH2_ಸಂದೇಶ_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_ಕೀಲಿ, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_ಕೀಲಿ->type) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		ಯದಿ ((r = sshkey_froms(b, &hostkey)) != 0)
			ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	ಯದಿ (userp != ರಿಕ್ತ) {
		*userp = user;
		user = ರಿಕ್ತ;
	}
	ಯದಿ (sess_idp != ರಿಕ್ತ) {
		*sess_idp = sess_id;
		sess_id = ರಿಕ್ತ;
	}
	ಯದಿ (hostkeyp != ರಿಕ್ತ) {
		*hostkeyp = hostkey;
		hostkey = ರಿಕ್ತ;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(service);
	ಮುಕ್ತ(method);
	ಮುಕ್ತ(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_sshsig_request(ಸಂರಚನಾ sshbuf *ಸಂದೇಶ)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *b;

	ಯದಿ ((b = sshbuf_fromb(ಸಂದೇಶ)) == ರಿಕ್ತ)
		fatal_f("sshbuf_fromb");

	ಯದಿ ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, ರಿಕ್ತ, ರಿಕ್ತ)) != 0) /* H(msg) */
		ಗಚ್ಛ out;
	ಯದಿ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_websafe_message_contents(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *data)
{
	ಯದಿ (parse_userauth_request(data, ಕೀಲಿ, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ) == 0) {
		debug_f("signed data matches public key userauth request");
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಯದಿ (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		ಪ್ರತ್ಯಾಗಮ 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
buf_equal(ಧ್ರುವ ಸಂರಚನಾ sshbuf *a, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b)
{
	ಯದಿ (sshbuf_ptr(a) == ರಿಕ್ತ || sshbuf_ptr(b) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (sshbuf_len(a) != sshbuf_len(b))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* ssh2 only */
ಸ್ಥಿರ ಶೂನ್ಯ
process_sign_request2(SocketEntry *e)
{
	u_char *signature = ರಿಕ್ತ;
	size_t slen = 0;
	u_int compat = 0, flags;
	ಪೂರ್ಣಾಙ್ಕ r, ok = -1, retried = 0;
	ವರ್ಣ *fp = ರಿಕ್ತ, *pin = ರಿಕ್ತ, *prompt = ರಿಕ್ತ;
	ವರ್ಣ *user = ರಿಕ್ತ, *sig_dest = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *fwd_host = ರಿಕ್ತ, *dest_host = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ = ರಿಕ್ತ, *data = ರಿಕ್ತ, *sid = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ, *hostkey = ರಿಕ್ತ;
	ಸಂರಚನಾ identity *id;
	ಸಂರಚನಾ notifier_ctx *notifier = ರಿಕ್ತ;

	debug_f("entering");

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ || (data = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_froms(e->request, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		ಗಚ್ಛ send;
	}

	ಯದಿ ((id = lookup_identity(ಕೀಲಿ)) == ರಿಕ್ತ) {
		verbose_f("%s key not found", sshkey_type(ಕೀಲಿ));
		ಗಚ್ಛ send;
	}
	ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		fatal_f("fingerprint failed");

	ಯದಿ (id->ndest_constraints != 0) {
		ಯದಿ (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			ಗಚ್ಛ send;
		}
		ಯದಿ (parse_userauth_request(data, ಕೀಲಿ, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			ಗಚ್ಛ send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		ಯದಿ (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			ಗಚ್ಛ send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		ಯದಿ (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->ಕೀಲಿ), fp);
			ಗಚ್ಛ send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		ಯದಿ (e->nsession_ids > 1 && hostkey == ರಿಕ್ತ) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			ಗಚ್ಛ send;
		}
		ಯದಿ (hostkey != ರಿಕ್ತ && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].ಕೀಲಿ)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			ಗಚ್ಛ send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	ಯದಿ (id->confirm && confirm_ಕೀಲಿ(id, sig_dest) != 0) {
		verbose_f("user refused key");
		ಗಚ್ಛ send;
	}
	ಯದಿ (sshkey_is_sk(id->ಕೀಲಿ)) {
		ಯದಿ (restrict_websafe &&
		    match_pattern_list(id->ಕೀಲಿ->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(ಕೀಲಿ, data)) {
			/* error already logged */
			ಗಚ್ಛ send;
		}
		ಯದಿ (id->ಕೀಲಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->ಕೀಲಿ), fp,
			    sig_dest == ರಿಕ್ತ ? "" : "\n",
			    sig_dest == ರಿಕ್ತ ? "" : sig_dest);
		}
	}
 retry_pin:
	ಯದಿ ((r = sshkey_sign(id->ಕೀಲಿ, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(ಕೀಲಿ, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ಯದಿ (pin == ರಿಕ್ತ && !retried && sshkey_is_sk(id->ಕೀಲಿ) &&
		    r == SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
			notify_complete(notifier, ರಿಕ್ತ);
			notifier = ರಿಕ್ತ;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->ಕೀಲಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->ಕೀಲಿ), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			ಗಚ್ಛ retry_pin;
		}
		error_fr(r, "sshkey_sign");
		ಗಚ್ಛ send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	ಯದಿ (ok == 0) {
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(ಸಂದೇಶ, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	ಯದಿ ((r = sshbuf_put_stringb(e->output, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(ಸಂದೇಶ);
	sshkey_free(ಕೀಲಿ);
	sshkey_free(hostkey);
	ಮುಕ್ತ(fp);
	ಮುಕ್ತ(signature);
	ಮುಕ್ತ(sig_dest);
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(prompt);
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));
}

/* shared */
ಸ್ಥಿರ ಶೂನ್ಯ
process_remove_identity(SocketEntry *e)
{
	ಪೂರ್ಣಾಙ್ಕ r, success = 0;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	Identity *id;

	debug2_f("entering");
	ಯದಿ ((r = sshkey_froms(e->request, &ಕೀಲಿ)) != 0) {
		error_fr(r, "parse key");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((id = lookup_identity(ಕೀಲಿ)) == ರಿಕ್ತ) {
		debug_f("key not found");
		ಗಚ್ಛ done;
	}
	/* identity not visible, cannot be removed */
	ಯದಿ (identity_permitted(id, e, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ) != 0)
		ಗಚ್ಛ done; /* error already logged */
	/* We have this key, free it. */
	ಯದಿ (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(ಕೀಲಿ);
	send_status(e, success);
}

ಸ್ಥಿರ ಶೂನ್ಯ
remove_all_identities(ಶೂನ್ಯ)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	ಪ್ರತಿ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
ಸ್ಥಿರ time_t
reaper(ಶೂನ್ಯ)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	ಪ್ರತಿ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		ಯದಿ (id->death == 0)
			ಅನುವರ್ತ;
		ಯದಿ (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} ಅನ್ಯಥಾ
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	ಯದಿ (deadline == 0 || deadline <= now)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ (deadline - now);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_dest_constraint_hop(ಸಂರಚನಾ sshbuf *b, ಸಂರಚನಾ dest_constraint_hop *dch)
{
	u_char ಕೀಲಿ_is_ca;
	size_t elen = 0, userlen = 0;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ವರ್ಣ *fp;

	memset(dch, '\0', ಪರಿಮಾಣ(*dch));
	ಯದಿ ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ರಿಕ್ತ, &elen)) != 0) {
		error_fr(r, "parse");
		ಗಚ್ಛ out;
	}
	ಯದಿ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಗಚ್ಛ out;
	}
	ಯದಿ (*dch->hostname == '\0') {
		ಮುಕ್ತ(dch->hostname);
		dch->hostname = ರಿಕ್ತ;
	}
	ಯದಿ (*dch->user == '\0') {
		ಮುಕ್ತ(dch->user);
		dch->user = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯಾವತ್ (sshbuf_len(b) != 0) {
		dch->ಕೀಲಿಗಳು = xrecallocarray(dch->ಕೀಲಿಗಳು, dch->nkeys,
		    dch->nkeys + 1, ಪರಿಮಾಣ(*dch->ಕೀಲಿಗಳು));
		dch->ಕೀಲಿ_is_ca = xrecallocarray(dch->ಕೀಲಿ_is_ca, dch->nkeys,
		    dch->nkeys + 1, ಪರಿಮಾಣ(*dch->ಕೀಲಿ_is_ca));
		ಯದಿ ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &ಕೀಲಿ_is_ca)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == ರಿಕ್ತ ? "" : dch->user,
		    dch->user == ರಿಕ್ತ ? "" : "@",
		    dch->hostname, ಕೀಲಿ_is_ca ? "CA " : "", sshkey_type(k), fp);
		ಮುಕ್ತ(fp);
		dch->ಕೀಲಿಗಳು[dch->nkeys] = k;
		dch->ಕೀಲಿ_is_ca[dch->nkeys] = ಕೀಲಿ_is_ca != 0;
		dch->nkeys++;
		k = ರಿಕ್ತ; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_dest_constraint(ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ dest_constraint *dc)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ, *frombuf = ರಿಕ್ತ, *tobuf = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', ಪರಿಮಾಣ(*dc));
	ಯದಿ ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, ರಿಕ್ತ, &elen)) != 0) {
		error_fr(r, "parse");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		ಗಚ್ಛ out; /* already logged */
	ಯದಿ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಗಚ್ಛ out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	ಯದಿ ((dc->from.hostname == ರಿಕ್ತ) != (dc->from.nkeys == 0) ||
	    dc->from.user != ರಿಕ್ತ) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (dc->to.hostname == ರಿಕ್ತ || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_ಕೀಲಿ_constraint_extension(ಸಂರಚನಾ sshbuf *m, ವರ್ಣ **sk_providerp,
    ಸಂರಚನಾ dest_constraint **dcsp, size_t *ndcsp, ಪೂರ್ಣಾಙ್ಕ *cert_onlyp,
    ಸಂರಚನಾ sshkey ***certs, size_t *ncerts)
{
	ವರ್ಣ *ext_name = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	u_char v;
	ಸಂರಚನಾ sshkey *k;

	ಯದಿ ((r = sshbuf_get_cstring(m, &ext_name, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse constraint extension");
		ಗಚ್ಛ out;
	}
	debug_f("constraint ext %s", ext_name);
	ಯದಿ (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		ಯದಿ (sk_providerp == ರಿಕ್ತ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ (*sk_providerp != ರಿಕ್ತ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_get_cstring(m, sk_providerp, ರಿಕ್ತ)) != 0) {
			error_fr(r, "parse %s", ext_name);
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		ಯದಿ (*dcsp != ರಿಕ್ತ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			ಗಚ್ಛ out;
		}
		ಯಾವತ್ (sshbuf_len(b) != 0) {
			ಯದಿ (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				ಗಚ್ಛ out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    ಪರಿಮಾಣ(**dcsp));
			ಯದಿ ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				ಗಚ್ಛ out; /* error already logged */
		}
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		ಯದಿ (certs == ರಿಕ್ತ || ncerts == ರಿಕ್ತ || cert_onlyp == ರಿಕ್ತ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ (*certs != ರಿಕ್ತ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			ಗಚ್ಛ out;
		}
		*cert_onlyp = v != 0;
		ಯಾವತ್ (sshbuf_len(b) != 0) {
			ಯದಿ (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				ಗಚ್ಛ out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    ಪರಿಮಾಣ(**certs));
			ಯದಿ ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				ಗಚ್ಛ out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} ಅನ್ಯಥಾ {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	ಮುಕ್ತ(ext_name);
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_ಕೀಲಿ_constraints(ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshkey *k, time_t *deathp,
    u_int *secondsp, ಪೂರ್ಣಾಙ್ಕ *confirmp, ವರ್ಣ **sk_providerp,
    ಸಂರಚನಾ dest_constraint **dcsp, size_t *ndcsp,
    ಪೂರ್ಣಾಙ್ಕ *cert_onlyp, size_t *ncerts, ಸಂರಚನಾ sshkey ***certs)
{
	u_char ctype;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int seconds;

	ಯಾವತ್ (sshbuf_len(m)) {
		ಯದಿ ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			ಗಚ್ಛ out;
		}
		ವಿಕಲ್ಪ (ctype) {
		ಪಕ್ಷ SSH_AGENT_CONSTRAIN_LIFETIME:
			ಯದಿ (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				ಗಚ್ಛ out;
			}
			ಯದಿ ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				ಗಚ್ಛ out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			ಭಙ್ಗ;
		ಪಕ್ಷ SSH_AGENT_CONSTRAIN_CONFIRM:
			ಯದಿ (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				ಗಚ್ಛ out;
			}
			*confirmp = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ SSH_AGENT_CONSTRAIN_EXTENSION:
			ಯದಿ ((r = parse_ಕೀಲಿ_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				ಗಚ್ಛ out; /* error already logged */
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			ಗಚ್ಛ out;
		}
	}
	/* success */
	r = 0;
 out:
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_add_identity(SocketEntry *e)
{
	Identity *id;
	ಪೂರ್ಣಾಙ್ಕ success = 0, confirm = 0;
	ವರ್ಣ *fp, *comment = ರಿಕ್ತ, *sk_provider = ರಿಕ್ತ;
	ವರ್ಣ canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	ಸಂರಚನಾ dest_constraint *dest_constraints = ರಿಕ್ತ;
	size_t ndest_constraints = 0;
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	ಯದಿ ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == ರಿಕ್ತ ||
	    (r = sshbuf_get_cstring(e->request, &comment, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse");
		ಗಚ್ಛ out;
	}
	ಯದಿ (parse_ಕೀಲಿ_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		ಗಚ್ಛ out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	ಯದಿ (sk_provider != ರಿಕ್ತ) {
		ಯದಿ (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			ಗಚ್ಛ out;
		}
		ಯದಿ (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} ಅನ್ಯಥಾ {
			ಯದಿ (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				ಗಚ್ಛ out;
			}
			ಯದಿ (realpath(sk_provider, canonical_provider) == ರಿಕ್ತ) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				ಗಚ್ಛ out;
			}
			ಮುಕ್ತ(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			ಯದಿ (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				ಗಚ್ಛ out;
			}
		}
	}
	ಯದಿ ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		ಗಚ್ಛ out;
	}
	ಯದಿ (lifetime && !death)
		death = monotime() + lifetime;
	ಯದಿ ((id = lookup_identity(k)) == ರಿಕ್ತ) {
		id = xcalloc(1, ಪರಿಮಾಣ(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} ಅನ್ಯಥಾ {
		/* identity not visible, do not update */
		ಯದಿ (identity_permitted(id, e, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ) != 0)
			ಗಚ್ಛ out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->ಕೀಲಿ);
		ಮುಕ್ತ(id->comment);
		ಮುಕ್ತ(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->ಕೀಲಿ = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	ಯದಿ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == ರಿಕ್ತ ? "none" : sk_provider, ndest_constraints);
	ಮುಕ್ತ(fp);
	/* transferred */
	k = ರಿಕ್ತ;
	comment = ರಿಕ್ತ;
	sk_provider = ರಿಕ್ತ;
	dest_constraints = ರಿಕ್ತ;
	ndest_constraints = 0;
	success = 1;
 out:
	ಮುಕ್ತ(sk_provider);
	ಮುಕ್ತ(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
ಸ್ಥಿರ ಶೂನ್ಯ
process_lock_agent(SocketEntry *e, ಪೂರ್ಣಾಙ್ಕ lock)
{
	ಪೂರ್ಣಾಙ್ಕ r, success = 0, delay;
	ವರ್ಣ *passwd;
	u_char passwdhash[LOCK_SIZE];
	ಸ್ಥಿರ u_int fail_ಎಣಿಕೆ = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	ಯದಿ ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (pwlen == 0) {
		debug("empty password not supported");
	} ಅನ್ಯಥಾ ಯದಿ (locked && !lock) {
		ಯದಿ (bcrypt_pbkdf(passwd, pwlen, lock_salt, ಪರಿಮಾಣ(lock_salt),
		    passwdhash, ಪರಿಮಾಣ(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		ಯದಿ (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_ಎಣಿಕೆ = 0;
			explicit_bzero(lock_pwhash, ಪರಿಮಾಣ(lock_pwhash));
			success = 1;
		} ಅನ್ಯಥಾ {
			/* delay in 0.1s increments up to 10s */
			ಯದಿ (fail_ಎಣಿಕೆ < 100)
				fail_ಎಣಿಕೆ++;
			delay = 100000 * fail_ಎಣಿಕೆ;
			debug("unlock failed, delaying %0.1lf seconds",
			    (ದ್ವಿಗುಣ)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, ಪರಿಮಾಣ(passwdhash));
	} ಅನ್ಯಥಾ ಯದಿ (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, ಪರಿಮಾಣ(lock_salt));
		ಯದಿ (bcrypt_pbkdf(passwd, pwlen, lock_salt, ಪರಿಮಾಣ(lock_salt),
		    lock_pwhash, ಪರಿಮಾಣ(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

ಸ್ಥಿರ ಶೂನ್ಯ
no_identities(SocketEntry *e)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(ಸಂದೇಶ);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
ಸ್ಥಿರ ಶೂನ್ಯ
add_p11_identity(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ವರ್ಣ *comment, ಧ್ರುವ ವರ್ಣ *provider,
    time_t death, u_int confirm, ಸಂರಚನಾ dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	ಯದಿ (lookup_identity(ಕೀಲಿ) != ರಿಕ್ತ) {
		sshkey_free(ಕೀಲಿ);
		ಮುಕ್ತ(comment);
		ಪ್ರತ್ಯಾಗಮ;
	}
	id = xcalloc(1, ಪರಿಮಾಣ(Identity));
	id->ಕೀಲಿ = ಕೀಲಿ;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_add_smartcard_ಕೀಲಿ(SocketEntry *e)
{
	ವರ್ಣ *provider = ರಿಕ್ತ, *pin = ರಿಕ್ತ, canonical_provider[PATH_MAX];
	ವರ್ಣ **comments = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, i, ಎಣಿಕೆ = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು = ರಿಕ್ತ, *k;
	ಸಂರಚನಾ dest_constraint *dest_constraints = ರಿಕ್ತ;
	size_t j, ndest_constraints = 0, ncerts = 0;
	ಸಂರಚನಾ sshkey **certs = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ cert_only = 0;

	debug2_f("entering");
	ಯದಿ ((r = sshbuf_get_cstring(e->request, &provider, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse");
		ಗಚ್ಛ send;
	}
	ಯದಿ (parse_ಕೀಲಿ_constraints(e->request, ರಿಕ್ತ, &death, &seconds, &confirm,
	    ರಿಕ್ತ, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		ಗಚ್ಛ send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	ಯದಿ (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		ಗಚ್ಛ send;
	}
	ಯದಿ (realpath(provider, canonical_provider) == ರಿಕ್ತ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		ಗಚ್ಛ send;
	}
	ಯದಿ (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		ಗಚ್ಛ send;
	}
	debug_f("add %.100s", canonical_provider);
	ಯದಿ (lifetime && !death)
		death = monotime() + lifetime;

	ಎಣಿಕೆ = pkcs11_add_provider(canonical_provider, pin, &ಕೀಲಿಗಳು, &comments);
	ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++) {
		ಯದಿ (comments[i] == ರಿಕ್ತ || comments[i][0] == '\0') {
			ಮುಕ್ತ(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		ಪ್ರತಿ (j = 0; j < ncerts; j++) {
			ಯದಿ (!sshkey_is_cert(certs[j]))
				ಅನುವರ್ತ;
			ಯದಿ (!sshkey_equal_public(ಕೀಲಿಗಳು[i], certs[j]))
				ಅನುವರ್ತ;
			ಯದಿ (pkcs11_make_cert(ಕೀಲಿಗಳು[i], certs[j], &k) != 0)
				ಅನುವರ್ತ;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		ಯದಿ (!cert_only && lookup_identity(ಕೀಲಿಗಳು[i]) == ರಿಕ್ತ) {
			add_p11_identity(ಕೀಲಿಗಳು[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			ಕೀಲಿಗಳು[i] = ರಿಕ್ತ;		/* transferred */
			comments[i] = ರಿಕ್ತ;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(ಕೀಲಿಗಳು[i]);
		ಮುಕ್ತ(comments[i]);
	}
send:
	ಮುಕ್ತ(pin);
	ಮುಕ್ತ(provider);
	ಮುಕ್ತ(ಕೀಲಿಗಳು);
	ಮುಕ್ತ(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ಪ್ರತಿ (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	ಮುಕ್ತ(certs);
	send_status(e, success);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_remove_smartcard_ಕೀಲಿ(SocketEntry *e)
{
	ವರ್ಣ *provider = ರಿಕ್ತ, *pin = ರಿಕ್ತ, canonical_provider[PATH_MAX];
	ಪೂರ್ಣಾಙ್ಕ r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	ಯದಿ ((r = sshbuf_get_cstring(e->request, &provider, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse");
		ಗಚ್ಛ send;
	}
	ಮುಕ್ತ(pin);

	ಯದಿ (realpath(provider, canonical_provider) == ರಿಕ್ತ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		ಗಚ್ಛ send;
	}

	debug_f("remove %.100s", canonical_provider);
	ಪ್ರತಿ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		ಯದಿ (id->provider == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	ಯದಿ (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	ಅನ್ಯಥಾ
		error_f("pkcs11_del_provider failed");
send:
	ಮುಕ್ತ(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
process_ext_session_bind(SocketEntry *e)
{
	ಪೂರ್ಣಾಙ್ಕ r, sid_match, ಕೀಲಿ_match;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *sid = ರಿಕ್ತ, *sig = ರಿಕ್ತ;
	ವರ್ಣ *fp = ರಿಕ್ತ;
	size_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	ಯದಿ ((r = sshkey_froms(e->request, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	ಯದಿ ((r = sshkey_verify(ಕೀಲಿ, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), ರಿಕ್ತ, 0, ರಿಕ್ತ)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(ಕೀಲಿ), fp);
		ಗಚ್ಛ out;
	}
	/* check whether sid/key already recorded */
	ಪ್ರತಿ (i = 0; i < e->nsession_ids; i++) {
		ಯದಿ (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			ಗಚ್ಛ out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		ಕೀಲಿ_match = sshkey_equal(ಕೀಲಿ, e->session_ids[i].ಕೀಲಿ);
		ಯದಿ (sid_match && ಕೀಲಿ_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(ಕೀಲಿ), fp);
			r = 0;
			ಗಚ್ಛ out;
		} ಅನ್ಯಥಾ ಯದಿ (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(ಕೀಲಿ), fp);
			r = -1;
			ಗಚ್ಛ out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	ಯದಿ (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		ಗಚ್ಛ out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, ಪರಿಮಾಣ(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(ಕೀಲಿ), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].ಕೀಲಿ = ಕೀಲಿ;
	e->session_ids[i].forwarded = fwd != 0;
	ಕೀಲಿ = ರಿಕ್ತ; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	ಯದಿ ((e->session_ids[i].sid = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	ಮುಕ್ತ(fp);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(sid);
	sshbuf_free(sig);
	ಪ್ರತ್ಯಾಗಮ r == 0 ? 1 : 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
process_ext_query(SocketEntry *e)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ = ರಿಕ್ತ;

	debug2_f("entering");
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	ಯದಿ ((r = sshbuf_put_stringb(e->output, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extension(SocketEntry *e)
{
	ಪೂರ್ಣಾಙ್ಕ r, replied = 0, success = 0;
	ವರ್ಣ *name;

	debug2_f("entering");
	ಯದಿ ((r = sshbuf_get_cstring(e->request, &name, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		ಪ್ರತ್ಯಾಗಮ;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	ಯದಿ (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} ಅನ್ಯಥಾ ಯದಿ (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		ಗಚ್ಛ generic_fail;
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} ಅನ್ಯಥಾ {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		ಮುಕ್ತ(name);
		send_status(e, 0);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಮುಕ್ತ(name);
	/* Agent failures are signalled with a different error code */
	ಯದಿ (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
process_message(u_int socknum)
{
	u_int ಸಂದೇಶ_len;
	u_char type;
	ಧ್ರುವ u_char *cp;
	ಪೂರ್ಣಾಙ್ಕ r;
	SocketEntry *e;

	ಯದಿ (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	ಯದಿ (sshbuf_len(e->ಒಳಹರಿವು) < 5)
		ಪ್ರತ್ಯಾಗಮ 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->ಒಳಹರಿವು);
	ಸಂದೇಶ_len = PEEK_U32(cp);
	ಯದಿ (ಸಂದೇಶ_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, ಸಂದೇಶ_len, AGENT_MAX_LEN);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (sshbuf_len(e->ಒಳಹರಿವು) < ಸಂದೇಶ_len + 4)
		ಪ್ರತ್ಯಾಗಮ 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	ಯದಿ ((r = sshbuf_get_stringb(e->ಒಳಹರಿವು, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		ಯದಿ (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	ಯದಿ (locked && type != SSH_AGENTC_UNLOCK) {
		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			ಭಙ್ಗ;
		ಪಕ್ಷ SSH_AGENTC_EXTENSION:
			process_extension(e);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		ಪ್ರತ್ಯಾಗಮ 1;
	}

	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ SSH_AGENTC_LOCK:
	ಪಕ್ಷ SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		ಭಙ್ಗ;
	/* ssh2 */
	ಪಕ್ಷ SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_AGENTC_ADD_IDENTITY:
	ಪಕ್ಷ SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		ಭಙ್ಗ;
#ifdef ENABLE_PKCS11
	ಪಕ್ಷ SSH_AGENTC_ADD_SMARTCARD_ಕೀಲಿ:
	ಪಕ್ಷ SSH_AGENTC_ADD_SMARTCARD_ಕೀಲಿ_CONSTRAINED:
		process_add_smartcard_ಕೀಲಿ(e);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_AGENTC_REMOVE_SMARTCARD_ಕೀಲಿ:
		process_remove_smartcard_ಕೀಲಿ(e);
		ಭಙ್ಗ;
#endif /* ENABLE_PKCS11 */
	ಪಕ್ಷ SSH_AGENTC_EXTENSION:
		process_extension(e);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
new_socket(sock_type type, ಪೂರ್ಣಾಙ್ಕ fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	ಯದಿ (fd > max_fd)
		max_fd = fd;

	ಪ್ರತಿ (i = 0; i < sockets_alloc; i++)
		ಯದಿ (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			ಯದಿ ((sockets[i].ಒಳಹರಿವು = sshbuf_new()) == ರಿಕ್ತ ||
			    (sockets[i].output = sshbuf_new()) == ರಿಕ್ತ ||
			    (sockets[i].request = sshbuf_new()) == ರಿಕ್ತ)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			ಪ್ರತ್ಯಾಗಮ;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    ಪರಿಮಾಣ(sockets[0]));
	ಪ್ರತಿ (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	ಯದಿ ((sockets[old_alloc].ಒಳಹರಿವು = sshbuf_new()) == ರಿಕ್ತ ||
	    (sockets[old_alloc].output = sshbuf_new()) == ರಿಕ್ತ ||
	    (sockets[old_alloc].request = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_socket_read(u_int socknum)
{
	ಸಂರಚನಾ sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	ಪೂರ್ಣಾಙ್ಕ fd;

	slen = ಪರಿಮಾಣ(sunaddr);
	fd = accept(sockets[socknum].fd, (ಸಂರಚನಾ sockaddr *)&sunaddr, &slen);
	ಯದಿ (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_conn_read(u_int socknum)
{
	ವರ್ಣ buf[AGENT_RBUF_LEN];
	ssize_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((len = ಪಠ(sockets[socknum].fd, buf, ಪರಿಮಾಣ(buf))) <= 0) {
		ಯದಿ (len == -1) {
			ಯದಿ (errno == EAGAIN || errno == EINTR)
				ಪ್ರತ್ಯಾಗಮ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((r = sshbuf_put(sockets[socknum].ಒಳಹರಿವು, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, ಪರಿಮಾಣ(buf));
	ಪ್ರತಿ (;;) {
		ಯದಿ ((r = process_message(socknum)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಅನ್ಯಥಾ ಯದಿ (r == 0)
			ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
handle_conn_write(u_int socknum)
{
	ssize_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (sshbuf_len(sockets[socknum].output) == 0)
		ಪ್ರತ್ಯಾಗಮ 0; /* shouldn't happen */
	ಯದಿ ((len = ಲಿಖ(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		ಯದಿ (len == -1) {
			ಯದಿ (errno == EAGAIN || errno == EINTR)
				ಪ್ರತ್ಯಾಗಮ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
after_poll(ಸಂರಚನಾ pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	ಪ್ರತಿ (i = 0; i < npfd; i++) {
		ಯದಿ (pfd[i].revents == 0)
			ಅನುವರ್ತ;
		/* Find sockets entry */
		ಪ್ರತಿ (socknum = 0; socknum < sockets_alloc; socknum++) {
			ಯದಿ (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				ಅನುವರ್ತ;
			ಯದಿ (pfd[i].fd == sockets[socknum].fd)
				ಭಙ್ಗ;
		}
		ಯದಿ (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			ಅನುವರ್ತ;
		}
		/* Process events */
		ವಿಕಲ್ಪ (sockets[socknum].type) {
		ಪಕ್ಷ AUTH_SOCKET:
			ಯದಿ ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				ಭಙ್ಗ;
			ಯದಿ (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				ಭಙ್ಗ;
			}
			ಯದಿ (handle_socket_read(socknum) == 0)
				activefds++;
			ಭಙ್ಗ;
		ಪಕ್ಷ AUTH_CONNECTION:
			ಯದಿ ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				ಗಚ್ಛ close_sock;
			ಯದಿ ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				ಯದಿ (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				ಭಙ್ಗ;
			}
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಭಙ್ಗ;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
prepare_poll(ಸಂರಚನಾ pollfd **pfdp, size_t *npfdp, ಸಂರಚನಾ timespec *timeoutp, u_int maxfds)
{
	ಸಂರಚನಾ pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* Count active sockets */
	ಪ್ರತಿ (i = 0; i < sockets_alloc; i++) {
		ವಿಕಲ್ಪ (sockets[i].type) {
		ಪಕ್ಷ AUTH_SOCKET:
		ಪಕ್ಷ AUTH_CONNECTION:
			npfd++;
			ಭಙ್ಗ;
		ಪಕ್ಷ AUTH_UNUSED:
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("Unknown socket type %d", sockets[i].type);
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, ಪರಿಮಾಣ(*pfd))) == ರಿಕ್ತ)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	ಪ್ರತಿ (i = j = 0; i < sockets_alloc; i++) {
		ವಿಕಲ್ಪ (sockets[i].type) {
		ಪಕ್ಷ AUTH_SOCKET:
			ಯದಿ (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				ಭಙ್ಗ;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			ಭಙ್ಗ;
		ಪಕ್ಷ AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			ಯದಿ ((r = sshbuf_check_reserve(sockets[i].ಒಳಹರಿವು,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			ಅನ್ಯಥಾ ಯದಿ (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			ಯದಿ (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಭಙ್ಗ;
		}
	}
	deadline = reaper();
	ಯದಿ (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	ಯದಿ (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_socket(ಶೂನ್ಯ)
{
	ಯದಿ (cleanup_pid != 0 && getpid() != cleanup_pid)
		ಪ್ರತ್ಯಾಗಮ;
	debug_f("cleanup");
	ಯದಿ (socket_name != ರಿಕ್ತ) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		ಮುಕ್ತ(socket_name);
		socket_name = ರಿಕ್ತ;
		ಮುಕ್ತ(socket_dir);
		socket_dir = ರಿಕ್ತ;
	}
}

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	signalled_exit = sig;
}

ಸ್ಥಿರ ಶೂನ್ಯ
keydrop_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	signalled_keydrop = sig;
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_parent_exists(ಶೂನ್ಯ)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	ಯದಿ (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	fprintf(stderr,
	    "usage: ssh-agent [-c | -s] [-DdU] [-T | -A directory | -a bind_address]\n"
	    "                 [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life]\n"
	    "       ssh-agent [-U] [-T | -A directory | -a bind_address]\n"
	    "                 [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life] command [arg ...]\n"
	    "       ssh-agent [-c | -s] -k\n"
	    "       ssh-agent -u\n"
	    "       ssh-agent -V\n");
	exit(1);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ ac, ವರ್ಣ **av)
{
	ಪೂರ್ಣಾಙ್ಕ c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	ಪೂರ್ಣಾಙ್ಕ s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	ಪೂರ್ಣಾಙ್ಕ sock = -1, ch, result, saved_errno;
	pid_t pid;
 	ವರ್ಣ *homedir = ರಿಕ್ತ, *shell, *format, *pidstr, *agentsocket = ರಿಕ್ತ;
	ವರ್ಣ *cp, pidstrbuf[1 + 3 * ಪರಿಮಾಣ pid];
	ವರ್ಣ *fdstr;
	ಧ್ರುವ ವರ್ಣ *errstr = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *ccp;
#ifdef HAVE_SETRLIMIT
	ಸಂರಚನಾ rlimit rlim;
#endif
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	size_t len;
	mode_t prev_mask;
	ಸಂರಚನಾ timespec timeout;
	ಸಂರಚನಾ pollfd *pfd = ರಿಕ್ತ;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	ಪೂರ್ಣಾಙ್ಕ socket_activated = 0;
	ಸಂರಚನಾ passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(ಶೂನ್ಯ)setegid(getgid());
	(ಶೂನ್ಯ)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	ಯದಿ ((pw = getpwuid(getuid())) == ರಿಕ್ತ)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	ಯದಿ (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	ಯಾವತ್ ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ಯದಿ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'c':
			ಯದಿ (s_flag)
				usage();
			c_flag++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'k':
			k_flag++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'O':
			ಯದಿ (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			ಅನ್ಯಥಾ ಯದಿ ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != ರಿಕ್ತ) {
				ಯದಿ (websafe_allowlist != ರಿಕ್ತ)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} ಅನ್ಯಥಾ
				fatal("Unknown -O option");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'P':
			ಯದಿ (allowed_providers != ರಿಕ್ತ)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 's':
			ಯದಿ (c_flag)
				usage();
			s_flag++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'd':
			ಯದಿ (d_flag || D_flag)
				usage();
			d_flag++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
			ಯದಿ (d_flag || D_flag)
				usage();
			D_flag++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'a':
			agentsocket = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'A':
			socket_dirspec = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
			ಯದಿ ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'T':
			T_flag++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'u':
			u_flag++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'U':
			U_flag++;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		ಸ್ವಭಾವ:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	ಯದಿ (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	ಯದಿ (((socket_dirspec != ರಿಕ್ತ) + (agentsocket != ರಿಕ್ತ) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	ಯದಿ (allowed_providers == ರಿಕ್ತ)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	ಯದಿ (websafe_allowlist == ರಿಕ್ತ)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	ಯದಿ (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	ಅನ್ಯಥಾ ಯದಿ (socket_dirspec == ರಿಕ್ತ && agentsocket == ರಿಕ್ತ)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	ಯದಿ (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		ಯದಿ (shell != ರಿಕ್ತ && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	ಯದಿ (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		ಯದಿ (pidstr == ರಿಕ್ತ) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (ಪೂರ್ಣಾಙ್ಕ)strtonum(pidstr, 2, INT_MAX, &errstr);
		ಯದಿ (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		ಯದಿ (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}
	ಯದಿ (u_flag) {
		ಯದಿ ((homedir = get_homedir()) == ರಿಕ್ತ)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		printf("Deleted stale agent sockets in ~/%s\n",
		    _PATH_SSH_AGENT_SOCKET_DIR);
		exit(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#define SSH_AGENT_MIN_FDS (3+1+1+1+4)
	ಯದಿ (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	ಯದಿ (agentsocket == ರಿಕ್ತ && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != ರಿಕ್ತ &&
	    (fdstr = getenv("LISTEN_FDS")) != ರಿಕ್ತ) {
		ಯದಿ (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		ಯದಿ (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (ಪೂರ್ಣಾಙ್ಕ)strtonum(pidstr, 1, INT_MAX, &errstr);
		ಯದಿ (errstr != ರಿಕ್ತ)
			fatal("invalid LISTEN_PID: %s", errstr);
		ಯದಿ (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	ಯದಿ (sock == -1 && agentsocket == ರಿಕ್ತ) {
		/* Listen on a socket in/under a given directory */
		ಯದಿ ((homedir = get_homedir()) == ರಿಕ್ತ)
			fatal("Couldn't determine home directory");
		ಯದಿ (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		ಯದಿ (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		ಮುಕ್ತ(homedir);
	} ಅನ್ಯಥಾ ಯದಿ (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		ಯದಿ ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			ಮುಕ್ತ(socket_name);
			socket_name = ರಿಕ್ತ; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	ಯದಿ (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		ಯದಿ (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	ಯದಿ (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		ಯದಿ (socket_name != ರಿಕ್ತ) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			ಮುಕ್ತ(cp);
			printf("echo Agent pid %ld;\n", (long)parent_pid);
			fflush(stdout);
		}
		ಗಚ್ಛ skip;
	}
	pid = fork();
	ಯದಿ (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	ಯದಿ (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, ಪರಿಮಾಣ pidstrbuf, "%ld", (long)pid);
		ಯದಿ (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			printf(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			ಮುಕ್ತ(cp);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		ಯದಿ (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
	/* child */
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	ಯದಿ (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(ಶೂನ್ಯ)chdir("/");
	ಯದಿ (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	ಯದಿ (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#endif

skip:

	cleanup_pid = getpid();

#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	ಯದಿ (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
	ssh_signal(SIGHUP, cleanup_handler);
	ssh_signal(SIGTERM, cleanup_handler);
	ssh_signal(SIGUSR1, keydrop_handler);

	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGINT);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGUSR1);

	ಯದಿ (socket_name != ರಿಕ್ತ && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	ಯದಿ (socket_dir != ರಿಕ್ತ && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	ಯದಿ (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	ಯದಿ ((ccp = getenv("SSH_SK_HELPER")) == ರಿಕ್ತ || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	ಯದಿ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ಯದಿ ((ccp = getenv("SSH_PKCS11_HELPER")) == ರಿಕ್ತ || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	ಯದಿ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ಯದಿ ((ccp = getenv("SSH_ASKPASS")) == ರಿಕ್ತ || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	ಯದಿ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ಯದಿ (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	ಯದಿ (pledge("stdio rpath cpath wpath unix id proc exec", ರಿಕ್ತ) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	ಯಾವತ್ (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ಯದಿ (signalled_exit != 0) {
			logit("exiting on signal %d", (ಪೂರ್ಣಾಙ್ಕ)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		ಯದಿ (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (ಪೂರ್ಣಾಙ್ಕ)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, ರಿಕ್ತ);
		saved_errno = errno;
		ಯದಿ (parent_alive_interval != 0)
			check_parent_exists();
		(ಶೂನ್ಯ) reaper();	/* remove expired keys */
		ಯದಿ (result == -1) {
			ಯದಿ (saved_errno == EINTR)
				ಅನುವರ್ತ;
			fatal("poll: %s", strerror(saved_errno));
		} ಅನ್ಯಥಾ ಯದಿ (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
