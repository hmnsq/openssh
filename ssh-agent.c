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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಆದರೆ_ಅಂತ್ಯ

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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#ಆದರೆ_ಅಂತ್ಯ

/* Maximum accepted message length */
#ವ್ಯಾಖ್ಯಾನಿಸು AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#ವ್ಯಾಖ್ಯಾನಿಸು AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#ವ್ಯಾಖ್ಯಾನಿಸು AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#ವ್ಯಾಖ್ಯಾನಿಸು AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#ವ್ಯಾಖ್ಯಾನಿಸು AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#ವ್ಯಾಖ್ಯಾನಿಸು AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#ವ್ಯಾಖ್ಯಾನಿಸು AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ {
	AUTH_ಬಳಸದ = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

ರಚನೆ hostkey_sid {
	ರಚನೆ sshkey *ಕೀಲಿ;
	ರಚನೆ sshbuf *sid;
	ಪೂರ್ಣಾಂಕ forwarded;
};

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ socket_ನಮೂದು {
	ಪೂರ್ಣಾಂಕ fd;
	sock_type type;
	ರಚನೆ sshbuf *ಒಳಹರಿವು;
	ರಚನೆ sshbuf *output;
	ರಚನೆ sshbuf *request;
	ಗಾತ್ರ_t nsession_ids;
	ರಚನೆ hostkey_sid *session_ids;
	ಪೂರ್ಣಾಂಕ session_bind_attempted;
} Socket_ನಮೂದು;

u_int sockets_alloc = 0;
Socket_ನಮೂದು *sockets = ಖಾಲಿ;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ತಟಸ್ಥ_2 {
	TAILQ_ENTRY(ತಟಸ್ಥ_2) ಮುಂದಿನ;
	ರಚನೆ sshkey *ಕೀಲಿ;
	ಅಕ್ಷರ *comment;
	ಅಕ್ಷರ *provider;
	time_t death;
	u_int confirm;
	ಅಕ್ಷರ *sk_provider;
	ರಚನೆ dest_constraint *dest_constraints;
	ಗಾತ್ರ_t ndest_constraints;
} ತಟಸ್ಥ;

ರಚನೆ idtable {
	ಪೂರ್ಣಾಂಕ nentries;
	TAILQ_HEAD(idqueue, ತಟಸ್ಥ_2) idlist;
};

/* private key table */
ರಚನೆ idtable *idtab;

ಪೂರ್ಣಾಂಕ max_fd = 0;

/* pid of shell == parent of agent */
pid_t ಪೋಷಕ_pid = -1;
time_t ಪೋಷಕ_alive_interval = 0;

ಸ್ಥಿರ sig_atomic_t signalled_exit;
ಸ್ಥಿರ sig_atomic_t signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
ಸ್ಥಿರ ಅಕ್ಷರ *socket_name;
ಸ್ಥಿರ ಅಕ್ಷರ *socket_dir;
ಸ್ಥಿರ ಅಕ್ಷರ *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
ಸ್ಥಿರ ಅಕ್ಷರ *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ remote_ಕೂಡಿಸು_provider;

/* locking */
#ವ್ಯಾಖ್ಯಾನಿಸು ಬೀಗ_ಗಾತ್ರ	32
#ವ್ಯಾಖ್ಯಾನಿಸು ಬೀಗ_SALT_ಗಾತ್ರ	16
#ವ್ಯಾಖ್ಯಾನಿಸು ಬೀಗ_ಸುತ್ತುಗಳು	1
ಪೂರ್ಣಾಂಕ locked = 0;
u_char ಬೀಗ_pwhash[ಬೀಗ_ಗಾತ್ರ];
u_char ಬೀಗ_salt[ಬೀಗ_SALT_ಗಾತ್ರ];

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

/* Default lifetime in seconds (0 == forever) */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ lifetime = 0;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ restrict_websafe = 1;
ಸ್ಥಿರ ಅಕ್ಷರ *websafe_allowlist;

ಸ್ಥಿರ ಶೂನ್ಯ
close_socket(Socket_ನಮೂದು *e)
{
	ಗಾತ್ರ_t i;

	close(e->fd);
	sshbuf_free(e->ಒಳಹರಿವು);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	ಗಾಗಿ (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].ಕೀಲಿ);
		sshbuf_free(e->session_ids[i].sid);
	}
	ಬಿಡುಗಡೆ(e->session_ids);
	memset(e, '\0', ಗಾತ್ರ(*e));
	e->fd = -1;
	e->type = AUTH_ಬಳಸದ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
idtab_init(ಶೂನ್ಯ)
{
	idtab = xcalloc(1, ಗಾತ್ರ(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dest_constraint_hop(ರಚನೆ dest_constraint_hop *dch)
{
	u_int i;

	ಆದರೆ (dch == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಬಿಡುಗಡೆ(dch->user);
	ಬಿಡುಗಡೆ(dch->hostname);
	ಗಾಗಿ (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->ಕೀಲಿಗಳು[i]);
	ಬಿಡುಗಡೆ(dch->ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(dch->ಕೀಲಿ_is_ca);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_dest_constraints(ರಚನೆ dest_constraint *dcs, ಗಾತ್ರ_t ndcs)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].ಗಮ್ಯ);
	}
	ಬಿಡುಗಡೆ(dcs);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
ಸ್ಥಿರ ಶೂನ್ಯ
dup_dest_constraint_hop(ಸ್ಥಿರಾಂಕ ರಚನೆ dest_constraint_hop *dch,
    ರಚನೆ dest_constraint_hop *ಹೊರಹೋಗು)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ r;

	ಹೊರಹೋಗು->user = dch->user == ಖಾಲಿ ? ಖಾಲಿ : xstrdup(dch->user);
	ಹೊರಹೋಗು->hostname = dch->hostname == ಖಾಲಿ ? ಖಾಲಿ : xstrdup(dch->hostname);
	ಹೊರಹೋಗು->is_ca = dch->is_ca;
	ಹೊರಹೋಗು->nkeys = dch->nkeys;
	ಹೊರಹೋಗು->ಕೀಲಿಗಳು = ಹೊರಹೋಗು->nkeys == 0 ? ಖಾಲಿ :
	    xcalloc(ಹೊರಹೋಗು->nkeys, ಗಾತ್ರ(*ಹೊರಹೋಗು->ಕೀಲಿಗಳು));
	ಹೊರಹೋಗು->ಕೀಲಿ_is_ca = ಹೊರಹೋಗು->nkeys == 0 ? ಖಾಲಿ :
	    xcalloc(ಹೊರಹೋಗು->nkeys, ಗಾತ್ರ(*ಹೊರಹೋಗು->ಕೀಲಿ_is_ca));
	ಗಾಗಿ (i = 0; i < dch->nkeys; i++) {
		ಆದರೆ (dch->ಕೀಲಿಗಳು[i] != ಖಾಲಿ &&
		    (r = sshkey_from_ಖಾಸಗಿ(dch->ಕೀಲಿಗಳು[i],
		    &(ಹೊರಹೋಗು->ಕೀಲಿಗಳು[i]))) != 0)
			fatal_fr(r, "copy key");
		ಹೊರಹೋಗು->ಕೀಲಿ_is_ca[i] = dch->ಕೀಲಿ_is_ca[i];
	}
}

ಸ್ಥಿರ ರಚನೆ dest_constraint *
dup_dest_constraints(ಸ್ಥಿರಾಂಕ ರಚನೆ dest_constraint *dcs, ಗಾತ್ರ_t ndcs)
{
	ಗಾತ್ರ_t i;
	ರಚನೆ dest_constraint *ret;

	ಆದರೆ (ndcs == 0)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ret = xcalloc(ndcs, ಗಾತ್ರ(*ret));
	ಗಾಗಿ (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].ಗಮ್ಯ, &ret[i].ಗಮ್ಯ);
	}
	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_PKCS11 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_CONSTRAINTS
ಸ್ಥಿರ ಶೂನ್ಯ
dump_dest_constraint_hop(ಸ್ಥಿರಾಂಕ ರಚನೆ dest_constraint_hop *dch)
{
	u_int i;
	ಅಕ್ಷರ *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == ಖಾಲಿ ? "(null)" : dch->user,
	    dch->hostname == ಖಾಲಿ ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	ಗಾಗಿ (i = 0; i < dch->nkeys; i++) {
		fp = ಖಾಲಿ;
		ಆದರೆ (dch->ಕೀಲಿಗಳು[i] != ಖಾಲಿ &&
		    (fp = sshkey_fingerprint(dch->ಕೀಲಿಗಳು[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->ಕೀಲಿಗಳು[i] == ಖಾಲಿ ? "" : sshkey_ssh_name(dch->ಕೀಲಿಗಳು[i]),
		    dch->ಕೀಲಿಗಳು[i] == ಖಾಲಿ ? "" : " ",
		    dch->ಕೀಲಿಗಳು[i] == ಖಾಲಿ ? "none" : fp,
		    dch->ಕೀಲಿ_is_ca[i]);
		ಬಿಡುಗಡೆ(fp);
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* DEBUG_CONSTRAINTS */

ಸ್ಥಿರ ಶೂನ್ಯ
dump_dest_constraints(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *context,
    ಸ್ಥಿರಾಂಕ ರಚನೆ dest_constraint *dcs, ಗಾತ್ರ_t ndcs)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_CONSTRAINTS
	ಗಾತ್ರ_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	ಗಾಗಿ (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].ಗಮ್ಯ);
	}
	debug_f("done for %s", context);
#ಆದರೆ_ಅಂತ್ಯ /* DEBUG_CONSTRAINTS */
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_ತಟಸ್ಥ(ತಟಸ್ಥ *id)
{
	sshkey_free(id->ಕೀಲಿ);
	ಬಿಡುಗಡೆ(id->provider);
	ಬಿಡುಗಡೆ(id->comment);
	ಬಿಡುಗಡೆ(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	ಬಿಡುಗಡೆ(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_ಕೀಲಿ_hop(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಟ್ಯಾಗ್, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ dest_constraint_hop *dch)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	ಅಕ್ಷರ *fp;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	/* XXX logspam */
	ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    ಟ್ಯಾಗ್, hostname, sshkey_type(ಕೀಲಿ), fp, dch->nkeys);
	ಬಿಡುಗಡೆ(fp);
	ಗಾಗಿ (i = 0; i < dch->nkeys; i++) {
		ಆದರೆ (dch->ಕೀಲಿಗಳು[i] == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ -1;
		/* XXX logspam */
		ಆದರೆ ((fp = sshkey_fingerprint(dch->ಕೀಲಿಗಳು[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", ಟ್ಯಾಗ್, i,
		    dch->ಕೀಲಿ_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->ಕೀಲಿಗಳು[i]), fp);
		ಬಿಡುಗಡೆ(fp);
		ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
			/* plain key */
			ಆದರೆ (dch->ಕೀಲಿ_is_ca[i] ||
			    !sshkey_equal(ಕೀಲಿ, dch->ಕೀಲಿಗಳು[i]))
				ಮುಂದುವರಿ;
			ಹಿಂತಿರುಗಿ 0;
		}
		/* certificate */
		ಆದರೆ (!dch->ಕೀಲಿ_is_ca[i])
			ಮುಂದುವರಿ;
		ಆದರೆ (ಕೀಲಿ->cert == ಖಾಲಿ || ಕೀಲಿ->cert->signature_ಕೀಲಿ == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ -1; /* shouldn't happen */
		ಆದರೆ (!sshkey_equal(ಕೀಲಿ->cert->signature_ಕೀಲಿ, dch->ಕೀಲಿಗಳು[i]))
			ಮುಂದುವರಿ;
		ಆದರೆ (sshkey_cert_check_host(ಕೀಲಿ, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    ಕೀಲಿ->cert->ಕೀಲಿ_id, hostname, reason);
			ಮುಂದುವರಿ;
		}
		ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ -1;
}

/* Check destination constraints on an identity against the hostkey/user */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
permitted_by_dest_constraints(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *fromkey,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *tokey, ತಟಸ್ಥ *id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **hostnamep)
{
	ಗಾತ್ರ_t i;
	ರಚನೆ dest_constraint *d;

	ಆದರೆ (hostnamep != ಖಾಲಿ)
		*hostnamep = ಖಾಲಿ;
	ಗಾಗಿ (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->ಗಮ್ಯ.user ? d->ಗಮ್ಯ.user : "", d->ಗಮ್ಯ.user ? "@" : "",
		    d->ಗಮ್ಯ.hostname ? d->ಗಮ್ಯ.hostname : "(ANY)", d->ಗಮ್ಯ.nkeys);

		/* Match 'from' key */
		ಆದರೆ (fromkey == ಖಾಲಿ) {
			/* We are matching the first hop */
			ಆದರೆ (d->from.hostname != ಖಾಲಿ || d->from.nkeys != 0)
				ಮುಂದುವರಿ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಹೊಂದಿಕೆ_ಕೀಲಿ_hop("from", fromkey, &d->from) != 0)
			ಮುಂದುವರಿ;

		/* Match 'to' key */
		ಆದರೆ (tokey != ಖಾಲಿ && ಹೊಂದಿಕೆ_ಕೀಲಿ_hop("to", tokey, &d->ಗಮ್ಯ) != 0)
			ಮುಂದುವರಿ;

		/* Match user if specified */
		ಆದರೆ (d->ಗಮ್ಯ.user != ಖಾಲಿ && user != ಖಾಲಿ &&
		    !ಹೊಂದಿಕೆ_ನಮೂನೆ(user, d->ಗಮ್ಯ.user))
			ಮುಂದುವರಿ;

		/* successfully matched this constraint */
		ಆದರೆ (hostnamep != ಖಾಲಿ)
			*hostnamep = d->ಗಮ್ಯ.hostname;
		debug2_f("allowed for hostname %s",
		    d->ಗಮ್ಯ.hostname == ಖಾಲಿ ? "*" : d->ಗಮ್ಯ.hostname);
		ಹಿಂತಿರುಗಿ 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->ಕೀಲಿ), id->comment);
	ಹಿಂತಿರುಗಿ -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ತಟಸ್ಥ_permitted(ತಟಸ್ಥ *id, Socket_ನಮೂದು *e, ಅಕ್ಷರ *user,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **forward_hostnamep, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **ಕೊನೆಯ_hostnamep)
{
	ಗಾತ್ರ_t i;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **hp;
	ರಚನೆ hostkey_sid *hks;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *fromkey = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *test_user;
	ಅಕ್ಷರ *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->ಕೀಲಿ), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	ಆದರೆ (id->ndest_constraints == 0)
		ಹಿಂತಿರುಗಿ 0; /* unconstrained */
	ಆದರೆ (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (e->nsession_ids == 0)
		ಹಿಂತಿರುಗಿ 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	ಗಾಗಿ (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		ಆದರೆ (hks->ಕೀಲಿ == ಖಾಲಿ)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = ಖಾಲಿ;
		ಆದರೆ (fromkey != ಖಾಲಿ &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("fingerprint failed");
		ಆದರೆ ((fp2 = sshkey_fingerprint(hks->ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->ಕೀಲಿ), fp2);
		ಬಿಡುಗಡೆ(fp1);
		ಬಿಡುಗಡೆ(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = ಖಾಲಿ;
		ಆದರೆ (i == e->nsession_ids - 1)
			hp = ಕೊನೆಯ_hostnamep;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = ಖಾಲಿ;
		ಆದರೆ (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			ಆದರೆ (hks->forwarded && user != ಖಾಲಿ) {
				error_f("tried to sign on forwarding hop");
				ಹಿಂತಿರುಗಿ -1;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			ಹಿಂತಿರುಗಿ -1;
		}
		ಆದರೆ (permitted_by_dest_constraints(fromkey, hks->ಕೀಲಿ, id,
		    test_user, hp) != 0)
			ಹಿಂತಿರುಗಿ -1;
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
	ಆದರೆ (hks->forwarded && user == ಖಾಲಿ &&
	    permitted_by_dest_constraints(hks->ಕೀಲಿ, ಖಾಲಿ, id,
	    ಖಾಲಿ, ಖಾಲಿ) != 0) {
		debug3_f("key permitted at host but not after");
		ಹಿಂತಿರುಗಿ -1;
	}

	/* success */
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
socket_is_remote(Socket_ನಮೂದು *e)
{
	ಹಿಂತಿರುಗಿ e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
ಸ್ಥಿರ ತಟಸ್ಥ *
lookup_ತಟಸ್ಥ(ರಚನೆ sshkey *ಕೀಲಿ)
{
	ತಟಸ್ಥ *id;

	TAILQ_FOREACH(id, &idtab->idlist, ಮುಂದಿನ) {
		ಆದರೆ (sshkey_equal(ಕೀಲಿ, id->ಕೀಲಿ))
			ಹಿಂತಿರುಗಿ (id);
	}
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}

/* Check confirmation of keysign request */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
confirm_ಕೀಲಿ(ತಟಸ್ಥ *id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *extra)
{
	ಅಕ್ಷರ *p;
	ಪೂರ್ಣಾಂಕ ret = -1;

	p = sshkey_fingerprint(id->ಕೀಲಿ, fingerprint_hash, SSH_FP_DEFAULT);
	ಆದರೆ (p != ಖಾಲಿ &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == ಖಾಲಿ ? "" : "\n", extra == ಖಾಲಿ ? "" : extra))
		ret = 0;
	ಬಿಡುಗಡೆ(p);

	ಹಿಂತಿರುಗಿ (ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸ್ಥಿತಿ_generic(Socket_ನಮೂದು *e, u_int ಸಂಕೇತ_2)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, ಸಂಕೇತ_2)) != 0)
		fatal_fr(r, "compose");
}

ಸ್ಥಿರ ಶೂನ್ಯ
send_ಸ್ಥಿತಿ(Socket_ನಮೂದು *e, ಪೂರ್ಣಾಂಕ success)
{
	send_ಸ್ಥಿತಿ_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
ಸ್ಥಿರ ಶೂನ್ಯ
process_request_identities(Socket_ನಮೂದು *e)
{
	ತಟಸ್ಥ *id;
	ರಚನೆ sshbuf *ಸಂದೇಶ, *ಕೀಲಿಗಳು;
	ಪೂರ್ಣಾಂಕ r;
	u_int i = 0, nentries = 0;
	ಅಕ್ಷರ *fp;

	debug2_f("entering");

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ || (ಕೀಲಿಗಳು = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, ಮುಂದಿನ) {
		ಆದರೆ ((fp = sshkey_fingerprint(id->ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->ಕೀಲಿ), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		ಬಿಡುಗಡೆ(fp);
		/* identity not visible, don't include in response */
		ಆದರೆ (ತಟಸ್ಥ_permitted(id, e, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ) != 0)
			ಮುಂದುವರಿ;
		ಆದರೆ ((r = sshkey_puts(id->ಕೀಲಿ, ಕೀಲಿಗಳು)) != 0 ||
		    (r = sshbuf_put_cstring(ಕೀಲಿಗಳು, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			ಮುಂದುವರಿ;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, nentries)) != 0 ||
	    (r = sshbuf_putb(ಸಂದೇಶ, ಕೀಲಿಗಳು)) != 0)
		fatal_fr(r, "compose");
	ಆದರೆ ((r = sshbuf_put_stringb(e->output, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ಸಂದೇಶ);
	sshbuf_free(ಕೀಲಿಗಳು);
}


ಸ್ಥಿರ ಅಕ್ಷರ *
agent_decode_alg(ರಚನೆ sshkey *ಕೀಲಿ, u_int flags)
{
	ಆದರೆ (ಕೀಲಿ->type == ಕೀಲಿ_RSA) {
		ಆದರೆ (flags & SSH_AGENT_RSA_SHA2_256)
			ಹಿಂತಿರುಗಿ "rsa-sha2-256";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (flags & SSH_AGENT_RSA_SHA2_512)
			ಹಿಂತಿರುಗಿ "rsa-sha2-512";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಕೀಲಿ->type == ಕೀಲಿ_RSA_CERT) {
		ಆದರೆ (flags & SSH_AGENT_RSA_SHA2_256)
			ಹಿಂತಿರುಗಿ "rsa-sha2-256-cert-v01@openssh.com";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (flags & SSH_AGENT_RSA_SHA2_512)
			ಹಿಂತಿರುಗಿ "rsa-sha2-512-cert-v01@openssh.com";
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_userauth_request(ರಚನೆ sshbuf *ಸಂದೇಶ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *expected_ಕೀಲಿ,
    ಅಕ್ಷರ **userp, ರಚನೆ sshbuf **sess_idp, ರಚನೆ sshkey **hostkeyp)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ, *sess_id = ಖಾಲಿ;
	ಅಕ್ಷರ *user = ಖಾಲಿ, *service = ಖಾಲಿ, *ವಿಧಾನ = ಖಾಲಿ, *pkalg = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	u_char t, sig_follows;
	ರಚನೆ sshkey *mkey = ಖಾಲಿ, *hostkey = ಖಾಲಿ;

	ಆದರೆ (userp != ಖಾಲಿ)
		*userp = ಖಾಲಿ;
	ಆದರೆ (sess_idp != ಖಾಲಿ)
		*sess_idp = ಖಾಲಿ;
	ಆದರೆ (hostkeyp != ಖಾಲಿ)
		*hostkeyp = ಖಾಲಿ;
	ಆದರೆ ((b = sshbuf_fromb(ಸಂದೇಶ)) == ಖಾಲಿ)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	ಆದರೆ ((r = sshbuf_froms(b, &sess_id)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, ಖಾಲಿ)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, ಖಾಲಿ)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &ವಿಧಾನ, ಖಾಲಿ)) != 0 || /*ವಿಧಾನ*/
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, ಖಾಲಿ)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*ಕೀಲಿ*/
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (t != SSH2_ಸಂದೇಶ_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_ಕೀಲಿ, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_ಕೀಲಿ->type) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (strcmp(ವಿಧಾನ, "publickey-hostbound-v00@openssh.com") == 0) {
		ಆದರೆ ((r = sshkey_froms(b, &hostkey)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ವಿಧಾನ, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	ಆದರೆ (userp != ಖಾಲಿ) {
		*userp = user;
		user = ಖಾಲಿ;
	}
	ಆದರೆ (sess_idp != ಖಾಲಿ) {
		*sess_idp = sess_id;
		sess_id = ಖಾಲಿ;
	}
	ಆದರೆ (hostkeyp != ಖಾಲಿ) {
		*hostkeyp = hostkey;
		hostkey = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(service);
	ಬಿಡುಗಡೆ(ವಿಧಾನ);
	ಬಿಡುಗಡೆ(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_sshsig_request(ರಚನೆ sshbuf *ಸಂದೇಶ)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *b;

	ಆದರೆ ((b = sshbuf_fromb(ಸಂದೇಶ)) == ಖಾಲಿ)
		fatal_f("sshbuf_fromb");

	ಆದರೆ ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, ಖಾಲಿ, ಖಾಲಿ)) != 0 || /* namespace */
	    (r = sshbuf_get_string_ನೇರ(b, ಖಾಲಿ, ಖಾಲಿ)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, ಖಾಲಿ, ಖಾಲಿ)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_ನೇರ(b, ಖಾಲಿ, ಖಾಲಿ)) != 0) /* H(msg) */
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_websafe_ಸಂದೇಶ_contents(ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *ದತ್ತಾಂಶ)
{
	ಆದರೆ (parse_userauth_request(ದತ್ತಾಂಶ, ಕೀಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ) == 0) {
		debug_f("signed data matches public key userauth request");
		ಹಿಂತಿರುಗಿ 1;
	}
	ಆದರೆ (parse_sshsig_request(ದತ್ತಾಂಶ) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		ಹಿಂತಿರುಗಿ 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
buf_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b)
{
	ಆದರೆ (sshbuf_ptr(a) == ಖಾಲಿ || sshbuf_ptr(b) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (sshbuf_len(a) != sshbuf_len(b))
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಹಿಂತಿರುಗಿ 0;
}

/* ssh2 only */
ಸ್ಥಿರ ಶೂನ್ಯ
process_sign_request2(Socket_ನಮೂದು *e)
{
	u_char *signature = ಖಾಲಿ;
	ಗಾತ್ರ_t slen = 0;
	u_int compat = 0, flags;
	ಪೂರ್ಣಾಂಕ r, ok = -1, retried = 0;
	ಅಕ್ಷರ *fp = ಖಾಲಿ, *pin = ಖಾಲಿ, *prompt = ಖಾಲಿ;
	ಅಕ್ಷರ *user = ಖಾಲಿ, *sig_dest = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fwd_host = ಖಾಲಿ, *dest_host = ಖಾಲಿ;
	ರಚನೆ sshbuf *ಸಂದೇಶ = ಖಾಲಿ, *ದತ್ತಾಂಶ = ಖಾಲಿ, *sid = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ, *hostkey = ಖಾಲಿ;
	ರಚನೆ ತಟಸ್ಥ_2 *id;
	ರಚನೆ notifier_ctx *notifier = ಖಾಲಿ;

	debug_f("entering");

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ || (ದತ್ತಾಂಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_froms(e->request, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, ದತ್ತಾಂಶ)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		ಹೋಗು send;
	}

	ಆದರೆ ((id = lookup_ತಟಸ್ಥ(ಕೀಲಿ)) == ಖಾಲಿ) {
		verbose_f("%s key not found", sshkey_type(ಕೀಲಿ));
		ಹೋಗು send;
	}
	ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ)
		fatal_f("fingerprint failed");

	ಆದರೆ (id->ndest_constraints != 0) {
		ಆದರೆ (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			ಹೋಗು send;
		}
		ಆದರೆ (parse_userauth_request(ದತ್ತಾಂಶ, ಕೀಲಿ, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			ಹೋಗು send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		ಆದರೆ (ತಟಸ್ಥ_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			ಹೋಗು send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		ಆದರೆ (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->ಕೀಲಿ), fp);
			ಹೋಗು send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		ಆದರೆ (e->nsession_ids > 1 && hostkey == ಖಾಲಿ) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			ಹೋಗು send;
		}
		ಆದರೆ (hostkey != ಖಾಲಿ && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].ಕೀಲಿ)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			ಹೋಗು send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	ಆದರೆ (id->confirm && confirm_ಕೀಲಿ(id, sig_dest) != 0) {
		verbose_f("user refused key");
		ಹೋಗು send;
	}
	ಆದರೆ (sshkey_is_sk(id->ಕೀಲಿ)) {
		ಆದರೆ (restrict_websafe &&
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(id->ಕೀಲಿ->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_ಸಂದೇಶ_contents(ಕೀಲಿ, ದತ್ತಾಂಶ)) {
			/* error already logged */
			ಹೋಗು send;
		}
		ಆದರೆ (id->ಕೀಲಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_ಆರಂಭ(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->ಕೀಲಿ), fp,
			    sig_dest == ಖಾಲಿ ? "" : "\n",
			    sig_dest == ಖಾಲಿ ? "" : sig_dest);
		}
	}
 retry_pin:
	ಆದರೆ ((r = sshkey_sign(id->ಕೀಲಿ, &signature, &slen,
	    sshbuf_ptr(ದತ್ತಾಂಶ), sshbuf_len(ದತ್ತಾಂಶ), agent_decode_alg(ಕೀಲಿ, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ಆದರೆ (pin == ಖಾಲಿ && !retried && sshkey_is_sk(id->ಕೀಲಿ) &&
		    r == SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
			notify_complete(notifier, ಖಾಲಿ);
			notifier = ಖಾಲಿ;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->ಕೀಲಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->ಕೀಲಿ), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			ಹೋಗು retry_pin;
		}
		error_fr(r, "sshkey_sign");
		ಹೋಗು send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	ಆದರೆ (ok == 0) {
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(ಸಂದೇಶ, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	ಆದರೆ ((r = sshbuf_put_stringb(e->output, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(ದತ್ತಾಂಶ);
	sshbuf_free(ಸಂದೇಶ);
	sshkey_free(ಕೀಲಿ);
	sshkey_free(hostkey);
	ಬಿಡುಗಡೆ(fp);
	ಬಿಡುಗಡೆ(signature);
	ಬಿಡುಗಡೆ(sig_dest);
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(prompt);
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));
}

/* shared */
ಸ್ಥಿರ ಶೂನ್ಯ
process_remove_ತಟಸ್ಥ(Socket_ನಮೂದು *e)
{
	ಪೂರ್ಣಾಂಕ r, success = 0;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ತಟಸ್ಥ *id;

	debug2_f("entering");
	ಆದರೆ ((r = sshkey_froms(e->request, &ಕೀಲಿ)) != 0) {
		error_fr(r, "parse key");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((id = lookup_ತಟಸ್ಥ(ಕೀಲಿ)) == ಖಾಲಿ) {
		debug_f("key not found");
		ಹೋಗು ಮುಗಿದ;
	}
	/* identity not visible, cannot be removed */
	ಆದರೆ (ತಟಸ್ಥ_permitted(id, e, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ) != 0)
		ಹೋಗು ಮುಗಿದ; /* error already logged */
	/* We have this key, free it. */
	ಆದರೆ (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, ಮುಂದಿನ);
	free_ತಟಸ್ಥ(id);
	idtab->nentries--;
	success = 1;
 ಮುಗಿದ:
	sshkey_free(ಕೀಲಿ);
	send_ಸ್ಥಿತಿ(e, success);
}

ಸ್ಥಿರ ಶೂನ್ಯ
remove_all_identities(ಶೂನ್ಯ)
{
	ತಟಸ್ಥ *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	ಗಾಗಿ (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, ಮುಂದಿನ);
		free_ತಟಸ್ಥ(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_remove_all_identities(Socket_ನಮೂದು *e)
{
	remove_all_identities();

	/* Send success. */
	send_ಸ್ಥಿತಿ(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
ಸ್ಥಿರ time_t
reaper(ಶೂನ್ಯ)
{
	time_t deadline = 0, now = monotime();
	ತಟಸ್ಥ *id, *nxt;

	ಗಾಗಿ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, ಮುಂದಿನ);
		ಆದರೆ (id->death == 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, ಮುಂದಿನ);
			free_ತಟಸ್ಥ(id);
			idtab->nentries--;
		} ಇಲ್ಲದಿದ್ದರೆ
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	ಆದರೆ (deadline == 0 || deadline <= now)
		ಹಿಂತಿರುಗಿ 0;
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ (deadline - now);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_dest_constraint_hop(ರಚನೆ sshbuf *b, ರಚನೆ dest_constraint_hop *dch)
{
	u_char ಕೀಲಿ_is_ca;
	ಗಾತ್ರ_t elen = 0, userlen = 0;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಅಕ್ಷರ *fp;

	memset(dch, '\0', ಗಾತ್ರ(*dch));
	ಆದರೆ ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(b, ಖಾಲಿ, &elen)) != 0) {
		error_fr(r, "parse");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (*dch->hostname == '\0') {
		ಬಿಡುಗಡೆ(dch->hostname);
		dch->hostname = ಖಾಲಿ;
	}
	ಆದರೆ (*dch->user == '\0') {
		ಬಿಡುಗಡೆ(dch->user);
		dch->user = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆಗ (sshbuf_len(b) != 0) {
		dch->ಕೀಲಿಗಳು = xrecallocarray(dch->ಕೀಲಿಗಳು, dch->nkeys,
		    dch->nkeys + 1, ಗಾತ್ರ(*dch->ಕೀಲಿಗಳು));
		dch->ಕೀಲಿ_is_ca = xrecallocarray(dch->ಕೀಲಿ_is_ca, dch->nkeys,
		    dch->nkeys + 1, ಗಾತ್ರ(*dch->ಕೀಲಿ_is_ca));
		ಆದರೆ ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &ಕೀಲಿ_is_ca)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == ಖಾಲಿ ? "" : dch->user,
		    dch->user == ಖಾಲಿ ? "" : "@",
		    dch->hostname, ಕೀಲಿ_is_ca ? "CA " : "", sshkey_type(k), fp);
		ಬಿಡುಗಡೆ(fp);
		dch->ಕೀಲಿಗಳು[dch->nkeys] = k;
		dch->ಕೀಲಿ_is_ca[dch->nkeys] = ಕೀಲಿ_is_ca != 0;
		dch->nkeys++;
		k = ಖಾಲಿ; /* transferred */
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshkey_free(k);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_dest_constraint(ರಚನೆ sshbuf *m, ರಚನೆ dest_constraint *dc)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ, *frombuf = ಖಾಲಿ, *tobuf = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', ಗಾತ್ರ(*dc));
	ಆದರೆ ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(b, ಖಾಲಿ, &elen)) != 0) {
		error_fr(r, "parse");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->ಗಮ್ಯ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು; /* already logged */
	ಆದರೆ (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->ಗಮ್ಯ.user ? dc->ಗಮ್ಯ.user : "", dc->ಗಮ್ಯ.user ? "@" : "",
	    dc->ಗಮ್ಯ.hostname ? dc->ಗಮ್ಯ.hostname : "(ANY)", dc->ಗಮ್ಯ.nkeys);
	/* check consistency */
	ಆದರೆ ((dc->from.hostname == ಖಾಲಿ) != (dc->from.nkeys == 0) ||
	    dc->from.user != ಖಾಲಿ) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (dc->ಗಮ್ಯ.hostname == ಖಾಲಿ || dc->ಗಮ್ಯ.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_ಕೀಲಿ_constraint_extension(ರಚನೆ sshbuf *m, ಅಕ್ಷರ **sk_providerp,
    ರಚನೆ dest_constraint **dcsp, ಗಾತ್ರ_t *ndcsp, ಪೂರ್ಣಾಂಕ *cert_onlyp,
    ರಚನೆ sshkey ***certs, ಗಾತ್ರ_t *ncerts)
{
	ಅಕ್ಷರ *ext_name = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	u_char v;
	ರಚನೆ sshkey *k;

	ಆದರೆ ((r = sshbuf_get_cstring(m, &ext_name, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse constraint extension");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug_f("constraint ext %s", ext_name);
	ಆದರೆ (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		ಆದರೆ (sk_providerp == ಖಾಲಿ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*sk_providerp != ಖಾಲಿ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_get_cstring(m, sk_providerp, ಖಾಲಿ)) != 0) {
			error_fr(r, "parse %s", ext_name);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		ಆದರೆ (*dcsp != ಖಾಲಿ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆಗ (sshbuf_len(b) != 0) {
			ಆದರೆ (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    ಗಾತ್ರ(**dcsp));
			ಆದರೆ ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		ಆದರೆ (certs == ಖಾಲಿ || ncerts == ಖಾಲಿ || cert_onlyp == ಖಾಲಿ) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*certs != ಖಾಲಿ) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		*cert_onlyp = v != 0;
		ಆಗ (sshbuf_len(b) != 0) {
			ಆದರೆ (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    ಗಾತ್ರ(**certs));
			ಆದರೆ ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				ಹೋಗು ಹೊರಹೋಗು;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ext_name);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_ಕೀಲಿ_constraints(ರಚನೆ sshbuf *m, ರಚನೆ sshkey *k, time_t *deathp,
    u_int *secondsp, ಪೂರ್ಣಾಂಕ *confirmp, ಅಕ್ಷರ **sk_providerp,
    ರಚನೆ dest_constraint **dcsp, ಗಾತ್ರ_t *ndcsp,
    ಪೂರ್ಣಾಂಕ *cert_onlyp, ಗಾತ್ರ_t *ncerts, ರಚನೆ sshkey ***certs)
{
	u_char ctype;
	ಪೂರ್ಣಾಂಕ r;
	u_int seconds;

	ಆಗ (sshbuf_len(m)) {
		ಆದರೆ ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆಯ್ಕೆ (ctype) {
		ಸ್ಥಿತಿ SSH_AGENT_CONSTRAIN_LIFETIME:
			ಆದರೆ (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				ಹೋಗು ಹೊರಹೋಗು;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH_AGENT_CONSTRAIN_CONFIRM:
			ಆದರೆ (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			*confirmp = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH_AGENT_CONSTRAIN_EXTENSION:
			ಆದರೆ ((r = parse_ಕೀಲಿ_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_ಕೂಡಿಸು_ತಟಸ್ಥ(Socket_ನಮೂದು *e)
{
	ತಟಸ್ಥ *id;
	ಪೂರ್ಣಾಂಕ success = 0, confirm = 0;
	ಅಕ್ಷರ *fp, *comment = ಖಾಲಿ, *sk_provider = ಖಾಲಿ;
	ಅಕ್ಷರ canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	ರಚನೆ dest_constraint *dest_constraints = ಖಾಲಿ;
	ಗಾತ್ರ_t ndest_constraints = 0;
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	debug2_f("entering");
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_deserialize(e->request, &k)) != 0 ||
	    k == ಖಾಲಿ ||
	    (r = sshbuf_get_cstring(e->request, &comment, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (parse_ಕೀಲಿ_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	ಆದರೆ (sk_provider != ಖಾಲಿ) {
		ಆದರೆ (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (socket_is_remote(e) && !remote_ಕೂಡಿಸು_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (realpath(sk_provider, canonical_provider) == ಖಾಲಿ) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಬಿಡುಗಡೆ(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
	}
	ಆದರೆ ((r = sshkey_shield_ಖಾಸಗಿ(k)) != 0) {
		error_fr(r, "shield private");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (lifetime && !death)
		death = monotime() + lifetime;
	ಆದರೆ ((id = lookup_ತಟಸ್ಥ(k)) == ಖಾಲಿ) {
		id = xcalloc(1, ಗಾತ್ರ(ತಟಸ್ಥ));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, ಮುಂದಿನ);
		/* Increment the number of identities. */
		idtab->nentries++;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* identity not visible, do not update */
		ಆದರೆ (ತಟಸ್ಥ_permitted(id, e, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ) != 0)
			ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->ಕೀಲಿ);
		ಬಿಡುಗಡೆ(id->comment);
		ಬಿಡುಗಡೆ(id->sk_provider);
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

	ಆದರೆ ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == ಖಾಲಿ ? "none" : sk_provider, ndest_constraints);
	ಬಿಡುಗಡೆ(fp);
	/* transferred */
	k = ಖಾಲಿ;
	comment = ಖಾಲಿ;
	sk_provider = ಖಾಲಿ;
	dest_constraints = ಖಾಲಿ;
	ndest_constraints = 0;
	success = 1;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(sk_provider);
	ಬಿಡುಗಡೆ(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_ಸ್ಥಿತಿ(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
ಸ್ಥಿರ ಶೂನ್ಯ
process_ಬೀಗ_agent(Socket_ನಮೂದು *e, ಪೂರ್ಣಾಂಕ ಬೀಗ)
{
	ಪೂರ್ಣಾಂಕ r, success = 0, delay;
	ಅಕ್ಷರ *passwd;
	u_char passwdhash[ಬೀಗ_ಗಾತ್ರ];
	ಸ್ಥಿರ u_int fail_ಎಣಿಕೆ = 0;
	ಗಾತ್ರ_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	ಆದರೆ ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (pwlen == 0) {
		debug("empty password not supported");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (locked && !ಬೀಗ) {
		ಆದರೆ (bcrypt_pbkdf(passwd, pwlen, ಬೀಗ_salt, ಗಾತ್ರ(ಬೀಗ_salt),
		    passwdhash, ಗಾತ್ರ(passwdhash), ಬೀಗ_ಸುತ್ತುಗಳು) < 0)
			fatal("bcrypt_pbkdf");
		ಆದರೆ (timingsafe_bcmp(passwdhash, ಬೀಗ_pwhash, ಬೀಗ_ಗಾತ್ರ) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_ಎಣಿಕೆ = 0;
			explicit_bzero(ಬೀಗ_pwhash, ಗಾತ್ರ(ಬೀಗ_pwhash));
			success = 1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* delay in 0.1s increments up to 10s */
			ಆದರೆ (fail_ಎಣಿಕೆ < 100)
				fail_ಎಣಿಕೆ++;
			delay = 100000 * fail_ಎಣಿಕೆ;
			debug("unlock failed, delaying %0.1lf seconds",
			    (ದ್ವಿಗುಣ)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, ಗಾತ್ರ(passwdhash));
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!locked && ಬೀಗ) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(ಬೀಗ_salt, ಗಾತ್ರ(ಬೀಗ_salt));
		ಆದರೆ (bcrypt_pbkdf(passwd, pwlen, ಬೀಗ_salt, ಗಾತ್ರ(ಬೀಗ_salt),
		    ಬೀಗ_pwhash, ಗಾತ್ರ(ಬೀಗ_pwhash), ಬೀಗ_ಸುತ್ತುಗಳು) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_ಸ್ಥಿತಿ(e, success);
}

ಸ್ಥಿರ ಶೂನ್ಯ
no_identities(Socket_ನಮೂದು *e)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(ಸಂದೇಶ);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
ಸ್ಥಿರ ಶೂನ್ಯ
ಕೂಡಿಸು_p11_ತಟಸ್ಥ(ರಚನೆ sshkey *ಕೀಲಿ, ಅಕ್ಷರ *comment, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider,
    time_t death, u_int confirm, ರಚನೆ dest_constraint *dest_constraints,
    ಗಾತ್ರ_t ndest_constraints)
{
	ತಟಸ್ಥ *id;

	ಆದರೆ (lookup_ತಟಸ್ಥ(ಕೀಲಿ) != ಖಾಲಿ) {
		sshkey_free(ಕೀಲಿ);
		ಬಿಡುಗಡೆ(comment);
		ಹಿಂತಿರುಗಿ;
	}
	id = xcalloc(1, ಗಾತ್ರ(ತಟಸ್ಥ));
	id->ಕೀಲಿ = ಕೀಲಿ;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, ಮುಂದಿನ);
	idtab->nentries++;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_ಕೂಡಿಸು_smartcard_ಕೀಲಿ(Socket_ನಮೂದು *e)
{
	ಅಕ್ಷರ *provider = ಖಾಲಿ, *pin = ಖಾಲಿ, canonical_provider[PATH_MAX];
	ಅಕ್ಷರ **comments = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, i, ಎಣಿಕೆ_2 = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	ರಚನೆ sshkey **ಕೀಲಿಗಳು = ಖಾಲಿ, *k;
	ರಚನೆ dest_constraint *dest_constraints = ಖಾಲಿ;
	ಗಾತ್ರ_t j, ndest_constraints = 0, ncerts = 0;
	ರಚನೆ sshkey **certs = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ cert_only = 0;

	debug2_f("entering");
	ಆದರೆ ((r = sshbuf_get_cstring(e->request, &provider, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse");
		ಹೋಗು send;
	}
	ಆದರೆ (parse_ಕೀಲಿ_constraints(e->request, ಖಾಲಿ, &death, &seconds, &confirm,
	    ಖಾಲಿ, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		ಹೋಗು send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	ಆದರೆ (socket_is_remote(e) && !remote_ಕೂಡಿಸು_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		ಹೋಗು send;
	}
	ಆದರೆ (realpath(provider, canonical_provider) == ಖಾಲಿ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		ಹೋಗು send;
	}
	ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		ಹೋಗು send;
	}
	debug_f("add %.100s", canonical_provider);
	ಆದರೆ (lifetime && !death)
		death = monotime() + lifetime;

	ಎಣಿಕೆ_2 = pkcs11_ಕೂಡಿಸು_provider(canonical_provider, pin, &ಕೀಲಿಗಳು, &comments);
	ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++) {
		ಆದರೆ (comments[i] == ಖಾಲಿ || comments[i][0] == '\0') {
			ಬಿಡುಗಡೆ(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		ಗಾಗಿ (j = 0; j < ncerts; j++) {
			ಆದರೆ (!sshkey_is_cert(certs[j]))
				ಮುಂದುವರಿ;
			ಆದರೆ (!sshkey_equal_ಬಹಿರಂಗ(ಕೀಲಿಗಳು[i], certs[j]))
				ಮುಂದುವರಿ;
			ಆದರೆ (pkcs11_make_cert(ಕೀಲಿಗಳು[i], certs[j], &k) != 0)
				ಮುಂದುವರಿ;
			ಕೂಡಿಸು_p11_ತಟಸ್ಥ(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		ಆದರೆ (!cert_only && lookup_ತಟಸ್ಥ(ಕೀಲಿಗಳು[i]) == ಖಾಲಿ) {
			ಕೂಡಿಸು_p11_ತಟಸ್ಥ(ಕೀಲಿಗಳು[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			ಕೀಲಿಗಳು[i] = ಖಾಲಿ;		/* transferred */
			comments[i] = ಖಾಲಿ;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(ಕೀಲಿಗಳು[i]);
		ಬಿಡುಗಡೆ(comments[i]);
	}
send:
	ಬಿಡುಗಡೆ(pin);
	ಬಿಡುಗಡೆ(provider);
	ಬಿಡುಗಡೆ(ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	ಗಾಗಿ (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	ಬಿಡುಗಡೆ(certs);
	send_ಸ್ಥಿತಿ(e, success);
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_remove_smartcard_ಕೀಲಿ(Socket_ನಮೂದು *e)
{
	ಅಕ್ಷರ *provider = ಖಾಲಿ, *pin = ಖಾಲಿ, canonical_provider[PATH_MAX];
	ಪೂರ್ಣಾಂಕ r, success = 0;
	ತಟಸ್ಥ *id, *nxt;

	debug2_f("entering");
	ಆದರೆ ((r = sshbuf_get_cstring(e->request, &provider, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse");
		ಹೋಗು send;
	}
	ಬಿಡುಗಡೆ(pin);

	ಆದರೆ (realpath(provider, canonical_provider) == ಖಾಲಿ) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		ಹೋಗು send;
	}

	debug_f("remove %.100s", canonical_provider);
	ಗಾಗಿ (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, ಮುಂದಿನ);
		/* Skip file--based keys */
		ಆದರೆ (id->provider == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, ಮುಂದಿನ);
			free_ತಟಸ್ಥ(id);
			idtab->nentries--;
		}
	}
	ಆದರೆ (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	ಇಲ್ಲದಿದ್ದರೆ
		error_f("pkcs11_del_provider failed");
send:
	ಬಿಡುಗಡೆ(provider);
	send_ಸ್ಥಿತಿ(e, success);
}
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_PKCS11 */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_ext_session_bind(Socket_ನಮೂದು *e)
{
	ಪೂರ್ಣಾಂಕ r, sid_ಹೊಂದಿಕೆ, ಕೀಲಿ_ಹೊಂದಿಕೆ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *sid = ಖಾಲಿ, *sig = ಖಾಲಿ;
	ಅಕ್ಷರ *fp = ಖಾಲಿ;
	ಗಾತ್ರ_t i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	ಆದರೆ ((r = sshkey_froms(e->request, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	ಆದರೆ ((r = sshkey_verify(ಕೀಲಿ, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), ಖಾಲಿ, 0, ಖಾಲಿ)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(ಕೀಲಿ), fp);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* check whether sid/key already recorded */
	ಗಾಗಿ (i = 0; i < e->nsession_ids; i++) {
		ಆದರೆ (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		sid_ಹೊಂದಿಕೆ = buf_equal(sid, e->session_ids[i].sid) == 0;
		ಕೀಲಿ_ಹೊಂದಿಕೆ = sshkey_equal(ಕೀಲಿ, e->session_ids[i].ಕೀಲಿ);
		ಆದರೆ (sid_ಹೊಂದಿಕೆ && ಕೀಲಿ_ಹೊಂದಿಕೆ) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(ಕೀಲಿ), fp);
			r = 0;
			ಹೋಗು ಹೊರಹೋಗು;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sid_ಹೊಂದಿಕೆ) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(ಕೀಲಿ), fp);
			r = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	ಆದರೆ (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, ಗಾತ್ರ(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(ಕೀಲಿ), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].ಕೀಲಿ = ಕೀಲಿ;
	e->session_ids[i].forwarded = fwd != 0;
	ಕೀಲಿ = ಖಾಲಿ; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	ಆದರೆ ((e->session_ids[i].sid = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(fp);
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(sid);
	sshbuf_free(sig);
	ಹಿಂತಿರುಗಿ r == 0 ? 1 : 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_ext_query(Socket_ನಮೂದು *e)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *ಸಂದೇಶ = ಖಾಲಿ;

	debug2_f("entering");
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	ಆದರೆ ((r = sshbuf_put_stringb(e->output, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
process_extension(Socket_ನಮೂದು *e)
{
	ಪೂರ್ಣಾಂಕ r, replied = 0, success = 0;
	ಅಕ್ಷರ *name;

	debug2_f("entering");
	ಆದರೆ ((r = sshbuf_get_cstring(e->request, &name, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse");
		send_ಸ್ಥಿತಿ(e, 0);
		ಹಿಂತಿರುಗಿ;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	ಆದರೆ (strcmp(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		ಹೋಗು generic_fail;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		ಬಿಡುಗಡೆ(name);
		send_ಸ್ಥಿತಿ(e, 0);
		ಹಿಂತಿರುಗಿ;
	}
	ಬಿಡುಗಡೆ(name);
	/* Agent failures are signalled with a different error code */
	ಆದರೆ (!replied) {
		send_ಸ್ಥಿತಿ_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_ಸಂದೇಶ(u_int socknum)
{
	u_int ಸಂದೇಶ_len;
	u_char type;
	ಸ್ಥಿರಾಂಕ u_char *cp;
	ಪೂರ್ಣಾಂಕ r;
	Socket_ನಮೂದು *e;

	ಆದರೆ (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	ಆದರೆ (sshbuf_len(e->ಒಳಹರಿವು) < 5)
		ಹಿಂತಿರುಗಿ 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->ಒಳಹರಿವು);
	ಸಂದೇಶ_len = PEEK_U32(cp);
	ಆದರೆ (ಸಂದೇಶ_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, ಸಂದೇಶ_len, AGENT_MAX_LEN);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (sshbuf_len(e->ಒಳಹರಿವು) < ಸಂದೇಶ_len + 4)
		ಹಿಂತಿರುಗಿ 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	ಆದರೆ ((r = sshbuf_get_stringb(e->ಒಳಹರಿವು, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		ಆದರೆ (r == SSH_ERR_ಸಂದೇಶ_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			ಹಿಂತಿರುಗಿ -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	ಆದರೆ (locked && type != SSH_AGENTC_UNLOCK) {
		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH_AGENTC_EXTENSION:
			process_extension(e);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			/* send a fail message for all other request types */
			send_ಸ್ಥಿತಿ(e, 0);
		}
		sshbuf_reset(e->request);
		ಹಿಂತಿರುಗಿ 1;
	}

	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ SSH_AGENTC_ಬೀಗ:
	ಸ್ಥಿತಿ SSH_AGENTC_UNLOCK:
		process_ಬೀಗ_agent(e, type == SSH_AGENTC_ಬೀಗ);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		ನಿಲ್ಲಿಸು;
	/* ssh2 */
	ಸ್ಥಿತಿ SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_AGENTC_ಕೂಡಿಸು_ತಟಸ್ಥ:
	ಸ್ಥಿತಿ SSH2_AGENTC_ಕೂಡಿಸು_ID_CONSTRAINED:
		process_ಕೂಡಿಸು_ತಟಸ್ಥ(e);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_AGENTC_REMOVE_ತಟಸ್ಥ:
		process_remove_ತಟಸ್ಥ(e);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		ನಿಲ್ಲಿಸು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	ಸ್ಥಿತಿ SSH_AGENTC_ಕೂಡಿಸು_SMARTCARD_ಕೀಲಿ:
	ಸ್ಥಿತಿ SSH_AGENTC_ಕೂಡಿಸು_SMARTCARD_ಕೀಲಿ_CONSTRAINED:
		process_ಕೂಡಿಸು_smartcard_ಕೀಲಿ(e);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_AGENTC_REMOVE_SMARTCARD_ಕೀಲಿ:
		process_remove_smartcard_ಕೀಲಿ(e);
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_PKCS11 */
	ಸ್ಥಿತಿ SSH_AGENTC_EXTENSION:
		process_extension(e);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_ಸ್ಥಿತಿ(e, 0);
		ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
new_socket(sock_type type, ಪೂರ್ಣಾಂಕ fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	ಗಣ_nonblock(fd);

	ಆದರೆ (fd > max_fd)
		max_fd = fd;

	ಗಾಗಿ (i = 0; i < sockets_alloc; i++)
		ಆದರೆ (sockets[i].type == AUTH_ಬಳಸದ) {
			sockets[i].fd = fd;
			ಆದರೆ ((sockets[i].ಒಳಹರಿವು = sshbuf_new()) == ಖಾಲಿ ||
			    (sockets[i].output = sshbuf_new()) == ಖಾಲಿ ||
			    (sockets[i].request = sshbuf_new()) == ಖಾಲಿ)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			ಹಿಂತಿರುಗಿ;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    ಗಾತ್ರ(sockets[0]));
	ಗಾಗಿ (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_ಬಳಸದ;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	ಆದರೆ ((sockets[old_alloc].ಒಳಹರಿವು = sshbuf_new()) == ಖಾಲಿ ||
	    (sockets[old_alloc].output = sshbuf_new()) == ಖಾಲಿ ||
	    (sockets[old_alloc].request = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_socket_read(u_int socknum)
{
	ರಚನೆ sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	ಪೂರ್ಣಾಂಕ fd;

	slen = ಗಾತ್ರ(sunaddr);
	fd = accept(sockets[socknum].fd, (ರಚನೆ sockaddr *)&sunaddr, &slen);
	ಆದರೆ (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		ಹಿಂತಿರುಗಿ -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_conn_read(u_int socknum)
{
	ಅಕ್ಷರ buf[AGENT_RBUF_LEN];
	ssize_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((len = ಪಠ(sockets[socknum].fd, buf, ಗಾತ್ರ(buf))) <= 0) {
		ಆದರೆ (len == -1) {
			ಆದರೆ (errno == EAGAIN || errno == EINTR)
				ಹಿಂತಿರುಗಿ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((r = sshbuf_put(sockets[socknum].ಒಳಹರಿವು, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, ಗಾತ್ರ(buf));
	ಗಾಗಿ (;;) {
		ಆದರೆ ((r = process_ಸಂದೇಶ(socknum)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == 0)
			ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
handle_conn_write(u_int socknum)
{
	ssize_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (sshbuf_len(sockets[socknum].output) == 0)
		ಹಿಂತಿರುಗಿ 0; /* shouldn't happen */
	ಆದರೆ ((len = ಲಿಖ(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		ಆದರೆ (len == -1) {
			ಆದರೆ (errno == EAGAIN || errno == EINTR)
				ಹಿಂತಿರುಗಿ 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
after_poll(ರಚನೆ pollfd *pfd, ಗಾತ್ರ_t npfd, u_int maxfds)
{
	ಗಾತ್ರ_t i;
	u_int socknum, activefds = npfd;

	ಗಾಗಿ (i = 0; i < npfd; i++) {
		ಆದರೆ (pfd[i].revents == 0)
			ಮುಂದುವರಿ;
		/* Find sockets entry */
		ಗಾಗಿ (socknum = 0; socknum < sockets_alloc; socknum++) {
			ಆದರೆ (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				ಮುಂದುವರಿ;
			ಆದರೆ (pfd[i].fd == sockets[socknum].fd)
				ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			ಮುಂದುವರಿ;
		}
		/* Process events */
		ಆಯ್ಕೆ (sockets[socknum].type) {
		ಸ್ಥಿತಿ AUTH_SOCKET:
			ಆದರೆ ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (handle_socket_read(socknum) == 0)
				activefds++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AUTH_CONNECTION:
			ಆದರೆ ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				ಹೋಗು close_sock;
			ಆದರೆ ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				ಆದರೆ (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				ನಿಲ್ಲಿಸು;
			}
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ನಿಲ್ಲಿಸು;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
prepare_poll(ರಚನೆ pollfd **pfdp, ಗಾತ್ರ_t *npfdp, ರಚನೆ timespec *timeoutp, u_int maxfds)
{
	ರಚನೆ pollfd *pfd = *pfdp;
	ಗಾತ್ರ_t i, j, npfd = 0;
	time_t deadline;
	ಪೂರ್ಣಾಂಕ r;

	/* Count active sockets */
	ಗಾಗಿ (i = 0; i < sockets_alloc; i++) {
		ಆಯ್ಕೆ (sockets[i].type) {
		ಸ್ಥಿತಿ AUTH_SOCKET:
		ಸ್ಥಿತಿ AUTH_CONNECTION:
			npfd++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AUTH_ಬಳಸದ:
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("Unknown socket type %d", sockets[i].type);
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, ಗಾತ್ರ(*pfd))) == ಖಾಲಿ)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	ಗಾಗಿ (i = j = 0; i < sockets_alloc; i++) {
		ಆಯ್ಕೆ (sockets[i].type) {
		ಸ್ಥಿತಿ AUTH_SOCKET:
			ಆದರೆ (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				ನಿಲ್ಲಿಸು;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			ಆದರೆ ((r = sshbuf_check_reserve(sockets[i].ಒಳಹರಿವು,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != SSH_ERR_NO_ಬಫರ್_SPACE)
				fatal_fr(r, "reserve");
			ಆದರೆ (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ನಿಲ್ಲಿಸು;
		}
	}
	deadline = reaper();
	ಆದರೆ (ಪೋಷಕ_alive_interval != 0)
		deadline = (deadline == 0) ? ಪೋಷಕ_alive_interval :
		    MINIMUM(deadline, ಪೋಷಕ_alive_interval);
	ಆದರೆ (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	ಹಿಂತಿರುಗಿ (1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_socket(ಶೂನ್ಯ)
{
	ಆದರೆ (cleanup_pid != 0 && getpid() != cleanup_pid)
		ಹಿಂತಿರುಗಿ;
	debug_f("cleanup");
	ಆದರೆ (socket_name != ಖಾಲಿ) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		ಬಿಡುಗಡೆ(socket_name);
		socket_name = ಖಾಲಿ;
		ಬಿಡುಗಡೆ(socket_dir);
		socket_dir = ಖಾಲಿ;
	}
}

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ i)
{
	cleanup_socket();
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	pkcs11_terminate();
#ಆದರೆ_ಅಂತ್ಯ
	_exit(i);
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_handler(ಪೂರ್ಣಾಂಕ sig)
{
	signalled_exit = sig;
}

ಸ್ಥಿರ ಶೂನ್ಯ
keydrop_handler(ಪೂರ್ಣಾಂಕ sig)
{
	signalled_keydrop = sig;
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_ಪೋಷಕ_exists(ಶೂನ್ಯ)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	ಆದರೆ (ಪೋಷಕ_pid != -1 && getppid() != ಪೋಷಕ_pid) {
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
	ನಿರ್ಗಮಿಸು(1);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ ac, ಅಕ್ಷರ **av)
{
	ಪೂರ್ಣಾಂಕ c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	ಪೂರ್ಣಾಂಕ s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	ಪೂರ್ಣಾಂಕ sock = -1, ch, ಫಲಿತಾಂಶ, saved_errno;
	pid_t pid;
 	ಅಕ್ಷರ *homedir = ಖಾಲಿ, *shell, *format, *pidstr, *agentsocket = ಖಾಲಿ;
	ಅಕ್ಷರ *cp, pidstrbuf[1 + 3 * ಗಾತ್ರ pid];
	ಅಕ್ಷರ *fdstr;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ccp;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SETRLIMIT
	ರಚನೆ rlimit rlim;
#ಆದರೆ_ಅಂತ್ಯ
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ಗಾತ್ರ_t len;
	ಬಹುಲಕ_t prev_ಮುಖವಾಡ;
	ರಚನೆ timespec timeout;
	ರಚನೆ pollfd *pfd = ಖಾಲಿ;
	ಗಾತ್ರ_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	ಪೂರ್ಣಾಂಕ socket_activated = 0;
	ರಚನೆ passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(ಶೂನ್ಯ)setegid(getgid());
	(ಶೂನ್ಯ)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	ಆದರೆ ((pw = getpwuid(getuid())) == ಖಾಲಿ)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ RLIMIT_NOFILE
	ಆದರೆ (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ

	__progname = ssh_get_progname(av[0]);
	ಬೀಜ_rng();

	ಆಗ ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			ಆದರೆ (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'c':
			ಆದರೆ (s_flag)
				usage();
			c_flag++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'k':
			k_flag++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'O':
			ಆದರೆ (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_ಕೂಡಿಸು_provider = 1;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != ಖಾಲಿ) {
				ಆದರೆ (websafe_allowlist != ಖಾಲಿ)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} ಇಲ್ಲದಿದ್ದರೆ
				fatal("Unknown -O option");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'P':
			ಆದರೆ (allowed_providers != ಖಾಲಿ)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 's':
			ಆದರೆ (c_flag)
				usage();
			s_flag++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'd':
			ಆದರೆ (d_flag || D_flag)
				usage();
			d_flag++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
			ಆದರೆ (d_flag || D_flag)
				usage();
			D_flag++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'a':
			agentsocket = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'A':
			socket_dirspec = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
			ಆದರೆ ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'T':
			T_flag++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'u':
			u_flag++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'U':
			U_flag++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_ಆವೃತ್ತಿ, SSH_OPENSSL_ಆವೃತ್ತಿ);
			ನಿರ್ಗಮಿಸು(0);
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	ಆದರೆ (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	ಆದರೆ (((socket_dirspec != ಖಾಲಿ) + (agentsocket != ಖಾಲಿ) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	ಆದರೆ (allowed_providers == ಖಾಲಿ)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	ಆದರೆ (websafe_allowlist == ಖಾಲಿ)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	ಆದರೆ (T_flag)
		socket_dirspec = xstrdup(ಮಾರ್ಗ_SSH_AGENT_SOCKET_TMPDIR);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (socket_dirspec == ಖಾಲಿ && agentsocket == ಖಾಲಿ)
		socket_dirspec = xstrdup(ಮಾರ್ಗ_SSH_AGENT_SOCKET_DIR);

	ಆದರೆ (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		ಆದರೆ (shell != ಖಾಲಿ && (len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(shell)) > 2 &&
		    ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	ಆದರೆ (k_flag) {
		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		ಆದರೆ (pidstr == ಖಾಲಿ) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			ನಿರ್ಗಮಿಸು(1);
		}
		pid = (ಪೂರ್ಣಾಂಕ)strtonum(pidstr, 2, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &errstr);
		ಆದರೆ (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			ನಿರ್ಗಮಿಸು(1);
		}
		ಆದರೆ (kill(pid, SIGTERM) == -1) {
			perror("kill");
			ನಿರ್ಗಮಿಸು(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		ಬರೆ(format, SSH_AUTHSOCKET_ENV_NAME);
		ಬರೆ(format, SSH_AGENTPID_ENV_NAME);
		ಬರೆ("echo Agent pid %ld killed;\n", (ದೀರ್ಘ)pid);
		ನಿರ್ಗಮಿಸು(0);
	}
	ಆದರೆ (u_flag) {
		ಆದರೆ ((homedir = get_homedir()) == ಖಾಲಿ)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		ಬರೆ("Deleted stale agent sockets in ~/%s\n",
		    ಮಾರ್ಗ_SSH_AGENT_SOCKET_DIR);
		ನಿರ್ಗಮಿಸು(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENT_MIN_FDS (3+1+1+1+4)
	ಆದರೆ (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (ದೀರ್ಘ ದೀರ್ಘ)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	ಪೋಷಕ_pid = getpid();

	/* Has the socket been provided via socket activation? */
	ಆದರೆ (agentsocket == ಖಾಲಿ && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = getenv("LISTEN_PID")) != ಖಾಲಿ &&
	    (fdstr = getenv("LISTEN_FDS")) != ಖಾಲಿ) {
		ಆದರೆ (strcmp(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		ಆದರೆ (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (ಪೂರ್ಣಾಂಕ)strtonum(pidstr, 1, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &errstr);
		ಆದರೆ (errstr != ಖಾಲಿ)
			fatal("invalid LISTEN_PID: %s", errstr);
		ಆದರೆ (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	ಆದರೆ (sock == -1 && agentsocket == ಖಾಲಿ) {
		/* Listen on a socket in/under a given directory */
		ಆದರೆ ((homedir = get_homedir()) == ಖಾಲಿ)
			fatal("Couldn't determine home directory");
		ಆದರೆ (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		ಆದರೆ (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		ಬಿಡುಗಡೆ(homedir);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sock == -1) {
		/* Listen on explicit socket path */
		prev_ಮುಖವಾಡ = umask(0177);
		socket_name = xstrdup(agentsocket);
		ಆದರೆ ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			ಬಿಡುಗಡೆ(socket_name);
			socket_name = ಖಾಲಿ; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_ಮುಖವಾಡ);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	ಆದರೆ (sock == -1) {
		prev_ಮುಖವಾಡ = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		ಆದರೆ (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_ಮುಖವಾಡ);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	ಆದರೆ (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		ಆದರೆ (socket_name != ಖಾಲಿ) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			ಬರೆ(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			ಬಿಡುಗಡೆ(cp);
			ಬರೆ("echo Agent pid %ld;\n", (ದೀರ್ಘ)ಪೋಷಕ_pid);
			fflush(stdout);
		}
		ಹೋಗು skip;
	}
	pid = fork();
	ಆದರೆ (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	ಆದರೆ (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, ಗಾತ್ರ pidstrbuf, "%ld", (ದೀರ್ಘ)pid);
		ಆದರೆ (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			ಬರೆ(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			ಬರೆ(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			ಬಿಡುಗಡೆ(cp);
			ಬರೆ("echo Agent pid %ld;\n", (ದೀರ್ಘ)pid);
			ನಿರ್ಗಮಿಸು(0);
		}
		ಆದರೆ (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			ನಿರ್ಗಮಿಸು(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		ನಿರ್ಗಮಿಸು(1);
	}
	/*ಮಗು*/
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	ಆದರೆ (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(ಶೂನ್ಯ)chdir("/");
	ಆದರೆ (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	ಆದರೆ (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#ಆದರೆ_ಅಂತ್ಯ

skip:

	cleanup_pid = getpid();

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	pkcs11_init(0);
#ಆದರೆ_ಅಂತ್ಯ
	new_socket(AUTH_SOCKET, sock);
	ಆದರೆ (ac > 0)
		ಪೋಷಕ_alive_interval = 10;
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

	ಆದರೆ (socket_name != ಖಾಲಿ && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    strerror(errno));
	}
	ಆದರೆ (socket_dir != ಖಾಲಿ && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    strerror(errno));
	}
	ಆದರೆ (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, strerror(errno));
	ಆದರೆ ((ccp = getenv("SSH_SK_HELPER")) == ಖಾಲಿ || *ccp == '\0')
		ccp = ಮಾರ್ಗ_SSH_SK_HELPER;
	ಆದರೆ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ಆದರೆ ((ccp = getenv("SSH_PKCS11_HELPER")) == ಖಾಲಿ || *ccp == '\0')
		ccp = ಮಾರ್ಗ_SSH_PKCS11_HELPER;
	ಆದರೆ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ಆದರೆ ((ccp = getenv("SSH_ASKPASS")) == ಖಾಲಿ || *ccp == '\0')
		ccp = ಮಾರ್ಗ_SSH_ASKPASS_DEFAULT;
	ಆದರೆ (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, strerror(errno));
	ಆದರೆ (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, strerror(errno));
	ಆದರೆ (pledge("stdio rpath cpath wpath unix id proc exec", ಖಾಲಿ) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	ಆಗ (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		ಆದರೆ (signalled_exit != 0) {
			logit("exiting on signal %d", (ಪೂರ್ಣಾಂಕ)signalled_exit);
			cleanup_exit((signalled_exit == SIGTERM &&
			    socket_activated) ? 0 : 2);
		}
		ಆದರೆ (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (ಪೂರ್ಣಾಂಕ)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		ಫಲಿತಾಂಶ = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, ಖಾಲಿ);
		saved_errno = errno;
		ಆದರೆ (ಪೋಷಕ_alive_interval != 0)
			check_ಪೋಷಕ_exists();
		(ಶೂನ್ಯ) reaper();	/* remove expired keys */
		ಆದರೆ (ಫಲಿತಾಂಶ == -1) {
			ಆದರೆ (saved_errno == EINTR)
				ಮುಂದುವರಿ;
			fatal("poll: %s", strerror(saved_errno));
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಫಲಿತಾಂಶ > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
