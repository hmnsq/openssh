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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/time.h>
#समावेश <sys/queue.h>
#समावेश <sys/resource.h>
#समावेश <sys/socket.h>
#समावेश <sys/stat.h>
#समावेश <sys/un.h>
#समावेश <sys/wait.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/evp.h>
#समावेश "openbsd-compat/openssl-compat.h"
#पूर्ण_अगर

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <paths.h>
#समावेश <poll.h>
#समावेश <signal.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <limits.h>
#समावेश <time.h>
#समावेश <unistd.h>
#समावेश <util.h>
#समावेश <pwd.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "authfd.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "digest.h"
#समावेश "ssherr.h"
#समावेश "match.h"
#समावेश "msg.h"
#समावेश "pathnames.h"
#समावेश "ssh-pkcs11.h"
#समावेश "sk-api.h"
#समावेश "myproposal.h"
#समावेश "version.h"

#अगर_अघोषित DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#पूर्ण_अगर
#अगर_अघोषित DEFAULT_WEBSAFE_ALLOWLIST
# define DEFAULT_WEBSAFE_ALLOWLIST "ssh:*"
#पूर्ण_अगर

/* Maximum accepted message length */
#घोषणा AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#घोषणा AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#घोषणा AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#घोषणा AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#घोषणा AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#घोषणा AGENT_MAX_EXT_CERTS		1024
/* Max length of username constraint */
#घोषणा AGENT_USER_CONSTRAINT_MAX_LEN	256

/* XXX store hostkey_sid in a refcounted tree */

प्रकार क्रमागत {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

काष्ठा hostkey_sid {
	काष्ठा sshkey *कुंजी;
	काष्ठा sshbuf *sid;
	पूर्णांक forwarded;
};

प्रकार काष्ठा socket_entry {
	पूर्णांक fd;
	sock_type type;
	काष्ठा sshbuf *निवेश;
	काष्ठा sshbuf *output;
	काष्ठा sshbuf *request;
	माप_प्रकार nsession_ids;
	काष्ठा hostkey_sid *session_ids;
	पूर्णांक session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = शून्य;

प्रकार काष्ठा identity {
	TAILQ_ENTRY(identity) अग्र;
	काष्ठा sshkey *कुंजी;
	अक्षर *comment;
	अक्षर *provider;
	समय_प्रकार death;
	u_int confirm;
	अक्षर *sk_provider;
	काष्ठा dest_constraint *dest_constraints;
	माप_प्रकार ndest_constraints;
} Identity;

काष्ठा idtable {
	पूर्णांक nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
काष्ठा idtable *idtab;

पूर्णांक max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
समय_प्रकार parent_alive_interval = 0;

अटल संक_पूर्ण_प्रकार signalled_exit;
अटल संक_पूर्ण_प्रकार signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
अटल अक्षर *socket_name;
अटल अक्षर *socket_dir;
अटल अक्षर *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
अटल अक्षर *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
अटल पूर्णांक remote_add_provider;

/* locking */
#घोषणा LOCK_आकार	32
#घोषणा LOCK_SALT_आकार	16
#घोषणा LOCK_ROUNDS	1
पूर्णांक locked = 0;
u_char lock_pwhash[LOCK_आकार];
u_char lock_salt[LOCK_SALT_आकार];

बाह्य अक्षर *__progname;

/* Default lifetime in seconds (0 == forever) */
अटल पूर्णांक lifetime = 0;

अटल पूर्णांक fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
अटल पूर्णांक restrict_websafe = 1;
अटल अक्षर *websafe_allowlist;

अटल व्योम
close_socket(SocketEntry *e)
{
	माप_प्रकार i;

	बंद(e->fd);
	sshbuf_free(e->निवेश);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	क्रम (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].कुंजी);
		sshbuf_free(e->session_ids[i].sid);
	}
	मुक्त(e->session_ids);
	स_रखो(e, '\0', माप(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

अटल व्योम
idtab_init(व्योम)
{
	idtab = xcalloc(1, माप(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

अटल व्योम
free_dest_constraint_hop(काष्ठा dest_constraint_hop *dch)
{
	u_int i;

	अगर (dch == शून्य)
		वापस;
	मुक्त(dch->user);
	मुक्त(dch->hostname);
	क्रम (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->कुंजियाँ[i]);
	मुक्त(dch->कुंजियाँ);
	मुक्त(dch->कुंजी_is_ca);
}

अटल व्योम
free_dest_constraints(काष्ठा dest_constraint *dcs, माप_प्रकार ndcs)
{
	माप_प्रकार i;

	क्रम (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	मुक्त(dcs);
}

#अगर_घोषित ENABLE_PKCS11
अटल व्योम
dup_dest_constraint_hop(स्थिर काष्ठा dest_constraint_hop *dch,
    काष्ठा dest_constraint_hop *out)
{
	u_int i;
	पूर्णांक r;

	out->user = dch->user == शून्य ? शून्य : xstrdup(dch->user);
	out->hostname = dch->hostname == शून्य ? शून्य : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->कुंजियाँ = out->nkeys == 0 ? शून्य :
	    xcalloc(out->nkeys, माप(*out->कुंजियाँ));
	out->कुंजी_is_ca = out->nkeys == 0 ? शून्य :
	    xcalloc(out->nkeys, माप(*out->कुंजी_is_ca));
	क्रम (i = 0; i < dch->nkeys; i++) {
		अगर (dch->कुंजियाँ[i] != शून्य &&
		    (r = sshkey_from_private(dch->कुंजियाँ[i],
		    &(out->कुंजियाँ[i]))) != 0)
			fatal_fr(r, "copy key");
		out->कुंजी_is_ca[i] = dch->कुंजी_is_ca[i];
	}
}

अटल काष्ठा dest_constraint *
dup_dest_constraints(स्थिर काष्ठा dest_constraint *dcs, माप_प्रकार ndcs)
{
	माप_प्रकार i;
	काष्ठा dest_constraint *ret;

	अगर (ndcs == 0)
		वापस शून्य;
	ret = xcalloc(ndcs, माप(*ret));
	क्रम (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	वापस ret;
}
#पूर्ण_अगर /* ENABLE_PKCS11 */

#अगर_घोषित DEBUG_CONSTRAINTS
अटल व्योम
dump_dest_constraint_hop(स्थिर काष्ठा dest_constraint_hop *dch)
{
	u_int i;
	अक्षर *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == शून्य ? "(null)" : dch->user,
	    dch->hostname == शून्य ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	क्रम (i = 0; i < dch->nkeys; i++) {
		fp = शून्य;
		अगर (dch->कुंजियाँ[i] != शून्य &&
		    (fp = sshkey_fingerprint(dch->कुंजियाँ[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == शून्य)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->कुंजियाँ[i] == शून्य ? "" : sshkey_ssh_name(dch->कुंजियाँ[i]),
		    dch->कुंजियाँ[i] == शून्य ? "" : " ",
		    dch->कुंजियाँ[i] == शून्य ? "none" : fp,
		    dch->कुंजी_is_ca[i]);
		मुक्त(fp);
	}
}
#पूर्ण_अगर /* DEBUG_CONSTRAINTS */

अटल व्योम
dump_dest_constraints(स्थिर अक्षर *context,
    स्थिर काष्ठा dest_constraint *dcs, माप_प्रकार ndcs)
{
#अगर_घोषित DEBUG_CONSTRAINTS
	माप_प्रकार i;

	debug_f("%s: %zu constraints", context, ndcs);
	क्रम (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#पूर्ण_अगर /* DEBUG_CONSTRAINTS */
}

अटल व्योम
free_identity(Identity *id)
{
	sshkey_free(id->कुंजी);
	मुक्त(id->provider);
	मुक्त(id->comment);
	मुक्त(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	मुक्त(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
अटल पूर्णांक
match_कुंजी_hop(स्थिर अक्षर *tag, स्थिर काष्ठा sshkey *कुंजी,
    स्थिर काष्ठा dest_constraint_hop *dch)
{
	स्थिर अक्षर *reason = शून्य;
	स्थिर अक्षर *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	अक्षर *fp;

	अगर (कुंजी == शून्य)
		वापस -1;
	/* XXX logspam */
	अगर ((fp = sshkey_fingerprint(कुंजी, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == शून्य)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(कुंजी), fp, dch->nkeys);
	मुक्त(fp);
	क्रम (i = 0; i < dch->nkeys; i++) {
		अगर (dch->कुंजियाँ[i] == शून्य)
			वापस -1;
		/* XXX logspam */
		अगर ((fp = sshkey_fingerprint(dch->कुंजियाँ[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == शून्य)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->कुंजी_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->कुंजियाँ[i]), fp);
		मुक्त(fp);
		अगर (!sshkey_is_cert(कुंजी)) {
			/* plain key */
			अगर (dch->कुंजी_is_ca[i] ||
			    !sshkey_equal(कुंजी, dch->कुंजियाँ[i]))
				जारी;
			वापस 0;
		}
		/* certificate */
		अगर (!dch->कुंजी_is_ca[i])
			जारी;
		अगर (कुंजी->cert == शून्य || कुंजी->cert->signature_कुंजी == शून्य)
			वापस -1; /* shouldn't happen */
		अगर (!sshkey_equal(कुंजी->cert->signature_कुंजी, dch->कुंजियाँ[i]))
			जारी;
		अगर (sshkey_cert_check_host(कुंजी, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    कुंजी->cert->कुंजी_id, hostname, reason);
			जारी;
		}
		वापस 0;
	}
	वापस -1;
}

/* Check destination constraints on an identity against the hostkey/user */
अटल पूर्णांक
permitted_by_dest_constraints(स्थिर काष्ठा sshkey *fromkey,
    स्थिर काष्ठा sshkey *tokey, Identity *id, स्थिर अक्षर *user,
    स्थिर अक्षर **hostnamep)
{
	माप_प्रकार i;
	काष्ठा dest_constraint *d;

	अगर (hostnamep != शून्य)
		*hostnamep = शून्य;
	क्रम (i = 0; i < id->ndest_constraints; i++) {
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
		अगर (fromkey == शून्य) {
			/* We are matching the first hop */
			अगर (d->from.hostname != शून्य || d->from.nkeys != 0)
				जारी;
		} अन्यथा अगर (match_कुंजी_hop("from", fromkey, &d->from) != 0)
			जारी;

		/* Match 'to' key */
		अगर (tokey != शून्य && match_कुंजी_hop("to", tokey, &d->to) != 0)
			जारी;

		/* Match user if specified */
		अगर (d->to.user != शून्य && user != शून्य &&
		    !match_pattern(user, d->to.user))
			जारी;

		/* successfully matched this constraint */
		अगर (hostnamep != शून्य)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == शून्य ? "*" : d->to.hostname);
		वापस 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->कुंजी), id->comment);
	वापस -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
अटल पूर्णांक
identity_permitted(Identity *id, SocketEntry *e, अक्षर *user,
    स्थिर अक्षर **forward_hostnamep, स्थिर अक्षर **last_hostnamep)
{
	माप_प्रकार i;
	स्थिर अक्षर **hp;
	काष्ठा hostkey_sid *hks;
	स्थिर काष्ठा sshkey *fromkey = शून्य;
	स्थिर अक्षर *test_user;
	अक्षर *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->कुंजी), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	अगर (id->ndest_constraints == 0)
		वापस 0; /* unconstrained */
	अगर (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		वापस -1;
	}
	अगर (e->nsession_ids == 0)
		वापस 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	क्रम (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		अगर (hks->कुंजी == शून्य)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = शून्य;
		अगर (fromkey != शून्य &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == शून्य)
			fatal_f("fingerprint failed");
		अगर ((fp2 = sshkey_fingerprint(hks->कुंजी, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == शून्य)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->कुंजी), fp2);
		मुक्त(fp1);
		मुक्त(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = शून्य;
		अगर (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		अन्यथा अगर (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = शून्य;
		अगर (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			अगर (hks->forwarded && user != शून्य) {
				error_f("tried to sign on forwarding hop");
				वापस -1;
			}
		} अन्यथा अगर (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			वापस -1;
		}
		अगर (permitted_by_dest_constraints(fromkey, hks->कुंजी, id,
		    test_user, hp) != 0)
			वापस -1;
		fromkey = hks->कुंजी;
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
	अगर (hks->forwarded && user == शून्य &&
	    permitted_by_dest_constraints(hks->कुंजी, शून्य, id,
	    शून्य, शून्य) != 0) {
		debug3_f("key permitted at host but not after");
		वापस -1;
	}

	/* success */
	वापस 0;
}

अटल पूर्णांक
socket_is_remote(SocketEntry *e)
{
	वापस e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
अटल Identity *
lookup_identity(काष्ठा sshkey *कुंजी)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, अग्र) {
		अगर (sshkey_equal(कुंजी, id->कुंजी))
			वापस (id);
	}
	वापस (शून्य);
}

/* Check confirmation of keysign request */
अटल पूर्णांक
confirm_कुंजी(Identity *id, स्थिर अक्षर *extra)
{
	अक्षर *p;
	पूर्णांक ret = -1;

	p = sshkey_fingerprint(id->कुंजी, fingerprint_hash, SSH_FP_DEFAULT);
	अगर (p != शून्य &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == शून्य ? "" : "\n", extra == शून्य ? "" : extra))
		ret = 0;
	मुक्त(p);

	वापस (ret);
}

अटल व्योम
send_status_generic(SocketEntry *e, u_int code)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

अटल व्योम
send_status(SocketEntry *e, पूर्णांक success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
अटल व्योम
process_request_identities(SocketEntry *e)
{
	Identity *id;
	काष्ठा sshbuf *संदेश, *कुंजियाँ;
	पूर्णांक r;
	u_int i = 0, nentries = 0;
	अक्षर *fp;

	debug2_f("entering");

	अगर ((संदेश = sshbuf_new()) == शून्य || (कुंजियाँ = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, अग्र) {
		अगर ((fp = sshkey_fingerprint(id->कुंजी, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == शून्य)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->कुंजी), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		मुक्त(fp);
		/* identity not visible, don't include in response */
		अगर (identity_permitted(id, e, शून्य, शून्य, शून्य) != 0)
			जारी;
		अगर ((r = sshkey_puts(id->कुंजी, कुंजियाँ)) != 0 ||
		    (r = sshbuf_put_cstring(कुंजियाँ, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			जारी;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, nentries)) != 0 ||
	    (r = sshbuf_putb(संदेश, कुंजियाँ)) != 0)
		fatal_fr(r, "compose");
	अगर ((r = sshbuf_put_stringb(e->output, संदेश)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(संदेश);
	sshbuf_free(कुंजियाँ);
}


अटल अक्षर *
agent_decode_alg(काष्ठा sshkey *कुंजी, u_int flags)
{
	अगर (कुंजी->type == कुंजी_RSA) {
		अगर (flags & SSH_AGENT_RSA_SHA2_256)
			वापस "rsa-sha2-256";
		अन्यथा अगर (flags & SSH_AGENT_RSA_SHA2_512)
			वापस "rsa-sha2-512";
	} अन्यथा अगर (कुंजी->type == कुंजी_RSA_CERT) {
		अगर (flags & SSH_AGENT_RSA_SHA2_256)
			वापस "rsa-sha2-256-cert-v01@openssh.com";
		अन्यथा अगर (flags & SSH_AGENT_RSA_SHA2_512)
			वापस "rsa-sha2-512-cert-v01@openssh.com";
	}
	वापस शून्य;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
अटल पूर्णांक
parse_userauth_request(काष्ठा sshbuf *संदेश, स्थिर काष्ठा sshkey *expected_कुंजी,
    अक्षर **userp, काष्ठा sshbuf **sess_idp, काष्ठा sshkey **hostkeyp)
{
	काष्ठा sshbuf *b = शून्य, *sess_id = शून्य;
	अक्षर *user = शून्य, *service = शून्य, *method = शून्य, *pkalg = शून्य;
	पूर्णांक r;
	u_char t, sig_follows;
	काष्ठा sshkey *mkey = शून्य, *hostkey = शून्य;

	अगर (userp != शून्य)
		*userp = शून्य;
	अगर (sess_idp != शून्य)
		*sess_idp = शून्य;
	अगर (hostkeyp != शून्य)
		*hostkeyp = शून्य;
	अगर ((b = sshbuf_fromb(संदेश)) == शून्य)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	अगर ((r = sshbuf_froms(b, &sess_id)) != 0)
		जाओ out;
	अगर (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, शून्य)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, शून्य)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, शून्य)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, शून्य)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*कुंजी*/
		जाओ out;
	अगर (t != SSH2_संदेश_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    म_भेद(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_कुंजी, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_कुंजी->type) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (म_भेद(method, "publickey-hostbound-v00@openssh.com") == 0) {
		अगर ((r = sshkey_froms(b, &hostkey)) != 0)
			जाओ out;
	} अन्यथा अगर (म_भेद(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	अगर (userp != शून्य) {
		*userp = user;
		user = शून्य;
	}
	अगर (sess_idp != शून्य) {
		*sess_idp = sess_id;
		sess_id = शून्य;
	}
	अगर (hostkeyp != शून्य) {
		*hostkeyp = hostkey;
		hostkey = शून्य;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	मुक्त(user);
	मुक्त(service);
	मुक्त(method);
	मुक्त(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	वापस r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
अटल पूर्णांक
parse_sshsig_request(काष्ठा sshbuf *संदेश)
{
	पूर्णांक r;
	काष्ठा sshbuf *b;

	अगर ((b = sshbuf_fromb(संदेश)) == शून्य)
		fatal_f("sshbuf_fromb");

	अगर ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, शून्य, शून्य)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, शून्य, शून्य)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, शून्य, शून्य)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, शून्य, शून्य)) != 0) /* H(msg) */
		जाओ out;
	अगर (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
अटल पूर्णांक
check_websafe_message_contents(काष्ठा sshkey *कुंजी, काष्ठा sshbuf *तथ्य)
{
	अगर (parse_userauth_request(तथ्य, कुंजी, शून्य, शून्य, शून्य) == 0) {
		debug_f("signed data matches public key userauth request");
		वापस 1;
	}
	अगर (parse_sshsig_request(तथ्य) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		वापस 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	वापस 0;
}

अटल पूर्णांक
buf_equal(स्थिर काष्ठा sshbuf *a, स्थिर काष्ठा sshbuf *b)
{
	अगर (sshbuf_ptr(a) == शून्य || sshbuf_ptr(b) == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (sshbuf_len(a) != sshbuf_len(b))
		वापस SSH_ERR_INVALID_FORMAT;
	अगर (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		वापस SSH_ERR_INVALID_FORMAT;
	वापस 0;
}

/* ssh2 only */
अटल व्योम
process_sign_request2(SocketEntry *e)
{
	u_char *signature = शून्य;
	माप_प्रकार slen = 0;
	u_int compat = 0, flags;
	पूर्णांक r, ok = -1, retried = 0;
	अक्षर *fp = शून्य, *pin = शून्य, *prompt = शून्य;
	अक्षर *user = शून्य, *sig_dest = शून्य;
	स्थिर अक्षर *fwd_host = शून्य, *dest_host = शून्य;
	काष्ठा sshbuf *संदेश = शून्य, *तथ्य = शून्य, *sid = शून्य;
	काष्ठा sshkey *कुंजी = शून्य, *hostkey = शून्य;
	काष्ठा identity *id;
	काष्ठा notifier_ctx *notifier = शून्य;

	debug_f("entering");

	अगर ((संदेश = sshbuf_new()) == शून्य || (तथ्य = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_froms(e->request, &कुंजी)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, तथ्य)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		जाओ send;
	}

	अगर ((id = lookup_identity(कुंजी)) == शून्य) {
		verbose_f("%s key not found", sshkey_type(कुंजी));
		जाओ send;
	}
	अगर ((fp = sshkey_fingerprint(कुंजी, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == शून्य)
		fatal_f("fingerprint failed");

	अगर (id->ndest_constraints != 0) {
		अगर (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			जाओ send;
		}
		अगर (parse_userauth_request(तथ्य, कुंजी, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			जाओ send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		अगर (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			जाओ send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		अगर (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->कुंजी), fp);
			जाओ send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		अगर (e->nsession_ids > 1 && hostkey == शून्य) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			जाओ send;
		}
		अगर (hostkey != शून्य && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].कुंजी)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			जाओ send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	अगर (id->confirm && confirm_कुंजी(id, sig_dest) != 0) {
		verbose_f("user refused key");
		जाओ send;
	}
	अगर (sshkey_is_sk(id->कुंजी)) {
		अगर (restrict_websafe &&
		    match_pattern_list(id->कुंजी->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(कुंजी, तथ्य)) {
			/* error already logged */
			जाओ send;
		}
		अगर (id->कुंजी->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->कुंजी), fp,
			    sig_dest == शून्य ? "" : "\n",
			    sig_dest == शून्य ? "" : sig_dest);
		}
	}
 retry_pin:
	अगर ((r = sshkey_sign(id->कुंजी, &signature, &slen,
	    sshbuf_ptr(तथ्य), sshbuf_len(तथ्य), agent_decode_alg(कुंजी, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		अगर (pin == शून्य && !retried && sshkey_is_sk(id->कुंजी) &&
		    r == SSH_ERR_कुंजी_WRONG_PASSPHRASE) {
			notify_complete(notifier, शून्य);
			notifier = शून्य;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->कुंजी->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->कुंजी), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			जाओ retry_pin;
		}
		error_fr(r, "sshkey_sign");
		जाओ send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	अगर (ok == 0) {
		अगर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(संदेश, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} अन्यथा अगर ((r = sshbuf_put_u8(संदेश, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	अगर ((r = sshbuf_put_stringb(e->output, संदेश)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(तथ्य);
	sshbuf_free(संदेश);
	sshkey_free(कुंजी);
	sshkey_free(hostkey);
	मुक्त(fp);
	मुक्त(signature);
	मुक्त(sig_dest);
	मुक्त(user);
	मुक्त(prompt);
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));
}

/* shared */
अटल व्योम
process_remove_identity(SocketEntry *e)
{
	पूर्णांक r, success = 0;
	काष्ठा sshkey *कुंजी = शून्य;
	Identity *id;

	debug2_f("entering");
	अगर ((r = sshkey_froms(e->request, &कुंजी)) != 0) {
		error_fr(r, "parse key");
		जाओ done;
	}
	अगर ((id = lookup_identity(कुंजी)) == शून्य) {
		debug_f("key not found");
		जाओ done;
	}
	/* identity not visible, cannot be removed */
	अगर (identity_permitted(id, e, शून्य, शून्य, शून्य) != 0)
		जाओ done; /* error already logged */
	/* We have this key, free it. */
	अगर (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, अग्र);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(कुंजी);
	send_status(e, success);
}

अटल व्योम
remove_all_identities(व्योम)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	क्रम (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, अग्र);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

अटल व्योम
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
अटल समय_प्रकार
reaper(व्योम)
{
	समय_प्रकार deadline = 0, now = monotime();
	Identity *id, *nxt;

	क्रम (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, अग्र);
		अगर (id->death == 0)
			जारी;
		अगर (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, अग्र);
			free_identity(id);
			idtab->nentries--;
		} अन्यथा
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	अगर (deadline == 0 || deadline <= now)
		वापस 0;
	अन्यथा
		वापस (deadline - now);
}

अटल पूर्णांक
parse_dest_constraint_hop(काष्ठा sshbuf *b, काष्ठा dest_constraint_hop *dch)
{
	u_char कुंजी_is_ca;
	माप_प्रकार elen = 0, userlen = 0;
	पूर्णांक r;
	काष्ठा sshkey *k = शून्य;
	अक्षर *fp;

	स_रखो(dch, '\0', माप(*dch));
	अगर ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, शून्य)) != 0 ||
	    (r = sshbuf_get_string_direct(b, शून्य, &elen)) != 0) {
		error_fr(r, "parse");
		जाओ out;
	}
	अगर (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		जाओ out;
	}
	अगर (*dch->hostname == '\0') {
		मुक्त(dch->hostname);
		dch->hostname = शून्य;
	}
	अगर (*dch->user == '\0') {
		मुक्त(dch->user);
		dch->user = शून्य;
	} अन्यथा अगर (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	जबतक (sshbuf_len(b) != 0) {
		dch->कुंजियाँ = xrecallocarray(dch->कुंजियाँ, dch->nkeys,
		    dch->nkeys + 1, माप(*dch->कुंजियाँ));
		dch->कुंजी_is_ca = xrecallocarray(dch->कुंजी_is_ca, dch->nkeys,
		    dch->nkeys + 1, माप(*dch->कुंजी_is_ca));
		अगर ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &कुंजी_is_ca)) != 0)
			जाओ out;
		अगर ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == शून्य)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == शून्य ? "" : dch->user,
		    dch->user == शून्य ? "" : "@",
		    dch->hostname, कुंजी_is_ca ? "CA " : "", sshkey_type(k), fp);
		मुक्त(fp);
		dch->कुंजियाँ[dch->nkeys] = k;
		dch->कुंजी_is_ca[dch->nkeys] = कुंजी_is_ca != 0;
		dch->nkeys++;
		k = शून्य; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	वापस r;
}

अटल पूर्णांक
parse_dest_constraint(काष्ठा sshbuf *m, काष्ठा dest_constraint *dc)
{
	काष्ठा sshbuf *b = शून्य, *frombuf = शून्य, *tobuf = शून्य;
	पूर्णांक r;
	माप_प्रकार elen = 0;

	debug3_f("entering");

	स_रखो(dc, '\0', माप(*dc));
	अगर ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, शून्य, &elen)) != 0) {
		error_fr(r, "parse");
		जाओ out;
	}
	अगर ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		जाओ out; /* already logged */
	अगर (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		जाओ out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	अगर ((dc->from.hostname == शून्य) != (dc->from.nkeys == 0) ||
	    dc->from.user != शून्य) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (dc->to.hostname == शून्य || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	वापस r;
}

अटल पूर्णांक
parse_कुंजी_constraint_extension(काष्ठा sshbuf *m, अक्षर **sk_providerp,
    काष्ठा dest_constraint **dcsp, माप_प्रकार *ndcsp, पूर्णांक *cert_onlyp,
    काष्ठा sshkey ***certs, माप_प्रकार *ncerts)
{
	अक्षर *ext_name = शून्य;
	पूर्णांक r;
	काष्ठा sshbuf *b = शून्य;
	u_char v;
	काष्ठा sshkey *k;

	अगर ((r = sshbuf_get_cstring(m, &ext_name, शून्य)) != 0) {
		error_fr(r, "parse constraint extension");
		जाओ out;
	}
	debug_f("constraint ext %s", ext_name);
	अगर (म_भेद(ext_name, "sk-provider@openssh.com") == 0) {
		अगर (sk_providerp == शून्य) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर (*sk_providerp != शून्य) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर ((r = sshbuf_get_cstring(m, sk_providerp, शून्य)) != 0) {
			error_fr(r, "parse %s", ext_name);
			जाओ out;
		}
	} अन्यथा अगर (म_भेद(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		अगर (*dcsp != शून्य) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			जाओ out;
		}
		जबतक (sshbuf_len(b) != 0) {
			अगर (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				जाओ out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    माप(**dcsp));
			अगर ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				जाओ out; /* error already logged */
		}
	} अन्यथा अगर (म_भेद(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		अगर (certs == शून्य || ncerts == शून्य || cert_onlyp == शून्य) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर (*certs != शून्य) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			जाओ out;
		}
		*cert_onlyp = v != 0;
		जबतक (sshbuf_len(b) != 0) {
			अगर (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				जाओ out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    माप(**certs));
			अगर ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				जाओ out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} अन्यथा {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(ext_name);
	sshbuf_free(b);
	वापस r;
}

अटल पूर्णांक
parse_कुंजी_constraints(काष्ठा sshbuf *m, काष्ठा sshkey *k, समय_प्रकार *deathp,
    u_int *secondsp, पूर्णांक *confirmp, अक्षर **sk_providerp,
    काष्ठा dest_constraint **dcsp, माप_प्रकार *ndcsp,
    पूर्णांक *cert_onlyp, माप_प्रकार *ncerts, काष्ठा sshkey ***certs)
{
	u_char ctype;
	पूर्णांक r;
	u_int seconds;

	जबतक (sshbuf_len(m)) {
		अगर ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			जाओ out;
		}
		चयन (ctype) {
		हाल SSH_AGENT_CONSTRAIN_LIFETIME:
			अगर (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				जाओ out;
			}
			अगर ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				जाओ out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			अवरोध;
		हाल SSH_AGENT_CONSTRAIN_CONFIRM:
			अगर (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				जाओ out;
			}
			*confirmp = 1;
			अवरोध;
		हाल SSH_AGENT_CONSTRAIN_EXTENSION:
			अगर ((r = parse_कुंजी_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				जाओ out; /* error already logged */
			अवरोध;
		शेष:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			जाओ out;
		}
	}
	/* success */
	r = 0;
 out:
	वापस r;
}

अटल व्योम
process_add_identity(SocketEntry *e)
{
	Identity *id;
	पूर्णांक success = 0, confirm = 0;
	अक्षर *fp, *comment = शून्य, *sk_provider = शून्य;
	अक्षर canonical_provider[PATH_MAX];
	समय_प्रकार death = 0;
	u_int seconds = 0;
	काष्ठा dest_constraint *dest_constraints = शून्य;
	माप_प्रकार ndest_constraints = 0;
	काष्ठा sshkey *k = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	अगर ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == शून्य ||
	    (r = sshbuf_get_cstring(e->request, &comment, शून्य)) != 0) {
		error_fr(r, "parse");
		जाओ out;
	}
	अगर (parse_कुंजी_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    शून्य, शून्य, शून्य) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		जाओ out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	अगर (sk_provider != शून्य) {
		अगर (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			जाओ out;
		}
		अगर (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} अन्यथा {
			अगर (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				जाओ out;
			}
			अगर (realpath(sk_provider, canonical_provider) == शून्य) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    म_त्रुटि(त्रुटि_सं));
				जाओ out;
			}
			मुक्त(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			अगर (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				जाओ out;
			}
		}
	}
	अगर ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		जाओ out;
	}
	अगर (lifetime && !death)
		death = monotime() + lifetime;
	अगर ((id = lookup_identity(k)) == शून्य) {
		id = xcalloc(1, माप(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, अग्र);
		/* Increment the number of identities. */
		idtab->nentries++;
	} अन्यथा {
		/* identity not visible, do not update */
		अगर (identity_permitted(id, e, शून्य, शून्य, शून्य) != 0)
			जाओ out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->कुंजी);
		मुक्त(id->comment);
		मुक्त(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->कुंजी = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	अगर ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == शून्य)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == शून्य ? "none" : sk_provider, ndest_constraints);
	मुक्त(fp);
	/* transferred */
	k = शून्य;
	comment = शून्य;
	sk_provider = शून्य;
	dest_constraints = शून्य;
	ndest_constraints = 0;
	success = 1;
 out:
	मुक्त(sk_provider);
	मुक्त(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
अटल व्योम
process_lock_agent(SocketEntry *e, पूर्णांक lock)
{
	पूर्णांक r, success = 0, delay;
	अक्षर *passwd;
	u_char passwdhash[LOCK_आकार];
	अटल u_int fail_गिनती = 0;
	माप_प्रकार pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	अगर ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	अगर (pwlen == 0) {
		debug("empty password not supported");
	} अन्यथा अगर (locked && !lock) {
		अगर (bcrypt_pbkdf(passwd, pwlen, lock_salt, माप(lock_salt),
		    passwdhash, माप(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		अगर (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_आकार) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_गिनती = 0;
			explicit_bzero(lock_pwhash, माप(lock_pwhash));
			success = 1;
		} अन्यथा {
			/* delay in 0.1s increments up to 10s */
			अगर (fail_गिनती < 100)
				fail_गिनती++;
			delay = 100000 * fail_गिनती;
			debug("unlock failed, delaying %0.1lf seconds",
			    (द्विगुन)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, माप(passwdhash));
	} अन्यथा अगर (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, माप(lock_salt));
		अगर (bcrypt_pbkdf(passwd, pwlen, lock_salt, माप(lock_salt),
		    lock_pwhash, माप(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

अटल व्योम
no_identities(SocketEntry *e)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, संदेश)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(संदेश);
}

#अगर_घोषित ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
अटल व्योम
add_p11_identity(काष्ठा sshkey *कुंजी, अक्षर *comment, स्थिर अक्षर *provider,
    समय_प्रकार death, u_int confirm, काष्ठा dest_constraint *dest_constraints,
    माप_प्रकार ndest_constraints)
{
	Identity *id;

	अगर (lookup_identity(कुंजी) != शून्य) {
		sshkey_free(कुंजी);
		मुक्त(comment);
		वापस;
	}
	id = xcalloc(1, माप(Identity));
	id->कुंजी = कुंजी;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, अग्र);
	idtab->nentries++;
}

अटल व्योम
process_add_smartcard_कुंजी(SocketEntry *e)
{
	अक्षर *provider = शून्य, *pin = शून्य, canonical_provider[PATH_MAX];
	अक्षर **comments = शून्य;
	पूर्णांक r, i, गिनती = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	समय_प्रकार death = 0;
	काष्ठा sshkey **कुंजियाँ = शून्य, *k;
	काष्ठा dest_constraint *dest_constraints = शून्य;
	माप_प्रकार j, ndest_constraints = 0, ncerts = 0;
	काष्ठा sshkey **certs = शून्य;
	पूर्णांक cert_only = 0;

	debug2_f("entering");
	अगर ((r = sshbuf_get_cstring(e->request, &provider, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, शून्य)) != 0) {
		error_fr(r, "parse");
		जाओ send;
	}
	अगर (parse_कुंजी_constraints(e->request, शून्य, &death, &seconds, &confirm,
	    शून्य, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		जाओ send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	अगर (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		जाओ send;
	}
	अगर (realpath(provider, canonical_provider) == शून्य) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, म_त्रुटि(त्रुटि_सं));
		जाओ send;
	}
	अगर (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		जाओ send;
	}
	debug_f("add %.100s", canonical_provider);
	अगर (lifetime && !death)
		death = monotime() + lifetime;

	गिनती = pkcs11_add_provider(canonical_provider, pin, &कुंजियाँ, &comments);
	क्रम (i = 0; i < गिनती; i++) {
		अगर (comments[i] == शून्य || comments[i][0] == '\0') {
			मुक्त(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		क्रम (j = 0; j < ncerts; j++) {
			अगर (!sshkey_is_cert(certs[j]))
				जारी;
			अगर (!sshkey_equal_public(कुंजियाँ[i], certs[j]))
				जारी;
			अगर (pkcs11_make_cert(कुंजियाँ[i], certs[j], &k) != 0)
				जारी;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		अगर (!cert_only && lookup_identity(कुंजियाँ[i]) == शून्य) {
			add_p11_identity(कुंजियाँ[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			कुंजियाँ[i] = शून्य;		/* transferred */
			comments[i] = शून्य;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(कुंजियाँ[i]);
		मुक्त(comments[i]);
	}
send:
	मुक्त(pin);
	मुक्त(provider);
	मुक्त(कुंजियाँ);
	मुक्त(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	क्रम (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	मुक्त(certs);
	send_status(e, success);
}

अटल व्योम
process_remove_smartcard_कुंजी(SocketEntry *e)
{
	अक्षर *provider = शून्य, *pin = शून्य, canonical_provider[PATH_MAX];
	पूर्णांक r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	अगर ((r = sshbuf_get_cstring(e->request, &provider, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, शून्य)) != 0) {
		error_fr(r, "parse");
		जाओ send;
	}
	मुक्त(pin);

	अगर (realpath(provider, canonical_provider) == शून्य) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, म_त्रुटि(त्रुटि_सं));
		जाओ send;
	}

	debug_f("remove %.100s", canonical_provider);
	क्रम (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, अग्र);
		/* Skip file--based keys */
		अगर (id->provider == शून्य)
			जारी;
		अगर (!म_भेद(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, अग्र);
			free_identity(id);
			idtab->nentries--;
		}
	}
	अगर (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	अन्यथा
		error_f("pkcs11_del_provider failed");
send:
	मुक्त(provider);
	send_status(e, success);
}
#पूर्ण_अगर /* ENABLE_PKCS11 */

अटल पूर्णांक
process_ext_session_bind(SocketEntry *e)
{
	पूर्णांक r, sid_match, कुंजी_match;
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा sshbuf *sid = शून्य, *sig = शून्य;
	अक्षर *fp = शून्य;
	माप_प्रकार i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	अगर ((r = sshkey_froms(e->request, &कुंजी)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		जाओ out;
	}
	अगर (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		जाओ out;
	}
	अगर ((fp = sshkey_fingerprint(कुंजी, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == शून्य)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	अगर ((r = sshkey_verify(कुंजी, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), शून्य, 0, शून्य)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(कुंजी), fp);
		जाओ out;
	}
	/* check whether sid/key already recorded */
	क्रम (i = 0; i < e->nsession_ids; i++) {
		अगर (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			जाओ out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		कुंजी_match = sshkey_equal(कुंजी, e->session_ids[i].कुंजी);
		अगर (sid_match && कुंजी_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(कुंजी), fp);
			r = 0;
			जाओ out;
		} अन्यथा अगर (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(कुंजी), fp);
			r = -1;
			जाओ out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	अगर (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		जाओ out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, माप(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(कुंजी), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].कुंजी = कुंजी;
	e->session_ids[i].forwarded = fwd != 0;
	कुंजी = शून्य; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	अगर ((e->session_ids[i].sid = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	मुक्त(fp);
	sshkey_free(कुंजी);
	sshbuf_free(sid);
	sshbuf_free(sig);
	वापस r == 0 ? 1 : 0;
}

अटल पूर्णांक
process_ext_query(SocketEntry *e)
{
	पूर्णांक r;
	काष्ठा sshbuf *संदेश = शून्य;

	debug2_f("entering");
	अगर ((संदेश = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshbuf_put_u8(संदेश, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(संदेश, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	अगर ((r = sshbuf_put_stringb(e->output, संदेश)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(संदेश);
	वापस 1;
}

अटल व्योम
process_extension(SocketEntry *e)
{
	पूर्णांक r, replied = 0, success = 0;
	अक्षर *name;

	debug2_f("entering");
	अगर ((r = sshbuf_get_cstring(e->request, &name, शून्य)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		वापस;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	अगर (म_भेद(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} अन्यथा अगर (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		जाओ generic_fail;
	} अन्यथा अगर (म_भेद(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} अन्यथा {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		मुक्त(name);
		send_status(e, 0);
		वापस;
	}
	मुक्त(name);
	/* Agent failures are signalled with a different error code */
	अगर (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
अटल पूर्णांक
process_message(u_int socknum)
{
	u_int संदेश_len;
	u_char type;
	स्थिर u_char *cp;
	पूर्णांक r;
	SocketEntry *e;

	अगर (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	अगर (sshbuf_len(e->निवेश) < 5)
		वापस 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->निवेश);
	संदेश_len = PEEK_U32(cp);
	अगर (संदेश_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, संदेश_len, AGENT_MAX_LEN);
		वापस -1;
	}
	अगर (sshbuf_len(e->निवेश) < संदेश_len + 4)
		वापस 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	अगर ((r = sshbuf_get_stringb(e->निवेश, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		अगर (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			वापस -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	अगर (locked && type != SSH_AGENTC_UNLOCK) {
		चयन (type) {
		हाल SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			अवरोध;
		हाल SSH_AGENTC_EXTENSION:
			process_extension(e);
			अवरोध;
		शेष:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		वापस 1;
	}

	चयन (type) {
	हाल SSH_AGENTC_LOCK:
	हाल SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		अवरोध;
	हाल SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		अवरोध;
	/* ssh2 */
	हाल SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		अवरोध;
	हाल SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		अवरोध;
	हाल SSH2_AGENTC_ADD_IDENTITY:
	हाल SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		अवरोध;
	हाल SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		अवरोध;
	हाल SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		अवरोध;
#अगर_घोषित ENABLE_PKCS11
	हाल SSH_AGENTC_ADD_SMARTCARD_कुंजी:
	हाल SSH_AGENTC_ADD_SMARTCARD_कुंजी_CONSTRAINED:
		process_add_smartcard_कुंजी(e);
		अवरोध;
	हाल SSH_AGENTC_REMOVE_SMARTCARD_कुंजी:
		process_remove_smartcard_कुंजी(e);
		अवरोध;
#पूर्ण_अगर /* ENABLE_PKCS11 */
	हाल SSH_AGENTC_EXTENSION:
		process_extension(e);
		अवरोध;
	शेष:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		अवरोध;
	}
	वापस 1;
}

अटल व्योम
new_socket(sock_type type, पूर्णांक fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	अगर (fd > max_fd)
		max_fd = fd;

	क्रम (i = 0; i < sockets_alloc; i++)
		अगर (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			अगर ((sockets[i].निवेश = sshbuf_new()) == शून्य ||
			    (sockets[i].output = sshbuf_new()) == शून्य ||
			    (sockets[i].request = sshbuf_new()) == शून्य)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			वापस;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    माप(sockets[0]));
	क्रम (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	अगर ((sockets[old_alloc].निवेश = sshbuf_new()) == शून्य ||
	    (sockets[old_alloc].output = sshbuf_new()) == शून्य ||
	    (sockets[old_alloc].request = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

अटल पूर्णांक
handle_socket_read(u_int socknum)
{
	काष्ठा sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	पूर्णांक fd;

	slen = माप(sunaddr);
	fd = accept(sockets[socknum].fd, (काष्ठा sockaddr *)&sunaddr, &slen);
	अगर (fd == -1) {
		error("accept from AUTH_SOCKET: %s", म_त्रुटि(त्रुटि_सं));
		वापस -1;
	}
	अगर (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		वापस -1;
	}
	अगर ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		बंद(fd);
		वापस -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	वापस 0;
}

अटल पूर्णांक
handle_conn_read(u_int socknum)
{
	अक्षर buf[AGENT_RBUF_LEN];
	ssize_t len;
	पूर्णांक r;

	अगर ((len = पढ़ो(sockets[socknum].fd, buf, माप(buf))) <= 0) {
		अगर (len == -1) {
			अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
				वापस 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, म_त्रुटि(त्रुटि_सं));
		}
		वापस -1;
	}
	अगर ((r = sshbuf_put(sockets[socknum].निवेश, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, माप(buf));
	क्रम (;;) {
		अगर ((r = process_message(socknum)) == -1)
			वापस -1;
		अन्यथा अगर (r == 0)
			अवरोध;
	}
	वापस 0;
}

अटल पूर्णांक
handle_conn_write(u_int socknum)
{
	ssize_t len;
	पूर्णांक r;

	अगर (sshbuf_len(sockets[socknum].output) == 0)
		वापस 0; /* shouldn't happen */
	अगर ((len = ग_लिखो(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		अगर (len == -1) {
			अगर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
				वापस 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, म_त्रुटि(त्रुटि_सं));
		}
		वापस -1;
	}
	अगर ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	वापस 0;
}

अटल व्योम
after_poll(काष्ठा pollfd *pfd, माप_प्रकार npfd, u_int maxfds)
{
	माप_प्रकार i;
	u_int socknum, activefds = npfd;

	क्रम (i = 0; i < npfd; i++) {
		अगर (pfd[i].revents == 0)
			जारी;
		/* Find sockets entry */
		क्रम (socknum = 0; socknum < sockets_alloc; socknum++) {
			अगर (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				जारी;
			अगर (pfd[i].fd == sockets[socknum].fd)
				अवरोध;
		}
		अगर (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			जारी;
		}
		/* Process events */
		चयन (sockets[socknum].type) {
		हाल AUTH_SOCKET:
			अगर ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				अवरोध;
			अगर (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				अवरोध;
			}
			अगर (handle_socket_read(socknum) == 0)
				activefds++;
			अवरोध;
		हाल AUTH_CONNECTION:
			अगर ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				जाओ close_sock;
			अगर ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				अगर (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				अवरोध;
			}
			अवरोध;
		शेष:
			अवरोध;
		}
	}
}

अटल पूर्णांक
prepare_poll(काष्ठा pollfd **pfdp, माप_प्रकार *npfdp, काष्ठा timespec *timeoutp, u_int maxfds)
{
	काष्ठा pollfd *pfd = *pfdp;
	माप_प्रकार i, j, npfd = 0;
	समय_प्रकार deadline;
	पूर्णांक r;

	/* Count active sockets */
	क्रम (i = 0; i < sockets_alloc; i++) {
		चयन (sockets[i].type) {
		हाल AUTH_SOCKET:
		हाल AUTH_CONNECTION:
			npfd++;
			अवरोध;
		हाल AUTH_UNUSED:
			अवरोध;
		शेष:
			fatal("Unknown socket type %d", sockets[i].type);
			अवरोध;
		}
	}
	अगर (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, माप(*pfd))) == शून्य)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	क्रम (i = j = 0; i < sockets_alloc; i++) {
		चयन (sockets[i].type) {
		हाल AUTH_SOCKET:
			अगर (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				अवरोध;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			अवरोध;
		हाल AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			अगर ((r = sshbuf_check_reserve(sockets[i].निवेश,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			अन्यथा अगर (r != SSH_ERR_NO_बफर_SPACE)
				fatal_fr(r, "reserve");
			अगर (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			अवरोध;
		शेष:
			अवरोध;
		}
	}
	deadline = reaper();
	अगर (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	अगर (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	वापस (1);
}

अटल व्योम
cleanup_socket(व्योम)
{
	अगर (cleanup_pid != 0 && getpid() != cleanup_pid)
		वापस;
	debug_f("cleanup");
	अगर (socket_name != शून्य) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		मुक्त(socket_name);
		socket_name = शून्य;
		मुक्त(socket_dir);
		socket_dir = शून्य;
	}
}

व्योम
cleanup_exit(पूर्णांक i)
{
	cleanup_socket();
#अगर_घोषित ENABLE_PKCS11
	pkcs11_terminate();
#पूर्ण_अगर
	_निकास(i);
}

अटल व्योम
cleanup_handler(पूर्णांक sig)
{
	signalled_exit = sig;
}

अटल व्योम
keydrop_handler(पूर्णांक sig)
{
	signalled_keydrop = sig;
}

अटल व्योम
check_parent_exists(व्योम)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	अगर (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_निकास(2);
	}
}

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि,
	    "usage: ssh-agent [-c | -s] [-DdU] [-T | -A directory | -a bind_address]\n"
	    "                 [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life]\n"
	    "       ssh-agent [-U] [-T | -A directory | -a bind_address]\n"
	    "                 [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life] command [arg ...]\n"
	    "       ssh-agent [-c | -s] -k\n"
	    "       ssh-agent -u\n"
	    "       ssh-agent -V\n");
	निकास(1);
}

पूर्णांक
मुख्य(पूर्णांक ac, अक्षर **av)
{
	पूर्णांक c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	पूर्णांक s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	पूर्णांक sock = -1, ch, परिणाम, saved_errno;
	pid_t pid;
 	अक्षर *homedir = शून्य, *shell, *format, *pidstr, *agentsocket = शून्य;
	अक्षर *cp, pidstrbuf[1 + 3 * माप pid];
	अक्षर *fdstr;
	स्थिर अक्षर *errstr = शून्य;
	स्थिर अक्षर *ccp;
#अगर_घोषित HAVE_SETRLIMIT
	काष्ठा rlimit rlim;
#पूर्ण_अगर
	बाह्य पूर्णांक optind;
	बाह्य अक्षर *optarg;
	माप_प्रकार len;
	mode_t पूर्व_mask;
	काष्ठा timespec timeout;
	काष्ठा pollfd *pfd = शून्य;
	माप_प्रकार npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	पूर्णांक socket_activated = 0;
	काष्ठा passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(व्योम)setegid(getgid());
	(व्योम)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	अगर ((pw = getpwuid(getuid())) == शून्य)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#अगर_घोषित RLIMIT_NOFILE
	अगर (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	जबतक ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		चयन (ch) {
		हाल 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			अगर (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			अवरोध;
		हाल 'c':
			अगर (s_flag)
				usage();
			c_flag++;
			अवरोध;
		हाल 'k':
			k_flag++;
			अवरोध;
		हाल 'O':
			अगर (म_भेद(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			अन्यथा अगर (म_भेद(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			अन्यथा अगर ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != शून्य) {
				अगर (websafe_allowlist != शून्य)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} अन्यथा
				fatal("Unknown -O option");
			अवरोध;
		हाल 'P':
			अगर (allowed_providers != शून्य)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			अवरोध;
		हाल 's':
			अगर (c_flag)
				usage();
			s_flag++;
			अवरोध;
		हाल 'd':
			अगर (d_flag || D_flag)
				usage();
			d_flag++;
			अवरोध;
		हाल 'D':
			अगर (d_flag || D_flag)
				usage();
			D_flag++;
			अवरोध;
		हाल 'a':
			agentsocket = optarg;
			अवरोध;
		हाल 'A':
			socket_dirspec = xstrdup(optarg);
			अवरोध;
		हाल 't':
			अगर ((lifetime = convtime(optarg)) == -1) {
				ख_लिखो(मानक_त्रुटि, "Invalid lifetime\n");
				usage();
			}
			अवरोध;
		हाल 'T':
			T_flag++;
			अवरोध;
		हाल 'u':
			u_flag++;
			अवरोध;
		हाल 'U':
			U_flag++;
			अवरोध;
		हाल 'V':
			ख_लिखो(मानक_त्रुटि, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			निकास(0);
		शेष:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	अगर (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	अगर (((socket_dirspec != शून्य) + (agentsocket != शून्य) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	अगर (allowed_providers == शून्य)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	अगर (websafe_allowlist == शून्य)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	अगर (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	अन्यथा अगर (socket_dirspec == शून्य && agentsocket == शून्य)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	अगर (ac == 0 && !c_flag && !s_flag) {
		shell = दो_पर्या("SHELL");
		अगर (shell != शून्य && (len = म_माप(shell)) > 2 &&
		    म_भेदन(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	अगर (k_flag) {
		pidstr = दो_पर्या(SSH_AGENTPID_ENV_NAME);
		अगर (pidstr == शून्य) {
			ख_लिखो(मानक_त्रुटि, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			निकास(1);
		}
		pid = (पूर्णांक)strtonum(pidstr, 2, पूर्णांक_उच्च, &errstr);
		अगर (errstr) {
			ख_लिखो(मानक_त्रुटि,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			निकास(1);
		}
		अगर (समाप्त(pid, संक_इति) == -1) {
			लिखो_त्रुटि("kill");
			निकास(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		म_लिखो(format, SSH_AUTHSOCKET_ENV_NAME);
		म_लिखो(format, SSH_AGENTPID_ENV_NAME);
		म_लिखो("echo Agent pid %ld killed;\n", (दीर्घ)pid);
		निकास(0);
	}
	अगर (u_flag) {
		अगर ((homedir = get_homedir()) == शून्य)
			fatal("Couldn't determine home directory");
		agent_cleanup_stale(socket_dirspec,
		    pw->pw_name, pw->pw_uid, homedir, u_flag > 1);
		म_लिखो("Deleted stale agent sockets in ~/%s\n",
		    _PATH_SSH_AGENT_SOCKET_DIR);
		निकास(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#घोषणा SSH_AGENT_MIN_FDS (3+1+1+1+4)
	अगर (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (दीर्घ दीर्घ)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	अगर (agentsocket == शून्य && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = दो_पर्या("LISTEN_PID")) != शून्य &&
	    (fdstr = दो_पर्या("LISTEN_FDS")) != शून्य) {
		अगर (म_भेद(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		अगर (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (पूर्णांक)strtonum(pidstr, 1, पूर्णांक_उच्च, &errstr);
		अगर (errstr != शून्य)
			fatal("invalid LISTEN_PID: %s", errstr);
		अगर (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	अगर (sock == -1 && agentsocket == शून्य) {
		/* Listen on a socket in/under a given directory */
		अगर ((homedir = get_homedir()) == शून्य)
			fatal("Couldn't determine home directory");
		अगर (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		अगर (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		मुक्त(homedir);
	} अन्यथा अगर (sock == -1) {
		/* Listen on explicit socket path */
		पूर्व_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		अगर ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			मुक्त(socket_name);
			socket_name = शून्य; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(पूर्व_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	अगर (sock == -1) {
		पूर्व_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		अगर (sock < 0) {
			/* XXX - unix_listener() calls error() not perror() */
			*socket_name = '\0'; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(पूर्व_mask);
	}

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	अगर (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		अगर (socket_name != शून्य) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			म_लिखो(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			मुक्त(cp);
			म_लिखो("echo Agent pid %ld;\n", (दीर्घ)parent_pid);
			ख_साफ(मानक_निकास);
		}
		जाओ skip;
	}
	pid = विभाजन();
	अगर (pid == -1) {
		लिखो_त्रुटि("fork");
		cleanup_exit(1);
	}
	अगर (pid != 0) {		/* Parent - execute the given command. */
		बंद(sock);
		snprintf(pidstrbuf, माप pidstrbuf, "%ld", (दीर्घ)pid);
		अगर (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			cp = argv_assemble(1, &socket_name);
			म_लिखो(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			म_लिखो(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			मुक्त(cp);
			म_लिखो("echo Agent pid %ld;\n", (दीर्घ)pid);
			निकास(0);
		}
		अगर (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			लिखो_त्रुटि("setenv");
			निकास(1);
		}
		execvp(av[0], av);
		लिखो_त्रुटि(av[0]);
		निकास(1);
	}
	/* child */
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	अगर (setsid() == -1) {
		error("setsid: %s", म_त्रुटि(त्रुटि_सं));
		cleanup_exit(1);
	}

	(व्योम)स_बदलो("/");
	अगर (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#अगर_घोषित HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	अगर (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", म_त्रुटि(त्रुटि_सं));
		cleanup_exit(1);
	}
#पूर्ण_अगर

skip:

	cleanup_pid = getpid();

#अगर_घोषित ENABLE_PKCS11
	pkcs11_init(0);
#पूर्ण_अगर
	new_socket(AUTH_SOCKET, sock);
	अगर (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
	ssh_signal(SIGPIPE, संक_छोड़ो);
	ssh_signal(संक_विघ्न, (d_flag | D_flag) ? cleanup_handler : संक_छोड़ो);
	ssh_signal(SIGHUP, cleanup_handler);
	ssh_signal(संक_इति, cleanup_handler);
	ssh_signal(SIGUSR1, keydrop_handler);

	sigemptyset(&nsigset);
	sigaddset(&nsigset, संक_विघ्न);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, संक_इति);
	sigaddset(&nsigset, SIGUSR1);

	अगर (socket_name != शून्य && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    म_त्रुटि(त्रुटि_सं));
	}
	अगर (socket_dir != शून्य && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    म_त्रुटि(त्रुटि_सं));
	}
	अगर (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, म_त्रुटि(त्रुटि_सं));
	अगर ((ccp = दो_पर्या("SSH_SK_HELPER")) == शून्य || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	अगर (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, म_त्रुटि(त्रुटि_सं));
	अगर ((ccp = दो_पर्या("SSH_PKCS11_HELPER")) == शून्य || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	अगर (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, म_त्रुटि(त्रुटि_सं));
	अगर ((ccp = दो_पर्या("SSH_ASKPASS")) == शून्य || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	अगर (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, म_त्रुटि(त्रुटि_सं));
	अगर (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, म_त्रुटि(त्रुटि_सं));
	अगर (pledge("stdio rpath cpath wpath unix id proc exec", शून्य) == -1)
		fatal("%s: pledge: %s", __progname, म_त्रुटि(त्रुटि_सं));
	platform_pledge_agent();

	जबतक (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		अगर (signalled_exit != 0) {
			logit("exiting on signal %d", (पूर्णांक)signalled_exit);
			cleanup_exit((signalled_exit == संक_इति &&
			    socket_activated) ? 0 : 2);
		}
		अगर (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (पूर्णांक)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		परिणाम = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, शून्य);
		saved_errno = त्रुटि_सं;
		अगर (parent_alive_interval != 0)
			check_parent_exists();
		(व्योम) reaper();	/* remove expired keys */
		अगर (परिणाम == -1) {
			अगर (saved_errno == EINTR)
				जारी;
			fatal("poll: %s", म_त्रुटि(saved_errno));
		} अन्यथा अगर (परिणाम > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
