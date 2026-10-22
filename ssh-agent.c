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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/resource.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/un.h>
#अन्तर्भाव <sys/wait.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#endif

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <util.h>
#अन्तर्भाव <pwd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "ssh-pkcs11.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "version.h"

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

प्रकारव्याख्या गणना {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

संरचना hostkey_sid {
	संरचना sshkey *किल्ली;
	संरचना sshbuf *sid;
	पूर्णांक forwarded;
};

प्रकारव्याख्या संरचना socket_entry {
	पूर्णांक fd;
	sock_type type;
	संरचना sshbuf *आदान;
	संरचना sshbuf *output;
	संरचना sshbuf *request;
	माप_प्रकार nsession_ids;
	संरचना hostkey_sid *session_ids;
	पूर्णांक session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = रिक्त;

प्रकारव्याख्या संरचना identity {
	TAILQ_ENTRY(identity) next;
	संरचना sshkey *किल्ली;
	अक्षर *comment;
	अक्षर *provider;
	समय_प्रकार death;
	u_int confirm;
	अक्षर *sk_provider;
	संरचना dest_constraint *dest_constraints;
	माप_प्रकार ndest_constraints;
} Identity;

संरचना idtable {
	पूर्णांक nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
संरचना idtable *idtab;

पूर्णांक max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
समय_प्रकार parent_alive_interval = 0;

स्थिर संक_पूर्ण_प्रकार signalled_exit;
स्थिर संक_पूर्ण_प्रकार signalled_keydrop;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
स्थिर अक्षर *socket_name;
स्थिर अक्षर *socket_dir;
स्थिर अक्षर *socket_dirspec;

/* Pattern-list of allowed PKCS#11/Security key paths */
स्थिर अक्षर *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
स्थिर पूर्णांक remote_add_provider;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
पूर्णांक locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

बाह्य अक्षर *__progname;

/* Default lifetime in seconds (0 == forever) */
स्थिर पूर्णांक lifetime = 0;

स्थिर पूर्णांक fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
स्थिर पूर्णांक restrict_websafe = 1;
स्थिर अक्षर *websafe_allowlist;

स्थिर शून्य
close_socket(SocketEntry *e)
{
	माप_प्रकार i;

	बंद(e->fd);
	sshbuf_free(e->आदान);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	साठी (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].किल्ली);
		sshbuf_free(e->session_ids[i].sid);
	}
	मुक्त(e->session_ids);
	स_रखो(e, '\0', आकार(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

स्थिर शून्य
idtab_init(शून्य)
{
	idtab = xcalloc(1, आकार(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

स्थिर शून्य
free_dest_constraint_hop(संरचना dest_constraint_hop *dch)
{
	u_int i;

	जर (dch == रिक्त)
		परत;
	मुक्त(dch->user);
	मुक्त(dch->hostname);
	साठी (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->किल्ल्या[i]);
	मुक्त(dch->किल्ल्या);
	मुक्त(dch->किल्ली_is_ca);
}

स्थिर शून्य
free_dest_constraints(संरचना dest_constraint *dcs, माप_प्रकार ndcs)
{
	माप_प्रकार i;

	साठी (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	मुक्त(dcs);
}

#ifdef ENABLE_PKCS11
स्थिर शून्य
dup_dest_constraint_hop(स्थिरांक संरचना dest_constraint_hop *dch,
    संरचना dest_constraint_hop *out)
{
	u_int i;
	पूर्णांक r;

	out->user = dch->user == रिक्त ? रिक्त : xstrdup(dch->user);
	out->hostname = dch->hostname == रिक्त ? रिक्त : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->किल्ल्या = out->nkeys == 0 ? रिक्त :
	    xcalloc(out->nkeys, आकार(*out->किल्ल्या));
	out->किल्ली_is_ca = out->nkeys == 0 ? रिक्त :
	    xcalloc(out->nkeys, आकार(*out->किल्ली_is_ca));
	साठी (i = 0; i < dch->nkeys; i++) {
		जर (dch->किल्ल्या[i] != रिक्त &&
		    (r = sshkey_from_private(dch->किल्ल्या[i],
		    &(out->किल्ल्या[i]))) != 0)
			fatal_fr(r, "copy key");
		out->किल्ली_is_ca[i] = dch->किल्ली_is_ca[i];
	}
}

स्थिर संरचना dest_constraint *
dup_dest_constraints(स्थिरांक संरचना dest_constraint *dcs, माप_प्रकार ndcs)
{
	माप_प्रकार i;
	संरचना dest_constraint *ret;

	जर (ndcs == 0)
		परत रिक्त;
	ret = xcalloc(ndcs, आकार(*ret));
	साठी (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	परत ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
स्थिर शून्य
dump_dest_constraint_hop(स्थिरांक संरचना dest_constraint_hop *dch)
{
	u_int i;
	अक्षर *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == रिक्त ? "(null)" : dch->user,
	    dch->hostname == रिक्त ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	साठी (i = 0; i < dch->nkeys; i++) {
		fp = रिक्त;
		जर (dch->किल्ल्या[i] != रिक्त &&
		    (fp = sshkey_fingerprint(dch->किल्ल्या[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->किल्ल्या[i] == रिक्त ? "" : sshkey_ssh_name(dch->किल्ल्या[i]),
		    dch->किल्ल्या[i] == रिक्त ? "" : " ",
		    dch->किल्ल्या[i] == रिक्त ? "none" : fp,
		    dch->किल्ली_is_ca[i]);
		मुक्त(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

स्थिर शून्य
dump_dest_constraints(स्थिरांक अक्षर *context,
    स्थिरांक संरचना dest_constraint *dcs, माप_प्रकार ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	माप_प्रकार i;

	debug_f("%s: %zu constraints", context, ndcs);
	साठी (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

स्थिर शून्य
free_identity(Identity *id)
{
	sshkey_free(id->किल्ली);
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
स्थिर पूर्णांक
match_किल्ली_hop(स्थिरांक अक्षर *tag, स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक संरचना dest_constraint_hop *dch)
{
	स्थिरांक अक्षर *reason = रिक्त;
	स्थिरांक अक्षर *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	अक्षर *fp;

	जर (किल्ली == रिक्त)
		परत -1;
	/* XXX logspam */
	जर ((fp = sshkey_fingerprint(किल्ली, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(किल्ली), fp, dch->nkeys);
	मुक्त(fp);
	साठी (i = 0; i < dch->nkeys; i++) {
		जर (dch->किल्ल्या[i] == रिक्त)
			परत -1;
		/* XXX logspam */
		जर ((fp = sshkey_fingerprint(dch->किल्ल्या[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->किल्ली_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->किल्ल्या[i]), fp);
		मुक्त(fp);
		जर (!sshkey_is_cert(किल्ली)) {
			/* plain key */
			जर (dch->किल्ली_is_ca[i] ||
			    !sshkey_equal(किल्ली, dch->किल्ल्या[i]))
				सुरूठेवा;
			परत 0;
		}
		/* certificate */
		जर (!dch->किल्ली_is_ca[i])
			सुरूठेवा;
		जर (किल्ली->cert == रिक्त || किल्ली->cert->signature_किल्ली == रिक्त)
			परत -1; /* shouldn't happen */
		जर (!sshkey_equal(किल्ली->cert->signature_किल्ली, dch->किल्ल्या[i]))
			सुरूठेवा;
		जर (sshkey_cert_check_host(किल्ली, hostname,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    किल्ली->cert->किल्ली_id, hostname, reason);
			सुरूठेवा;
		}
		परत 0;
	}
	परत -1;
}

/* Check destination constraints on an identity against the hostkey/user */
स्थिर पूर्णांक
permitted_by_dest_constraints(स्थिरांक संरचना sshkey *fromkey,
    स्थिरांक संरचना sshkey *tokey, Identity *id, स्थिरांक अक्षर *user,
    स्थिरांक अक्षर **hostnamep)
{
	माप_प्रकार i;
	संरचना dest_constraint *d;

	जर (hostnamep != रिक्त)
		*hostnamep = रिक्त;
	साठी (i = 0; i < id->ndest_constraints; i++) {
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
		जर (fromkey == रिक्त) {
			/* We are matching the first hop */
			जर (d->from.hostname != रिक्त || d->from.nkeys != 0)
				सुरूठेवा;
		} अन्यथा जर (match_किल्ली_hop("from", fromkey, &d->from) != 0)
			सुरूठेवा;

		/* Match 'to' key */
		जर (tokey != रिक्त && match_किल्ली_hop("to", tokey, &d->to) != 0)
			सुरूठेवा;

		/* Match user if specified */
		जर (d->to.user != रिक्त && user != रिक्त &&
		    !match_pattern(user, d->to.user))
			सुरूठेवा;

		/* successfully matched this constraint */
		जर (hostnamep != रिक्त)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == रिक्त ? "*" : d->to.hostname);
		परत 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->किल्ली), id->comment);
	परत -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
स्थिर पूर्णांक
identity_permitted(Identity *id, SocketEntry *e, अक्षर *user,
    स्थिरांक अक्षर **forward_hostnamep, स्थिरांक अक्षर **last_hostnamep)
{
	माप_प्रकार i;
	स्थिरांक अक्षर **hp;
	संरचना hostkey_sid *hks;
	स्थिरांक संरचना sshkey *fromkey = रिक्त;
	स्थिरांक अक्षर *test_user;
	अक्षर *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->किल्ली), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	जर (id->ndest_constraints == 0)
		परत 0; /* unconstrained */
	जर (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		परत -1;
	}
	जर (e->nsession_ids == 0)
		परत 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	साठी (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		जर (hks->किल्ली == रिक्त)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = रिक्त;
		जर (fromkey != रिक्त &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		जर ((fp2 = sshkey_fingerprint(hks->किल्ली, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->किल्ली), fp2);
		मुक्त(fp1);
		मुक्त(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = रिक्त;
		जर (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		अन्यथा जर (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = रिक्त;
		जर (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			जर (hks->forwarded && user != रिक्त) {
				error_f("tried to sign on forwarding hop");
				परत -1;
			}
		} अन्यथा जर (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			परत -1;
		}
		जर (permitted_by_dest_constraints(fromkey, hks->किल्ली, id,
		    test_user, hp) != 0)
			परत -1;
		fromkey = hks->किल्ली;
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
	जर (hks->forwarded && user == रिक्त &&
	    permitted_by_dest_constraints(hks->किल्ली, रिक्त, id,
	    रिक्त, रिक्त) != 0) {
		debug3_f("key permitted at host but not after");
		परत -1;
	}

	/* success */
	परत 0;
}

स्थिर पूर्णांक
socket_is_remote(SocketEntry *e)
{
	परत e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
स्थिर Identity *
lookup_identity(संरचना sshkey *किल्ली)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		जर (sshkey_equal(किल्ली, id->किल्ली))
			परत (id);
	}
	परत (रिक्त);
}

/* Check confirmation of keysign request */
स्थिर पूर्णांक
confirm_किल्ली(Identity *id, स्थिरांक अक्षर *extra)
{
	अक्षर *p;
	पूर्णांक ret = -1;

	p = sshkey_fingerprint(id->किल्ली, fingerprint_hash, SSH_FP_DEFAULT);
	जर (p != रिक्त &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == रिक्त ? "" : "\n", extra == रिक्त ? "" : extra))
		ret = 0;
	मुक्त(p);

	परत (ret);
}

स्थिर शून्य
send_status_generic(SocketEntry *e, u_int code)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, code)) != 0)
		fatal_fr(r, "compose");
}

स्थिर शून्य
send_status(SocketEntry *e, पूर्णांक success)
{
	send_status_generic(e,
	    success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
}

/* send list of supported public keys to 'client' */
स्थिर शून्य
process_request_identities(SocketEntry *e)
{
	Identity *id;
	संरचना sshbuf *संदेश, *किल्ल्या;
	पूर्णांक r;
	u_int i = 0, nentries = 0;
	अक्षर *fp;

	debug2_f("entering");

	जर ((संदेश = sshbuf_new()) == रिक्त || (किल्ल्या = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		जर ((fp = sshkey_fingerprint(id->किल्ली, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->किल्ली), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		मुक्त(fp);
		/* identity not visible, don't include in response */
		जर (identity_permitted(id, e, रिक्त, रिक्त, रिक्त) != 0)
			सुरूठेवा;
		जर ((r = sshkey_puts(id->किल्ली, किल्ल्या)) != 0 ||
		    (r = sshbuf_put_cstring(किल्ल्या, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			सुरूठेवा;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	जर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, nentries)) != 0 ||
	    (r = sshbuf_putb(संदेश, किल्ल्या)) != 0)
		fatal_fr(r, "compose");
	जर ((r = sshbuf_put_stringb(e->output, संदेश)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(संदेश);
	sshbuf_free(किल्ल्या);
}


स्थिर अक्षर *
agent_decode_alg(संरचना sshkey *किल्ली, u_int flags)
{
	जर (किल्ली->type == किल्ली_RSA) {
		जर (flags & SSH_AGENT_RSA_SHA2_256)
			परत "rsa-sha2-256";
		अन्यथा जर (flags & SSH_AGENT_RSA_SHA2_512)
			परत "rsa-sha2-512";
	} अन्यथा जर (किल्ली->type == किल्ली_RSA_CERT) {
		जर (flags & SSH_AGENT_RSA_SHA2_256)
			परत "rsa-sha2-256-cert-v01@openssh.com";
		अन्यथा जर (flags & SSH_AGENT_RSA_SHA2_512)
			परत "rsa-sha2-512-cert-v01@openssh.com";
	}
	परत रिक्त;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
स्थिर पूर्णांक
parse_userauth_request(संरचना sshbuf *संदेश, स्थिरांक संरचना sshkey *expected_किल्ली,
    अक्षर **userp, संरचना sshbuf **sess_idp, संरचना sshkey **hostkeyp)
{
	संरचना sshbuf *b = रिक्त, *sess_id = रिक्त;
	अक्षर *user = रिक्त, *service = रिक्त, *method = रिक्त, *pkalg = रिक्त;
	पूर्णांक r;
	u_char t, sig_follows;
	संरचना sshkey *mkey = रिक्त, *hostkey = रिक्त;

	जर (userp != रिक्त)
		*userp = रिक्त;
	जर (sess_idp != रिक्त)
		*sess_idp = रिक्त;
	जर (hostkeyp != रिक्त)
		*hostkeyp = रिक्त;
	जर ((b = sshbuf_fromb(संदेश)) == रिक्त)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	जर ((r = sshbuf_froms(b, &sess_id)) != 0)
		जा out;
	जर (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, रिक्त)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, रिक्त)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, रिक्त)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, रिक्त)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /*किल्ली*/
		जा out;
	जर (t != SSH2_संदेश_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    म_भेद(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_किल्ली, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_किल्ली->type) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (म_भेद(method, "publickey-hostbound-v00@openssh.com") == 0) {
		जर ((r = sshkey_froms(b, &hostkey)) != 0)
			जा out;
	} अन्यथा जर (म_भेद(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	जर (userp != रिक्त) {
		*userp = user;
		user = रिक्त;
	}
	जर (sess_idp != रिक्त) {
		*sess_idp = sess_id;
		sess_id = रिक्त;
	}
	जर (hostkeyp != रिक्त) {
		*hostkeyp = hostkey;
		hostkey = रिक्त;
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
	परत r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
स्थिर पूर्णांक
parse_sshsig_request(संरचना sshbuf *संदेश)
{
	पूर्णांक r;
	संरचना sshbuf *b;

	जर ((b = sshbuf_fromb(संदेश)) == रिक्त)
		fatal_f("sshbuf_fromb");

	जर ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, रिक्त, रिक्त)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, रिक्त, रिक्त)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, रिक्त, रिक्त)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, रिक्त, रिक्त)) != 0) /* H(msg) */
		जा out;
	जर (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	परत r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
स्थिर पूर्णांक
check_websafe_message_contents(संरचना sshkey *किल्ली, संरचना sshbuf *data)
{
	जर (parse_userauth_request(data, किल्ली, रिक्त, रिक्त, रिक्त) == 0) {
		debug_f("signed data matches public key userauth request");
		परत 1;
	}
	जर (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		परत 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	परत 0;
}

स्थिर पूर्णांक
buf_equal(स्थिरांक संरचना sshbuf *a, स्थिरांक संरचना sshbuf *b)
{
	जर (sshbuf_ptr(a) == रिक्त || sshbuf_ptr(b) == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (sshbuf_len(a) != sshbuf_len(b))
		परत SSH_ERR_INVALID_FORMAT;
	जर (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		परत SSH_ERR_INVALID_FORMAT;
	परत 0;
}

/* ssh2 only */
स्थिर शून्य
process_sign_request2(SocketEntry *e)
{
	u_char *signature = रिक्त;
	माप_प्रकार slen = 0;
	u_int compat = 0, flags;
	पूर्णांक r, ok = -1, retried = 0;
	अक्षर *fp = रिक्त, *pin = रिक्त, *prompt = रिक्त;
	अक्षर *user = रिक्त, *sig_dest = रिक्त;
	स्थिरांक अक्षर *fwd_host = रिक्त, *dest_host = रिक्त;
	संरचना sshbuf *संदेश = रिक्त, *data = रिक्त, *sid = रिक्त;
	संरचना sshkey *किल्ली = रिक्त, *hostkey = रिक्त;
	संरचना identity *id;
	संरचना notifier_ctx *notifier = रिक्त;

	debug_f("entering");

	जर ((संदेश = sshbuf_new()) == रिक्त || (data = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshkey_froms(e->request, &किल्ली)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		जा send;
	}

	जर ((id = lookup_identity(किल्ली)) == रिक्त) {
		verbose_f("%s key not found", sshkey_type(किल्ली));
		जा send;
	}
	जर ((fp = sshkey_fingerprint(किल्ली, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("fingerprint failed");

	जर (id->ndest_constraints != 0) {
		जर (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			जा send;
		}
		जर (parse_userauth_request(data, किल्ली, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			जा send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		जर (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			जा send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		जर (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->किल्ली), fp);
			जा send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		जर (e->nsession_ids > 1 && hostkey == रिक्त) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			जा send;
		}
		जर (hostkey != रिक्त && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].किल्ली)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			जा send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	जर (id->confirm && confirm_किल्ली(id, sig_dest) != 0) {
		verbose_f("user refused key");
		जा send;
	}
	जर (sshkey_is_sk(id->किल्ली)) {
		जर (restrict_websafe &&
		    match_pattern_list(id->किल्ली->sk_application,
		    websafe_allowlist, 0) != 1 &&
		    !check_websafe_message_contents(किल्ली, data)) {
			/* error already logged */
			जा send;
		}
		जर (id->किल्ली->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->किल्ली), fp,
			    sig_dest == रिक्त ? "" : "\n",
			    sig_dest == रिक्त ? "" : sig_dest);
		}
	}
 retry_pin:
	जर ((r = sshkey_sign(id->किल्ली, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(किल्ली, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		जर (pin == रिक्त && !retried && sshkey_is_sk(id->किल्ली) &&
		    r == SSH_ERR_किल्ली_WRONG_PASSPHRASE) {
			notify_complete(notifier, रिक्त);
			notifier = रिक्त;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->किल्ली->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->किल्ली), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			जा retry_pin;
		}
		error_fr(r, "sshkey_sign");
		जा send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	जर (ok == 0) {
		जर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(संदेश, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} अन्यथा जर ((r = sshbuf_put_u8(संदेश, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	जर ((r = sshbuf_put_stringb(e->output, संदेश)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(संदेश);
	sshkey_free(किल्ली);
	sshkey_free(hostkey);
	मुक्त(fp);
	मुक्त(signature);
	मुक्त(sig_dest);
	मुक्त(user);
	मुक्त(prompt);
	जर (pin != रिक्त)
		freezero(pin, म_माप(pin));
}

/* shared */
स्थिर शून्य
process_remove_identity(SocketEntry *e)
{
	पूर्णांक r, success = 0;
	संरचना sshkey *किल्ली = रिक्त;
	Identity *id;

	debug2_f("entering");
	जर ((r = sshkey_froms(e->request, &किल्ली)) != 0) {
		error_fr(r, "parse key");
		जा done;
	}
	जर ((id = lookup_identity(किल्ली)) == रिक्त) {
		debug_f("key not found");
		जा done;
	}
	/* identity not visible, cannot be removed */
	जर (identity_permitted(id, e, रिक्त, रिक्त, रिक्त) != 0)
		जा done; /* error already logged */
	/* We have this key, free it. */
	जर (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(किल्ली);
	send_status(e, success);
}

स्थिर शून्य
remove_all_identities(शून्य)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	साठी (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;
}

स्थिर शून्य
process_remove_all_identities(SocketEntry *e)
{
	remove_all_identities();

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
स्थिर समय_प्रकार
reaper(शून्य)
{
	समय_प्रकार deadline = 0, now = monotime();
	Identity *id, *nxt;

	साठी (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		जर (id->death == 0)
			सुरूठेवा;
		जर (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} अन्यथा
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	जर (deadline == 0 || deadline <= now)
		परत 0;
	अन्यथा
		परत (deadline - now);
}

स्थिर पूर्णांक
parse_dest_constraint_hop(संरचना sshbuf *b, संरचना dest_constraint_hop *dch)
{
	u_char किल्ली_is_ca;
	माप_प्रकार elen = 0, userlen = 0;
	पूर्णांक r;
	संरचना sshkey *k = रिक्त;
	अक्षर *fp;

	स_रखो(dch, '\0', आकार(*dch));
	जर ((r = sshbuf_get_cstring(b, &dch->user, &userlen)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(b, रिक्त, &elen)) != 0) {
		error_fr(r, "parse");
		जा out;
	}
	जर (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		जा out;
	}
	जर (*dch->hostname == '\0') {
		मुक्त(dch->hostname);
		dch->hostname = रिक्त;
	}
	जर (*dch->user == '\0') {
		मुक्त(dch->user);
		dch->user = रिक्त;
	} अन्यथा जर (userlen > AGENT_USER_CONSTRAINT_MAX_LEN) {
		error_f("user match pattern too long");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	पर्यंत (sshbuf_len(b) != 0) {
		dch->किल्ल्या = xrecallocarray(dch->किल्ल्या, dch->nkeys,
		    dch->nkeys + 1, आकार(*dch->किल्ल्या));
		dch->किल्ली_is_ca = xrecallocarray(dch->किल्ली_is_ca, dch->nkeys,
		    dch->nkeys + 1, आकार(*dch->किल्ली_is_ca));
		जर ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &किल्ली_is_ca)) != 0)
			जा out;
		जर ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == रिक्त ? "" : dch->user,
		    dch->user == रिक्त ? "" : "@",
		    dch->hostname, किल्ली_is_ca ? "CA " : "", sshkey_type(k), fp);
		मुक्त(fp);
		dch->किल्ल्या[dch->nkeys] = k;
		dch->किल्ली_is_ca[dch->nkeys] = किल्ली_is_ca != 0;
		dch->nkeys++;
		k = रिक्त; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	परत r;
}

स्थिर पूर्णांक
parse_dest_constraint(संरचना sshbuf *m, संरचना dest_constraint *dc)
{
	संरचना sshbuf *b = रिक्त, *frombuf = रिक्त, *tobuf = रिक्त;
	पूर्णांक r;
	माप_प्रकार elen = 0;

	debug3_f("entering");

	स_रखो(dc, '\0', आकार(*dc));
	जर ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, रिक्त, &elen)) != 0) {
		error_fr(r, "parse");
		जा out;
	}
	जर ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		जा out; /* already logged */
	जर (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		जा out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	जर ((dc->from.hostname == रिक्त) != (dc->from.nkeys == 0) ||
	    dc->from.user != रिक्त) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (dc->to.hostname == रिक्त || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	परत r;
}

स्थिर पूर्णांक
parse_किल्ली_constraint_extension(संरचना sshbuf *m, अक्षर **sk_providerp,
    संरचना dest_constraint **dcsp, माप_प्रकार *ndcsp, पूर्णांक *cert_onlyp,
    संरचना sshkey ***certs, माप_प्रकार *ncerts)
{
	अक्षर *ext_name = रिक्त;
	पूर्णांक r;
	संरचना sshbuf *b = रिक्त;
	u_char v;
	संरचना sshkey *k;

	जर ((r = sshbuf_get_cstring(m, &ext_name, रिक्त)) != 0) {
		error_fr(r, "parse constraint extension");
		जा out;
	}
	debug_f("constraint ext %s", ext_name);
	जर (म_भेद(ext_name, "sk-provider@openssh.com") == 0) {
		जर (sk_providerp == रिक्त) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		जर (*sk_providerp != रिक्त) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		जर ((r = sshbuf_get_cstring(m, sk_providerp, रिक्त)) != 0) {
			error_fr(r, "parse %s", ext_name);
			जा out;
		}
	} अन्यथा जर (म_भेद(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		जर (*dcsp != रिक्त) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		जर ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			जा out;
		}
		पर्यंत (sshbuf_len(b) != 0) {
			जर (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				जा out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    आकार(**dcsp));
			जर ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				जा out; /* error already logged */
		}
	} अन्यथा जर (म_भेद(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		जर (certs == रिक्त || ncerts == रिक्त || cert_onlyp == रिक्त) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		जर (*certs != रिक्त) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		जर ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			जा out;
		}
		*cert_onlyp = v != 0;
		पर्यंत (sshbuf_len(b) != 0) {
			जर (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				r = SSH_ERR_INVALID_FORMAT;
				जा out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    आकार(**certs));
			जर ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				जा out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} अन्यथा {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		जा out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(ext_name);
	sshbuf_free(b);
	परत r;
}

स्थिर पूर्णांक
parse_किल्ली_constraints(संरचना sshbuf *m, संरचना sshkey *k, समय_प्रकार *deathp,
    u_int *secondsp, पूर्णांक *confirmp, अक्षर **sk_providerp,
    संरचना dest_constraint **dcsp, माप_प्रकार *ndcsp,
    पूर्णांक *cert_onlyp, माप_प्रकार *ncerts, संरचना sshkey ***certs)
{
	u_char ctype;
	पूर्णांक r;
	u_int seconds;

	पर्यंत (sshbuf_len(m)) {
		जर ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			जा out;
		}
		निवड (ctype) {
		स्थिती SSH_AGENT_CONSTRAIN_LIFETIME:
			जर (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				जा out;
			}
			जर ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				जा out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			थांबा;
		स्थिती SSH_AGENT_CONSTRAIN_CONFIRM:
			जर (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				जा out;
			}
			*confirmp = 1;
			थांबा;
		स्थिती SSH_AGENT_CONSTRAIN_EXTENSION:
			जर ((r = parse_किल्ली_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				जा out; /* error already logged */
			थांबा;
		पूर्वनिर्धारित:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			जा out;
		}
	}
	/* success */
	r = 0;
 out:
	परत r;
}

स्थिर शून्य
process_add_identity(SocketEntry *e)
{
	Identity *id;
	पूर्णांक success = 0, confirm = 0;
	अक्षर *fp, *comment = रिक्त, *sk_provider = रिक्त;
	अक्षर canonical_provider[PATH_MAX];
	समय_प्रकार death = 0;
	u_int seconds = 0;
	संरचना dest_constraint *dest_constraints = रिक्त;
	माप_प्रकार ndest_constraints = 0;
	संरचना sshkey *k = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	जर ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == रिक्त ||
	    (r = sshbuf_get_cstring(e->request, &comment, रिक्त)) != 0) {
		error_fr(r, "parse");
		जा out;
	}
	जर (parse_किल्ली_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    रिक्त, रिक्त, रिक्त) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		जा out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	जर (sk_provider != रिक्त) {
		जर (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			जा out;
		}
		जर (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} अन्यथा {
			जर (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				जा out;
			}
			जर (realpath(sk_provider, canonical_provider) == रिक्त) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    म_त्रुटि(त्रुटि_सं));
				जा out;
			}
			मुक्त(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			जर (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				जा out;
			}
		}
	}
	जर ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		जा out;
	}
	जर (lifetime && !death)
		death = monotime() + lifetime;
	जर ((id = lookup_identity(k)) == रिक्त) {
		id = xcalloc(1, आकार(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} अन्यथा {
		/* identity not visible, do not update */
		जर (identity_permitted(id, e, रिक्त, रिक्त, रिक्त) != 0)
			जा out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->किल्ली);
		मुक्त(id->comment);
		मुक्त(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->किल्ली = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	जर ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == रिक्त ? "none" : sk_provider, ndest_constraints);
	मुक्त(fp);
	/* transferred */
	k = रिक्त;
	comment = रिक्त;
	sk_provider = रिक्त;
	dest_constraints = रिक्त;
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
स्थिर शून्य
process_lock_agent(SocketEntry *e, पूर्णांक lock)
{
	पूर्णांक r, success = 0, delay;
	अक्षर *passwd;
	u_char passwdhash[LOCK_SIZE];
	स्थिर u_int fail_मोजणी = 0;
	माप_प्रकार pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	जर ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	जर (pwlen == 0) {
		debug("empty password not supported");
	} अन्यथा जर (locked && !lock) {
		जर (bcrypt_pbkdf(passwd, pwlen, lock_salt, आकार(lock_salt),
		    passwdhash, आकार(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		जर (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_मोजणी = 0;
			explicit_bzero(lock_pwhash, आकार(lock_pwhash));
			success = 1;
		} अन्यथा {
			/* delay in 0.1s increments up to 10s */
			जर (fail_मोजणी < 100)
				fail_मोजणी++;
			delay = 100000 * fail_मोजणी;
			debug("unlock failed, delaying %0.1lf seconds",
			    (द्विगुण)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, आकार(passwdhash));
	} अन्यथा जर (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, आकार(lock_salt));
		जर (bcrypt_pbkdf(passwd, pwlen, lock_salt, आकार(lock_salt),
		    lock_pwhash, आकार(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

स्थिर शून्य
no_identities(SocketEntry *e)
{
	संरचना sshbuf *संदेश;
	पूर्णांक r;

	जर ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_u8(संदेश, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, संदेश)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(संदेश);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
स्थिर शून्य
add_p11_identity(संरचना sshkey *किल्ली, अक्षर *comment, स्थिरांक अक्षर *provider,
    समय_प्रकार death, u_int confirm, संरचना dest_constraint *dest_constraints,
    माप_प्रकार ndest_constraints)
{
	Identity *id;

	जर (lookup_identity(किल्ली) != रिक्त) {
		sshkey_free(किल्ली);
		मुक्त(comment);
		परत;
	}
	id = xcalloc(1, आकार(Identity));
	id->किल्ली = किल्ली;
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

स्थिर शून्य
process_add_smartcard_किल्ली(SocketEntry *e)
{
	अक्षर *provider = रिक्त, *pin = रिक्त, canonical_provider[PATH_MAX];
	अक्षर **comments = रिक्त;
	पूर्णांक r, i, मोजणी = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	समय_प्रकार death = 0;
	संरचना sshkey **किल्ल्या = रिक्त, *k;
	संरचना dest_constraint *dest_constraints = रिक्त;
	माप_प्रकार j, ndest_constraints = 0, ncerts = 0;
	संरचना sshkey **certs = रिक्त;
	पूर्णांक cert_only = 0;

	debug2_f("entering");
	जर ((r = sshbuf_get_cstring(e->request, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, रिक्त)) != 0) {
		error_fr(r, "parse");
		जा send;
	}
	जर (parse_किल्ली_constraints(e->request, रिक्त, &death, &seconds, &confirm,
	    रिक्त, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		जा send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	जर (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		जा send;
	}
	जर (realpath(provider, canonical_provider) == रिक्त) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, म_त्रुटि(त्रुटि_सं));
		जा send;
	}
	जर (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		जा send;
	}
	debug_f("add %.100s", canonical_provider);
	जर (lifetime && !death)
		death = monotime() + lifetime;

	मोजणी = pkcs11_add_provider(canonical_provider, pin, &किल्ल्या, &comments);
	साठी (i = 0; i < मोजणी; i++) {
		जर (comments[i] == रिक्त || comments[i][0] == '\0') {
			मुक्त(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		साठी (j = 0; j < ncerts; j++) {
			जर (!sshkey_is_cert(certs[j]))
				सुरूठेवा;
			जर (!sshkey_equal_public(किल्ल्या[i], certs[j]))
				सुरूठेवा;
			जर (pkcs11_make_cert(किल्ल्या[i], certs[j], &k) != 0)
				सुरूठेवा;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		जर (!cert_only && lookup_identity(किल्ल्या[i]) == रिक्त) {
			add_p11_identity(किल्ल्या[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			किल्ल्या[i] = रिक्त;		/* transferred */
			comments[i] = रिक्त;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(किल्ल्या[i]);
		मुक्त(comments[i]);
	}
send:
	मुक्त(pin);
	मुक्त(provider);
	मुक्त(किल्ल्या);
	मुक्त(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	साठी (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	मुक्त(certs);
	send_status(e, success);
}

स्थिर शून्य
process_remove_smartcard_किल्ली(SocketEntry *e)
{
	अक्षर *provider = रिक्त, *pin = रिक्त, canonical_provider[PATH_MAX];
	पूर्णांक r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	जर ((r = sshbuf_get_cstring(e->request, &provider, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, रिक्त)) != 0) {
		error_fr(r, "parse");
		जा send;
	}
	मुक्त(pin);

	जर (realpath(provider, canonical_provider) == रिक्त) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, म_त्रुटि(त्रुटि_सं));
		जा send;
	}

	debug_f("remove %.100s", canonical_provider);
	साठी (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		जर (id->provider == रिक्त)
			सुरूठेवा;
		जर (!म_भेद(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	जर (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	अन्यथा
		error_f("pkcs11_del_provider failed");
send:
	मुक्त(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

स्थिर पूर्णांक
process_ext_session_bind(SocketEntry *e)
{
	पूर्णांक r, sid_match, किल्ली_match;
	संरचना sshkey *किल्ली = रिक्त;
	संरचना sshbuf *sid = रिक्त, *sig = रिक्त;
	अक्षर *fp = रिक्त;
	माप_प्रकार i;
	u_char fwd = 0;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	जर ((r = sshkey_froms(e->request, &किल्ली)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		जा out;
	}
	जर (sshbuf_len(sid) > AGENT_MAX_SID_LEN) {
		error_f("session ID too long");
		जा out;
	}
	जर ((fp = sshkey_fingerprint(किल्ली, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	जर ((r = sshkey_verify(किल्ली, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), रिक्त, 0, रिक्त)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(किल्ली), fp);
		जा out;
	}
	/* check whether sid/key already recorded */
	साठी (i = 0; i < e->nsession_ids; i++) {
		जर (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			जा out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		किल्ली_match = sshkey_equal(किल्ली, e->session_ids[i].किल्ली);
		जर (sid_match && किल्ली_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(किल्ली), fp);
			r = 0;
			जा out;
		} अन्यथा जर (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(किल्ली), fp);
			r = -1;
			जा out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	जर (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		r = -1;
		जा out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, आकार(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(किल्ली), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].किल्ली = किल्ली;
	e->session_ids[i].forwarded = fwd != 0;
	किल्ली = रिक्त; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	जर ((e->session_ids[i].sid = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जर ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	मुक्त(fp);
	sshkey_free(किल्ली);
	sshbuf_free(sid);
	sshbuf_free(sig);
	परत r == 0 ? 1 : 0;
}

स्थिर पूर्णांक
process_ext_query(SocketEntry *e)
{
	पूर्णांक r;
	संरचना sshbuf *संदेश = रिक्त;

	debug2_f("entering");
	जर ((संदेश = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर ((r = sshbuf_put_u8(संदेश, SSH_AGENT_EXTENSION_RESPONSE)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "query")) != 0 ||
	    /* string[]     supported extension types */
	    (r = sshbuf_put_cstring(संदेश, "session-bind@openssh.com")) != 0)
		fatal_fr(r, "compose");
	जर ((r = sshbuf_put_stringb(e->output, संदेश)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(संदेश);
	परत 1;
}

स्थिर शून्य
process_extension(SocketEntry *e)
{
	पूर्णांक r, replied = 0, success = 0;
	अक्षर *name;

	debug2_f("entering");
	जर ((r = sshbuf_get_cstring(e->request, &name, रिक्त)) != 0) {
		error_fr(r, "parse");
		send_status(e, 0);
		परत;
	}

	/*
	 * This function can be called while the agent is locked to allow
	 * session binds to be processed for new channels.
	 * Other operations should be refused when locked.
	 */

	जर (म_भेद(name, "session-bind@openssh.com") == 0) {
		success = process_ext_session_bind(e);
	} अन्यथा जर (locked) {
		debug_f("attempt to use extension \"%s\" while locked", name);
		जा generic_fail;
	} अन्यथा जर (म_भेद(name, "query") == 0) {
		replied = success = process_ext_query(e);
	} अन्यथा {
		debug_f("unsupported extension \"%s\"", name);
 generic_fail:
		मुक्त(name);
		send_status(e, 0);
		परत;
	}
	मुक्त(name);
	/* Agent failures are signalled with a different error code */
	जर (!replied) {
		send_status_generic(e,
		    success ? SSH_AGENT_SUCCESS : SSH_AGENT_EXTENSION_FAILURE);
	}
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
स्थिर पूर्णांक
process_message(u_int socknum)
{
	u_int संदेश_len;
	u_char type;
	स्थिरांक u_char *cp;
	पूर्णांक r;
	SocketEntry *e;

	जर (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	जर (sshbuf_len(e->आदान) < 5)
		परत 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->आदान);
	संदेश_len = PEEK_U32(cp);
	जर (संदेश_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, संदेश_len, AGENT_MAX_LEN);
		परत -1;
	}
	जर (sshbuf_len(e->आदान) < संदेश_len + 4)
		परत 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	जर ((r = sshbuf_get_stringb(e->आदान, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		जर (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			परत -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	जर (locked && type != SSH_AGENTC_UNLOCK) {
		निवड (type) {
		स्थिती SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			थांबा;
		स्थिती SSH_AGENTC_EXTENSION:
			process_extension(e);
			थांबा;
		पूर्वनिर्धारित:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		sshbuf_reset(e->request);
		परत 1;
	}

	निवड (type) {
	स्थिती SSH_AGENTC_LOCK:
	स्थिती SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		थांबा;
	स्थिती SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		थांबा;
	/* ssh2 */
	स्थिती SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		थांबा;
	स्थिती SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		थांबा;
	स्थिती SSH2_AGENTC_ADD_IDENTITY:
	स्थिती SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		थांबा;
	स्थिती SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		थांबा;
	स्थिती SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		थांबा;
#ifdef ENABLE_PKCS11
	स्थिती SSH_AGENTC_ADD_SMARTCARD_किल्ली:
	स्थिती SSH_AGENTC_ADD_SMARTCARD_किल्ली_CONSTRAINED:
		process_add_smartcard_किल्ली(e);
		थांबा;
	स्थिती SSH_AGENTC_REMOVE_SMARTCARD_किल्ली:
		process_remove_smartcard_किल्ली(e);
		थांबा;
#endif /* ENABLE_PKCS11 */
	स्थिती SSH_AGENTC_EXTENSION:
		process_extension(e);
		थांबा;
	पूर्वनिर्धारित:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		थांबा;
	}
	परत 1;
}

स्थिर शून्य
new_socket(sock_type type, पूर्णांक fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	जर (fd > max_fd)
		max_fd = fd;

	साठी (i = 0; i < sockets_alloc; i++)
		जर (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			जर ((sockets[i].आदान = sshbuf_new()) == रिक्त ||
			    (sockets[i].output = sshbuf_new()) == रिक्त ||
			    (sockets[i].request = sshbuf_new()) == रिक्त)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			परत;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    आकार(sockets[0]));
	साठी (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	जर ((sockets[old_alloc].आदान = sshbuf_new()) == रिक्त ||
	    (sockets[old_alloc].output = sshbuf_new()) == रिक्त ||
	    (sockets[old_alloc].request = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

स्थिर पूर्णांक
handle_socket_read(u_int socknum)
{
	संरचना sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	पूर्णांक fd;

	slen = आकार(sunaddr);
	fd = accept(sockets[socknum].fd, (संरचना sockaddr *)&sunaddr, &slen);
	जर (fd == -1) {
		error("accept from AUTH_SOCKET: %s", म_त्रुटि(त्रुटि_सं));
		परत -1;
	}
	जर (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, म_त्रुटि(त्रुटि_सं));
		बंद(fd);
		परत -1;
	}
	जर ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		बंद(fd);
		परत -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	परत 0;
}

स्थिर पूर्णांक
handle_conn_read(u_int socknum)
{
	अक्षर buf[AGENT_RBUF_LEN];
	ssize_t len;
	पूर्णांक r;

	जर ((len = पठ(sockets[socknum].fd, buf, आकार(buf))) <= 0) {
		जर (len == -1) {
			जर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
				परत 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, म_त्रुटि(त्रुटि_सं));
		}
		परत -1;
	}
	जर ((r = sshbuf_put(sockets[socknum].आदान, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, आकार(buf));
	साठी (;;) {
		जर ((r = process_message(socknum)) == -1)
			परत -1;
		अन्यथा जर (r == 0)
			थांबा;
	}
	परत 0;
}

स्थिर पूर्णांक
handle_conn_write(u_int socknum)
{
	ssize_t len;
	पूर्णांक r;

	जर (sshbuf_len(sockets[socknum].output) == 0)
		परत 0; /* shouldn't happen */
	जर ((len = लिख(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		जर (len == -1) {
			जर (त्रुटि_सं == EAGAIN || त्रुटि_सं == EINTR)
				परत 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, म_त्रुटि(त्रुटि_सं));
		}
		परत -1;
	}
	जर ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	परत 0;
}

स्थिर शून्य
after_poll(संरचना pollfd *pfd, माप_प्रकार npfd, u_int maxfds)
{
	माप_प्रकार i;
	u_int socknum, activefds = npfd;

	साठी (i = 0; i < npfd; i++) {
		जर (pfd[i].revents == 0)
			सुरूठेवा;
		/* Find sockets entry */
		साठी (socknum = 0; socknum < sockets_alloc; socknum++) {
			जर (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				सुरूठेवा;
			जर (pfd[i].fd == sockets[socknum].fd)
				थांबा;
		}
		जर (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			सुरूठेवा;
		}
		/* Process events */
		निवड (sockets[socknum].type) {
		स्थिती AUTH_SOCKET:
			जर ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				थांबा;
			जर (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				थांबा;
			}
			जर (handle_socket_read(socknum) == 0)
				activefds++;
			थांबा;
		स्थिती AUTH_CONNECTION:
			जर ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				जा close_sock;
			जर ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				जर (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				थांबा;
			}
			थांबा;
		पूर्वनिर्धारित:
			थांबा;
		}
	}
}

स्थिर पूर्णांक
prepare_poll(संरचना pollfd **pfdp, माप_प्रकार *npfdp, संरचना timespec *timeoutp, u_int maxfds)
{
	संरचना pollfd *pfd = *pfdp;
	माप_प्रकार i, j, npfd = 0;
	समय_प्रकार deadline;
	पूर्णांक r;

	/* Count active sockets */
	साठी (i = 0; i < sockets_alloc; i++) {
		निवड (sockets[i].type) {
		स्थिती AUTH_SOCKET:
		स्थिती AUTH_CONNECTION:
			npfd++;
			थांबा;
		स्थिती AUTH_UNUSED:
			थांबा;
		पूर्वनिर्धारित:
			fatal("Unknown socket type %d", sockets[i].type);
			थांबा;
		}
	}
	जर (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, आकार(*pfd))) == रिक्त)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	साठी (i = j = 0; i < sockets_alloc; i++) {
		निवड (sockets[i].type) {
		स्थिती AUTH_SOCKET:
			जर (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				थांबा;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			थांबा;
		स्थिती AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			जर ((r = sshbuf_check_reserve(sockets[i].आदान,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			अन्यथा जर (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			जर (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			थांबा;
		पूर्वनिर्धारित:
			थांबा;
		}
	}
	deadline = reaper();
	जर (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	जर (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	परत (1);
}

स्थिर शून्य
cleanup_socket(शून्य)
{
	जर (cleanup_pid != 0 && getpid() != cleanup_pid)
		परत;
	debug_f("cleanup");
	जर (socket_name != रिक्त) {
		agent_listener_cleanup(socket_dirspec, socket_name, socket_dir);
		मुक्त(socket_name);
		socket_name = रिक्त;
		मुक्त(socket_dir);
		socket_dir = रिक्त;
	}
}

शून्य
cleanup_exit(पूर्णांक i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

स्थिर शून्य
cleanup_handler(पूर्णांक sig)
{
	signalled_exit = sig;
}

स्थिर शून्य
keydrop_handler(पूर्णांक sig)
{
	signalled_keydrop = sig;
}

स्थिर शून्य
check_parent_exists(शून्य)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	जर (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

स्थिर शून्य
usage(शून्य)
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
main(पूर्णांक ac, अक्षर **av)
{
	पूर्णांक c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0;
	पूर्णांक s_flag = 0, T_flag = 0, u_flag = 0, U_flag = 0;
	पूर्णांक sock = -1, ch, result, saved_errno;
	pid_t pid;
 	अक्षर *homedir = रिक्त, *shell, *format, *pidstr, *agentsocket = रिक्त;
	अक्षर *cp, pidstrbuf[1 + 3 * आकार pid];
	अक्षर *fdstr;
	स्थिरांक अक्षर *errstr = रिक्त;
	स्थिरांक अक्षर *ccp;
#ifdef HAVE_SETRLIMIT
	संरचना rlimit rlim;
#endif
	बाह्य पूर्णांक optind;
	बाह्य अक्षर *optarg;
	माप_प्रकार len;
	mode_t prev_mask;
	संरचना timespec timeout;
	संरचना pollfd *pfd = रिक्त;
	माप_प्रकार npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;
	पूर्णांक socket_activated = 0;
	संरचना passwd *pw;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(शून्य)setegid(getgid());
	(शून्य)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

	जर ((pw = getpwuid(getuid())) == रिक्त)
		fatal("No user exists for uid %lu", (u_long)getuid());
	pw = pwcopy(pw);

#ifdef RLIMIT_NOFILE
	जर (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, म_त्रुटि(त्रुटि_सं));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	पर्यंत ((ch = getopt(ac, av, "cDdksTuUVA:E:a:O:P:t:")) != -1) {
		निवड (ch) {
		स्थिती 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			जर (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			थांबा;
		स्थिती 'c':
			जर (s_flag)
				usage();
			c_flag++;
			थांबा;
		स्थिती 'k':
			k_flag++;
			थांबा;
		स्थिती 'O':
			जर (म_भेद(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			अन्यथा जर (म_भेद(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			अन्यथा जर ((ccp = strprefix(optarg,
			    "websafe-allow=", 0)) != रिक्त) {
				जर (websafe_allowlist != रिक्त)
					fatal("websafe-allow already set");
				websafe_allowlist = xstrdup(ccp);
			} अन्यथा
				fatal("Unknown -O option");
			थांबा;
		स्थिती 'P':
			जर (allowed_providers != रिक्त)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			थांबा;
		स्थिती 's':
			जर (c_flag)
				usage();
			s_flag++;
			थांबा;
		स्थिती 'd':
			जर (d_flag || D_flag)
				usage();
			d_flag++;
			थांबा;
		स्थिती 'D':
			जर (d_flag || D_flag)
				usage();
			D_flag++;
			थांबा;
		स्थिती 'a':
			agentsocket = optarg;
			थांबा;
		स्थिती 'A':
			socket_dirspec = xstrdup(optarg);
			थांबा;
		स्थिती 't':
			जर ((lifetime = convtime(optarg)) == -1) {
				ख_लिखो(मानक_त्रुटि, "Invalid lifetime\n");
				usage();
			}
			थांबा;
		स्थिती 'T':
			T_flag++;
			थांबा;
		स्थिती 'u':
			u_flag++;
			थांबा;
		स्थिती 'U':
			U_flag++;
			थांबा;
		स्थिती 'V':
			ख_लिखो(मानक_त्रुटि, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			निकास(0);
		पूर्वनिर्धारित:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	जर (ac > 0 &&
	    (c_flag || k_flag || s_flag || d_flag || D_flag || u_flag))
		usage();
	/* only one of -a, -A and -T allowed */
	जर (((socket_dirspec != रिक्त) + (agentsocket != रिक्त) + T_flag) > 1)
		usage();

	log_init(__progname,
	    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
	    SYSLOG_FACILITY_AUTH, 1);

	जर (allowed_providers == रिक्त)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);
	जर (websafe_allowlist == रिक्त)
		websafe_allowlist = xstrdup(DEFAULT_WEBSAFE_ALLOWLIST);

	जर (T_flag)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_TMPDIR);
	अन्यथा जर (socket_dirspec == रिक्त && agentsocket == रिक्त)
		socket_dirspec = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	जर (ac == 0 && !c_flag && !s_flag) {
		shell = दो_पर्या("SHELL");
		जर (shell != रिक्त && (len = म_माप(shell)) > 2 &&
		    म_भेदन(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	जर (k_flag) {
		pidstr = दो_पर्या(SSH_AGENTPID_ENV_NAME);
		जर (pidstr == रिक्त) {
			ख_लिखो(मानक_त्रुटि, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			निकास(1);
		}
		pid = (पूर्णांक)strtonum(pidstr, 2, पूर्णांक_उच्च, &errstr);
		जर (errstr) {
			ख_लिखो(मानक_त्रुटि,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			निकास(1);
		}
		जर (समाप्त(pid, संक_इति) == -1) {
			लिखो_त्रुटि("kill");
			निकास(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		म_लिखो(format, SSH_AUTHSOCKET_ENV_NAME);
		म_लिखो(format, SSH_AGENTPID_ENV_NAME);
		म_लिखो("echo Agent pid %ld killed;\n", (दीर्घ)pid);
		निकास(0);
	}
	जर (u_flag) {
		जर ((homedir = get_homedir()) == रिक्त)
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
#define SSH_AGENT_MIN_FDS (3+1+1+1+4)
	जर (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (दीर्घ दीर्घ)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	/* Has the socket been provided via socket activation? */
	जर (agentsocket == रिक्त && ac == 0 && (d_flag || D_flag) &&
	    (pidstr = दो_पर्या("LISTEN_PID")) != रिक्त &&
	    (fdstr = दो_पर्या("LISTEN_FDS")) != रिक्त) {
		जर (म_भेद(fdstr, "1") != 0) {
			fatal("unexpected LISTEN_FDS contents "
			    "(want: \"1\" got\"%s\"", fdstr);
		}
		जर (fcntl(3, F_GETFL) == -1)
			fatal("LISTEN_FDS set but fd 3 unavailable");
		pid = (पूर्णांक)strtonum(pidstr, 1, पूर्णांक_उच्च, &errstr);
		जर (errstr != रिक्त)
			fatal("invalid LISTEN_PID: %s", errstr);
		जर (pid != getpid())
			fatal("bad LISTEN_PID: %d vs pid %d", pid, getpid());
		debug("using socket activation on fd=3");
		sock = 3;
		socket_activated = 1;
	}

	जर (sock == -1 && agentsocket == रिक्त) {
		/* Listen on a socket in/under a given directory */
		जर ((homedir = get_homedir()) == रिक्त)
			fatal("Couldn't determine home directory");
		जर (!U_flag) {
			agent_cleanup_stale(socket_dirspec,
			    pw->pw_name, pw->pw_uid, homedir, 0);
		}
		जर (agent_listener(socket_dirspec, pw->pw_name, pw->pw_uid,
		    homedir, getpid(), "local", &sock, &socket_name,
		    &socket_dir) != 0)
			fatal_f("Couldn't prepare agent socket");
		मुक्त(homedir);
	} अन्यथा जर (sock == -1) {
		/* Listen on explicit socket path */
		prev_mask = umask(0177);
		socket_name = xstrdup(agentsocket);
		जर ((sock = unix_listener(socket_name,
		    SSH_LISTEN_BACKLOG, 0)) < 0) {
			मुक्त(socket_name);
			socket_name = रिक्त; /* Don't unlink existing file */
			cleanup_exit(1);
		}
		umask(prev_mask);
	}

	closefrom(sock == -1 ? STDERR_FILENO + 1 : sock + 1);

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	जर (sock == -1) {
		prev_mask = umask(0177);
		sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
		जर (sock < 0) {
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
	जर (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		जर (socket_name != रिक्त) {
			cp = argv_assemble(1, &socket_name);
			format = c_flag ?
			    "setenv %s %s;\n" : "%s=%s; export %s;\n";
			म_लिखो(format, SSH_AUTHSOCKET_ENV_NAME, cp,
			    SSH_AUTHSOCKET_ENV_NAME);
			मुक्त(cp);
			म_लिखो("echo Agent pid %ld;\n", (दीर्घ)parent_pid);
			ख_साफ(मानक_निकास);
		}
		जा skip;
	}
	pid = विभाजन();
	जर (pid == -1) {
		लिखो_त्रुटि("fork");
		cleanup_exit(1);
	}
	जर (pid != 0) {		/* Parent - execute the given command. */
		बंद(sock);
		snprintf(pidstrbuf, आकार pidstrbuf, "%ld", (दीर्घ)pid);
		जर (ac == 0) {
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
		जर (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
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

	जर (setsid() == -1) {
		error("setsid: %s", म_त्रुटि(त्रुटि_सं));
		cleanup_exit(1);
	}

	(शून्य)स_बदलो("/");
	जर (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	जर (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", म_त्रुटि(त्रुटि_सं));
		cleanup_exit(1);
	}
#endif

skip:

	cleanup_pid = getpid();

#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	जर (ac > 0)
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

	जर (socket_name != रिक्त && unveil(socket_name, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_name,
		    म_त्रुटि(त्रुटि_सं));
	}
	जर (socket_dir != रिक्त && unveil(socket_dir, "c") == -1) {
		fatal("%s: unveil %s %s", __progname, socket_dir,
		    म_त्रुटि(त्रुटि_सं));
	}
	जर (unveil("/", "r") == -1)
		fatal("%s: unveil /: %s", __progname, म_त्रुटि(त्रुटि_सं));
	जर ((ccp = दो_पर्या("SSH_SK_HELPER")) == रिक्त || *ccp == '\0')
		ccp = _PATH_SSH_SK_HELPER;
	जर (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, म_त्रुटि(त्रुटि_सं));
	जर ((ccp = दो_पर्या("SSH_PKCS11_HELPER")) == रिक्त || *ccp == '\0')
		ccp = _PATH_SSH_PKCS11_HELPER;
	जर (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, म_त्रुटि(त्रुटि_सं));
	जर ((ccp = दो_पर्या("SSH_ASKPASS")) == रिक्त || *ccp == '\0')
		ccp = _PATH_SSH_ASKPASS_DEFAULT;
	जर (unveil(ccp, "x") == -1)
		fatal("%s: unveil %s: %s", __progname, ccp, म_त्रुटि(त्रुटि_सं));
	जर (unveil("/dev/null", "rw") == -1)
		fatal("%s: unveil /dev/null: %s", __progname, म_त्रुटि(त्रुटि_सं));
	जर (pledge("stdio rpath cpath wpath unix id proc exec", रिक्त) == -1)
		fatal("%s: pledge: %s", __progname, म_त्रुटि(त्रुटि_सं));
	platform_pledge_agent();

	पर्यंत (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		जर (signalled_exit != 0) {
			logit("exiting on signal %d", (पूर्णांक)signalled_exit);
			cleanup_exit((signalled_exit == संक_इति &&
			    socket_activated) ? 0 : 2);
		}
		जर (signalled_keydrop) {
			logit("signal %d received; removing all keys",
			    (पूर्णांक)signalled_keydrop);
			remove_all_identities();
			signalled_keydrop = 0;
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, रिक्त);
		saved_errno = त्रुटि_सं;
		जर (parent_alive_interval != 0)
			check_parent_exists();
		(शून्य) reaper();	/* remove expired keys */
		जर (result == -1) {
			जर (saved_errno == EINTR)
				सुरूठेवा;
			fatal("poll: %s", म_त्रुटि(saved_errno));
		} अन्यथा जर (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
