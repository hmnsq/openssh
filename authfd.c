/* $OpenBSD: authfd.c,v 1.144 2026/06/29 08:57:06 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for connecting the local authentication agent.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation,
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
#ضمن <sys/un.h>
#ضمن <sys/socket.h>

#ضمن <fcntl.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>
#ضمن <errno.h>

#ضمن "ssh.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "authfd.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "atomicio.h"
#ضمن "ssherr.h"
#ضمن "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
ساكن صحيح
decode_reply(u_char type)
{
	إذا (agent_failed(type))
		أرجع SSH_ERR_AGENT_FAILURE;
	وإلا إذا (type == SSH_AGENT_SUCCESS)
		أرجع 0;
	وإلا
		أرجع SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
صحيح
ssh_get_authentication_socket_path(ثابت حرف *authsocket, صحيح *fdp)
{
	صحيح sock, oerrno;
	بنية sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, حجم(sunaddr.sun_path));

	إذا ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	إذا (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (بنية sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	إذا (fdp != عدم)
		*fdp = sock;
	وإلا
		close(sock);
	أرجع 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
صحيح
ssh_get_authentication_socket(صحيح *fdp)
{
	ثابت حرف *authsocket;

	إذا (fdp != عدم)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	إذا (authsocket == عدم || *authsocket == '\0')
		أرجع SSH_ERR_AGENT_NOT_PRESENT;

	أرجع ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
ساكن صحيح
ssh_request_reply(صحيح sock, بنية sshbuf *request, بنية sshbuf *reply)
{
	صحيح r;
	size_t l, len;
	حرف buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	إذا (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		أرجع SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	إذا (atomicio(اقرأ, sock, buf, 4) != 4)
	    أرجع SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	إذا (len > MAX_AGENT_REPLY_LEN)
		أرجع SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	طالما (len > 0) {
		l = len;
		إذا (l > حجم(buf))
			l = حجم(buf);
		إذا (atomicio(اقرأ, sock, buf, l) != l)
			أرجع SSH_ERR_AGENT_COMMUNICATION;
		إذا ((r = sshbuf_put(reply, buf, l)) != 0)
			أرجع r;
		len -= l;
	}
	أرجع 0;
}

/* Communicate with agent: sent request, read and decode status reply */
ساكن صحيح
ssh_request_reply_decode(صحيح sock, بنية sshbuf *request)
{
	بنية sshbuf *reply;
	صحيح r;
	u_char type;

	إذا ((reply = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	أرجع r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
فراغ
ssh_close_authentication_socket(صحيح sock)
{
	إذا (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != عدم)
		close(sock);
}

/* Lock/unlock agent */
صحيح
ssh_lock_agent(صحيح sock, صحيح lock, ثابت حرف *password)
{
	صحيح r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	بنية sshbuf *ئۇچۇر;

	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(ئۇچۇر, type)) != 0 ||
	    (r = sshbuf_put_cstring(ئۇچۇر, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, ئۇچۇر)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ئۇچۇر);
	أرجع r;
}


ساكن صحيح
deserialise_identity2(بنية sshbuf *ids, بنية sshkey **keyp, حرف **commentp)
{
	صحيح r;
	حرف *comment = عدم;
	ثابت u_char *blob;
	size_t blen;

	إذا ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, عدم)) != 0)
		اذهب out;
	إذا ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		اذهب out;
	إذا (commentp != عدم) {
		*commentp = comment;
		comment = عدم;
	}
	r = 0;
 out:
	حرر(comment);
	أرجع r;
}

/*
 * Fetch list of identities held by the agent.
 */
صحيح
ssh_fetch_identitylist(صحيح sock, بنية ssh_identitylist **idlp)
{
	u_char type;
	uint32_t رەقەم, i;
	بنية sshbuf *ئۇچۇر;
	بنية ssh_identitylist *idl = عدم;
	صحيح r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(ئۇچۇر, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		اذهب out;

	إذا ((r = ssh_request_reply(sock, ئۇچۇر, ئۇچۇر)) != 0)
		اذهب out;

	/* Get message type, and verify that we got a proper answer. */
	إذا ((r = sshbuf_get_u8(ئۇچۇر, &type)) != 0)
		اذهب out;
	إذا (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		اذهب out;
	} وإلا إذا (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	إذا ((r = sshbuf_get_u32(ئۇچۇر, &رەقەم)) != 0)
		اذهب out;
	إذا (رەقەم > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (رەقەم == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		اذهب out;
	}

	/* Deserialise the response into a list of keys/comments */
	إذا ((idl = calloc(1, حجم(*idl))) == عدم ||
	    (idl->ئاچقۇچلار = calloc(رەقەم, حجم(*idl->ئاچقۇچلار))) == عدم ||
	    (idl->comments = calloc(رەقەم, حجم(*idl->comments))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	لكل (i = 0; i < رەقەم;) {
		إذا ((r = deserialise_identity2(ئۇچۇر, &(idl->ئاچقۇچلار[i]),
		    &(idl->comments[i]))) != 0) {
			إذا (r == SSH_ERR_ئاچقۇچ_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				رەقەم--;
				استمر;
			} وإلا
				اذهب out;
		}
		i++;
	}
	idl->nkeys = رەقەم;
	*idlp = idl;
	idl = عدم;
	r = 0;
 out:
	sshbuf_free(ئۇچۇر);
	إذا (idl != عدم)
		ssh_free_identitylist(idl);
	أرجع r;
}

فراغ
ssh_free_identitylist(بنية ssh_identitylist *idl)
{
	size_t i;

	إذا (idl == عدم)
		أرجع;
	لكل (i = 0; i < idl->nkeys; i++) {
		إذا (idl->ئاچقۇچلار != عدم)
			sshkey_free(idl->ئاچقۇچلار[i]);
		إذا (idl->comments != عدم)
			حرر(idl->comments[i]);
	}
	حرر(idl->ئاچقۇچلار);
	حرر(idl->comments);
	حرر(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
صحيح
ssh_agent_has_ئاچقۇچ(صحيح sock, ثابت بنية sshkey *ئاچقۇچ)
{
	صحيح r, ret = SSH_ERR_ئاچقۇچ_NOT_FOUND;
	size_t i;
	بنية ssh_identitylist *idlist = عدم;

	إذا ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		أرجع r;
	}

	لكل (i = 0; i < idlist->nkeys; i++) {
		إذا (sshkey_equal_public(idlist->ئاچقۇچلار[i], ئاچقۇچ)) {
			ret = 0;
			اكسر;
		}
	}

	ssh_free_identitylist(idlist);
	أرجع ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
ساكن u_int
agent_encode_alg(ثابت بنية sshkey *ئاچقۇچ, ثابت حرف *alg)
{
	إذا (alg != عدم && sshkey_type_plain(ئاچقۇچ->type) == ئاچقۇچ_RSA) {
		إذا (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			أرجع SSH_AGENT_RSA_SHA2_256;
		إذا (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			أرجع SSH_AGENT_RSA_SHA2_512;
	}
	أرجع 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
صحيح
ssh_agent_sign(صحيح sock, ثابت بنية sshkey *ئاچقۇچ,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen, ثابت حرف *alg, u_int compat)
{
	بنية sshbuf *ئۇچۇر;
	u_char *sig = عدم, type = 0;
	size_t len = 0;
	u_int flags = 0;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	*sigp = عدم;
	*lenp = 0;

	إذا (datalen > SSH_ئاچقۇچ_MAX_SIGN_DATA_SIZE)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(ئاچقۇچ, alg);
	إذا ((r = sshbuf_put_u8(ئۇچۇر, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(ئاچقۇچ, ئۇچۇر)) != 0 ||
	    (r = sshbuf_put_string(ئۇچۇر, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(ئۇچۇر, flags)) != 0)
		اذهب out;
	إذا ((r = ssh_request_reply(sock, ئۇچۇر, ئۇچۇر)) != 0)
		اذهب out;
	إذا ((r = sshbuf_get_u8(ئۇچۇر, &type)) != 0)
		اذهب out;
	إذا (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		اذهب out;
	} وإلا إذا (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((r = sshbuf_get_string(ئۇچۇر, &sig, &len)) != 0)
		اذهب out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	إذا (!sshkey_is_sk(ئاچقۇچ) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		اذهب out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = عدم;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(ئۇچۇر);
	أرجع r;
}

/* Encode key for a message to the agent. */

ساكن صحيح
encode_dest_constraint_hop(بنية sshbuf *m,
    ثابت بنية dest_constraint_hop *dch)
{
	بنية sshbuf *b;
	u_int i;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, عدم, 0)) != 0) /* reserved */
		اذهب out;
	لكل (i = 0; i < dch->nkeys; i++) {
		إذا ((r = sshkey_puts(dch->ئاچقۇچلار[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->ئاچقۇچ_is_ca[i] != 0)) != 0)
			اذهب out;
	}
	إذا ((r = sshbuf_put_stringb(m, b)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
encode_dest_constraint(بنية sshbuf *m, ثابت بنية dest_constraint *dc)
{
	بنية sshbuf *b;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, عدم, 0)) != 0) /* reserved */
		اذهب out;
	إذا ((r = sshbuf_put_stringb(m, b)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
encode_constraints(بنية sshbuf *m, u_int life, u_int confirm,
    ثابت حرف *provider,
    بنية dest_constraint **dest_constraints, size_t ndest_constraints,
    صحيح cert_only, بنية sshkey **certs, size_t ncerts)
{
	صحيح r;
	بنية sshbuf *b = عدم;
	size_t i;

	إذا (life != 0) {
		إذا ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			اذهب out;
	}
	إذا (confirm != 0) {
		إذا ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			اذهب out;
	}
	إذا (provider != عدم) {
		إذا ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			اذهب out;
	}
	إذا (dest_constraints != عدم && ndest_constraints > 0) {
		إذا ((b = sshbuf_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		لكل (i = 0; i < ndest_constraints; i++) {
			إذا ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				اذهب out;
		}
		إذا ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			اذهب out;
		sshbuf_free(b);
		b = عدم;
	}
	إذا (ncerts != 0) {
		إذا ((b = sshbuf_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		لكل (i = 0; i < ncerts; i++) {
			إذا ((r = sshkey_puts(certs[i], b)) != 0)
				اذهب out;
		}
		إذا ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			اذهب out;
		sshbuf_free(b);
		b = عدم;
	}
	r = 0;
 out:
	sshbuf_free(b);
	أرجع r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحيح
ssh_add_identity_constrained(صحيح sock, بنية sshkey *ئاچقۇچ,
    ثابت حرف *comment, u_int life, u_int confirm,
    ثابت حرف *provider, بنية dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	بنية sshbuf *ئۇچۇر;
	صحيح r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	بدل (ئاچقۇچ->type) {
#ifdef WITH_OPENSSL
	حالة ئاچقۇچ_RSA:
	حالة ئاچقۇچ_RSA_CERT:
	حالة ئاچقۇچ_ECDSA:
	حالة ئاچقۇچ_ECDSA_CERT:
	حالة ئاچقۇچ_ECDSA_SK:
	حالة ئاچقۇچ_ECDSA_SK_CERT:
#endif
	حالة ئاچقۇچ_ED25519:
	حالة ئاچقۇچ_ED25519_CERT:
	حالة ئاچقۇچ_MLDSA44_ED25519:
	حالة ئاچقۇچ_MLDSA44_ED25519_CERT:
	حالة ئاچقۇچ_ED25519_SK:
	حالة ئاچقۇچ_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		إذا ((r = sshbuf_put_u8(ئۇچۇر, type)) != 0 ||
		    (r = sshkey_private_serialize(ئاچقۇچ, ئۇچۇر)) != 0 ||
		    (r = sshbuf_put_cstring(ئۇچۇر, comment)) != 0)
			اذهب out;
		اكسر;
	افتراضي:
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (constrained &&
	    (r = encode_constraints(ئۇچۇر, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, عدم, 0)) != 0)
		اذهب out;
	إذا ((r = ssh_request_reply_decode(sock, ئۇچۇر)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ئۇچۇر);
	أرجع r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحيح
ssh_remove_identity(صحيح sock, ثابت بنية sshkey *ئاچقۇچ)
{
	بنية sshbuf *ئۇچۇر;
	صحيح r;
	u_char *blob = عدم;
	size_t blen;

	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	إذا (ئاچقۇچ->type != ئاچقۇچ_UNSPEC) {
		إذا ((r = sshkey_to_blob(ئاچقۇچ, &blob, &blen)) != 0)
			اذهب out;
		إذا ((r = sshbuf_put_u8(ئۇچۇر,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(ئۇچۇر, blob, blen)) != 0)
			اذهب out;
	} وإلا {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا ((r = ssh_request_reply_decode(sock, ئۇچۇر)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	إذا (blob != عدم)
		freezero(blob, blen);
	sshbuf_free(ئۇچۇر);
	أرجع r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحيح
ssh_update_card(صحيح sock, صحيح add, ثابت حرف *reader_id, ثابت حرف *pin,
    u_int life, u_int confirm,
    بنية dest_constraint **dest_constraints, size_t ndest_constraints,
    صحيح cert_only, بنية sshkey **certs, size_t ncerts)
{
	بنية sshbuf *ئۇچۇر;
	صحيح r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	إذا (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_ئاچقۇچ_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_ئاچقۇچ;
	} وإلا
		type = SSH_AGENTC_REMOVE_SMARTCARD_ئاچقۇچ;

	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(ئۇچۇر, type)) != 0 ||
	    (r = sshbuf_put_cstring(ئۇچۇر, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(ئۇچۇر, pin)) != 0)
		اذهب out;
	إذا (constrained &&
	    (r = encode_constraints(ئۇچۇر, life, confirm, عدم,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		اذهب out;
	إذا ((r = ssh_request_reply_decode(sock, ئۇچۇر)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ئۇچۇر);
	أرجع r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
صحيح
ssh_remove_all_identities(صحيح sock, صحيح version)
{
	بنية sshbuf *ئۇچۇر;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	صحيح r;

	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(ئۇچۇر, type)) != 0)
		اذهب out;
	إذا ((r = ssh_request_reply_decode(sock, ئۇچۇر)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ئۇچۇر);
	أرجع r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
صحيح
ssh_agent_bind_hostkey(صحيح sock, ثابت بنية sshkey *ئاچقۇچ,
    ثابت بنية sshbuf *session_id, ثابت بنية sshbuf *signature,
    صحيح forwarding)
{
	بنية sshbuf *ئۇچۇر;
	صحيح r;

	إذا (ئاچقۇچ == عدم || session_id == عدم || signature == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(ئۇچۇر, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ئۇچۇر, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(ئاچقۇچ, ئۇچۇر)) != 0 ||
	    (r = sshbuf_put_stringb(ئۇچۇر, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(ئۇچۇر, signature)) != 0 ||
	    (r = sshbuf_put_u8(ئۇچۇر, forwarding ? 1 : 0)) != 0)
		اذهب out;
	إذا ((r = ssh_request_reply_decode(sock, ئۇچۇر)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ئۇچۇر);
	أرجع r;
}

/* Queries supported extension request types */
صحيح
ssh_agent_query_extensions(صحيح sock, حرف ***exts)
{
	بنية sshbuf *ئۇچۇر;
	صحيح r;
	u_char type;
	حرف *cp = عدم, **ret = عدم;
	size_t i = 0;

	*exts = عدم;
	إذا ((ئۇچۇر = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(ئۇچۇر, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ئۇچۇر, "query")) != 0)
		اذهب out;
	إذا ((r = ssh_request_reply(sock, ئۇچۇر, ئۇچۇر)) != 0)
		اذهب out;
	إذا ((r = sshbuf_get_u8(ئۇچۇر, &type)) != 0)
		اذهب out;
	إذا (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		اذهب out;
	}
	/* Reply should start with "query" */
	إذا (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(ئۇچۇر, &cp, عدم)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	ret = xcalloc(1, حجم(*ret));
	طالما (sshbuf_len(ئۇچۇر)) {
		ret = xrecallocarray(ret, i + 1, i + 2, حجم(*ret));
		إذا ((r = sshbuf_get_cstring(ئۇچۇر, ret + i, عدم)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = عدم; /* transferred */
 out:
	حرر(cp);
	stringlist_free(ret);
	sshbuf_free(ئۇچۇر);
	أرجع r;
}
