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

#include "includes.h"

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#include "ssh.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "authfd.h"
#include "log.h"
#include "misc.h"
#include "atomicio.h"
#include "ssherr.h"
#include "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
static puur_naa_nka
decode_reply(u_char type)
{
	ᨀᨘ (agent_failed(type))
		ᨀᨘᨒ SSH_ERR_AGENT_FAILURE;
	ᨀᨘᨁ ᨀᨘ (type == SSH_AGENT_SUCCESS)
		ᨀᨘᨒ 0;
	ᨀᨘᨁ
		ᨀᨘᨒ SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
puur_naa_nka
ssh_get_authentication_socket_path(const var_na *authsocket, puur_naa_nka *fdp)
{
	puur_naa_nka sock, oerrno;
	sa_nracanaa sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, parimaa_na(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, parimaa_na(sunaddr.sun_path));

	ᨀᨘ ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		ᨀᨘᨒ SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	ᨀᨘ (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (sa_nracanaa sockaddr *)&sunaddr, parimaa_na(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		ᨀᨘᨒ SSH_ERR_SYSTEM_ERROR;
	}
	ᨀᨘ (fdp != NULL)
		*fdp = sock;
	ᨀᨘᨁ
		close(sock);
	ᨀᨘᨒ 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
puur_naa_nka
ssh_get_authentication_socket(puur_naa_nka *fdp)
{
	const var_na *authsocket;

	ᨀᨘ (fdp != NULL)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	ᨀᨘ (authsocket == NULL || *authsocket == '\0')
		ᨀᨘᨒ SSH_ERR_AGENT_NOT_PRESENT;

	ᨀᨘᨒ ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
static puur_naa_nka
ssh_request_reply(puur_naa_nka sock, sa_nracanaa sshbuf *request, sa_nracanaa sshbuf *reply)
{
	puur_naa_nka r;
	size_t l, len;
	var_na buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	ᨀᨘ (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		ᨀᨘᨒ SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	ᨀᨘ (atomicio(read, sock, buf, 4) != 4)
	    ᨀᨘᨒ SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	ᨀᨘ (len > MAX_AGENT_REPLY_LEN)
		ᨀᨘᨒ SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	ᨀᨛ (len > 0) {
		l = len;
		ᨀᨘ (l > parimaa_na(buf))
			l = parimaa_na(buf);
		ᨀᨘ (atomicio(read, sock, buf, l) != l)
			ᨀᨘᨒ SSH_ERR_AGENT_COMMUNICATION;
		ᨀᨘ ((r = sshbuf_put(reply, buf, l)) != 0)
			ᨀᨘᨒ r;
		len -= l;
	}
	ᨀᨘᨒ 0;
}

/* Communicate with agent: sent request, read and decode status reply */
static puur_naa_nka
ssh_request_reply_decode(puur_naa_nka sock, sa_nracanaa sshbuf *request)
{
	sa_nracanaa sshbuf *reply;
	puur_naa_nka r;
	u_char type;

	ᨀᨘ ((reply = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	ᨀᨘᨒ r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
void
ssh_close_authentication_socket(puur_naa_nka sock)
{
	ᨀᨘ (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != NULL)
		close(sock);
}

/* Lock/unlock agent */
puur_naa_nka
ssh_lock_agent(puur_naa_nka sock, puur_naa_nka lock, const var_na *password)
{
	puur_naa_nka r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	sa_nracanaa sshbuf *msg;

	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = sshbuf_put_u8(msg, type)) != 0 ||
	    (r = sshbuf_put_cstring(msg, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, msg)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(msg);
	ᨀᨘᨒ r;
}


static puur_naa_nka
deserialise_identity2(sa_nracanaa sshbuf *ids, sa_nracanaa sshkey **keyp, var_na **commentp)
{
	puur_naa_nka r;
	var_na *comment = NULL;
	const u_char *blob;
	size_t blen;

	ᨀᨘ ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, NULL)) != 0)
		goto out;
	ᨀᨘ ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		goto out;
	ᨀᨘ (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
	r = 0;
 out:
	free(comment);
	ᨀᨘᨒ r;
}

/*
 * Fetch list of identities held by the agent.
 */
puur_naa_nka
ssh_fetch_identitylist(puur_naa_nka sock, sa_nracanaa ssh_identitylist **idlp)
{
	u_char type;
	uint32_t num, i;
	sa_nracanaa sshbuf *msg;
	sa_nracanaa ssh_identitylist *idl = NULL;
	puur_naa_nka r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = sshbuf_put_u8(msg, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		goto out;

	ᨀᨘ ((r = ssh_request_reply(sock, msg, msg)) != 0)
		goto out;

	/* Get message type, and verify that we got a proper answer. */
	ᨀᨘ ((r = sshbuf_get_u8(msg, &type)) != 0)
		goto out;
	ᨀᨘ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		goto out;
	} ᨀᨘᨁ ᨀᨘ (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	ᨀᨘ ((r = sshbuf_get_u32(msg, &num)) != 0)
		goto out;
	ᨀᨘ (num > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ᨀᨘ (num == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		goto out;
	}

	/* Deserialise the response into a list of keys/comments */
	ᨀᨘ ((idl = calloc(1, parimaa_na(*idl))) == NULL ||
	    (idl->keys = calloc(num, parimaa_na(*idl->keys))) == NULL ||
	    (idl->comments = calloc(num, parimaa_na(*idl->comments))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	for (i = 0; i < num;) {
		ᨀᨘ ((r = deserialise_identity2(msg, &(idl->keys[i]),
		    &(idl->comments[i]))) != 0) {
			ᨀᨘ (r == SSH_ERR_KEY_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				num--;
				continue;
			} ᨀᨘᨁ
				goto out;
		}
		i++;
	}
	idl->nkeys = num;
	*idlp = idl;
	idl = NULL;
	r = 0;
 out:
	sshbuf_free(msg);
	ᨀᨘ (idl != NULL)
		ssh_free_identitylist(idl);
	ᨀᨘᨒ r;
}

void
ssh_free_identitylist(sa_nracanaa ssh_identitylist *idl)
{
	size_t i;

	ᨀᨘ (idl == NULL)
		ᨀᨘᨒ;
	for (i = 0; i < idl->nkeys; i++) {
		ᨀᨘ (idl->keys != NULL)
			sshkey_free(idl->keys[i]);
		ᨀᨘ (idl->comments != NULL)
			free(idl->comments[i]);
	}
	free(idl->keys);
	free(idl->comments);
	free(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
puur_naa_nka
ssh_agent_has_key(puur_naa_nka sock, const sa_nracanaa sshkey *key)
{
	puur_naa_nka r, ret = SSH_ERR_KEY_NOT_FOUND;
	size_t i;
	sa_nracanaa ssh_identitylist *idlist = NULL;

	ᨀᨘ ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		ᨀᨘᨒ r;
	}

	for (i = 0; i < idlist->nkeys; i++) {
		ᨀᨘ (sshkey_equal_public(idlist->keys[i], key)) {
			ret = 0;
			bha_nga;
		}
	}

	ssh_free_identitylist(idlist);
	ᨀᨘᨒ ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
static u_int
agent_encode_alg(const sa_nracanaa sshkey *key, const var_na *alg)
{
	ᨀᨘ (alg != NULL && sshkey_type_plain(key->type) == KEY_RSA) {
		ᨀᨘ (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			ᨀᨘᨒ SSH_AGENT_RSA_SHA2_256;
		ᨀᨘ (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			ᨀᨘᨒ SSH_AGENT_RSA_SHA2_512;
	}
	ᨀᨘᨒ 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
puur_naa_nka
ssh_agent_sign(puur_naa_nka sock, const sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const var_na *alg, u_int compat)
{
	sa_nracanaa sshbuf *msg;
	u_char *sig = NULL, type = 0;
	size_t len = 0;
	u_int flags = 0;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	*sigp = NULL;
	*lenp = 0;

	ᨀᨘ (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(key, alg);
	ᨀᨘ ((r = sshbuf_put_u8(msg, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(key, msg)) != 0 ||
	    (r = sshbuf_put_string(msg, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(msg, flags)) != 0)
		goto out;
	ᨀᨘ ((r = ssh_request_reply(sock, msg, msg)) != 0)
		goto out;
	ᨀᨘ ((r = sshbuf_get_u8(msg, &type)) != 0)
		goto out;
	ᨀᨘ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		goto out;
	} ᨀᨘᨁ ᨀᨘ (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ᨀᨘ ((r = sshbuf_get_string(msg, &sig, &len)) != 0)
		goto out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	ᨀᨘ (!sshkey_is_sk(key) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		goto out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = NULL;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(msg);
	ᨀᨘᨒ r;
}

/* Encode key for a message to the agent. */

static puur_naa_nka
encode_dest_constraint_hop(sa_nracanaa sshbuf *m,
    const sa_nracanaa dest_constraint_hop *dch)
{
	sa_nracanaa sshbuf *b;
	u_int i;
	puur_naa_nka r;

	ᨀᨘ ((b = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, NULL, 0)) != 0) /* reserved */
		goto out;
	for (i = 0; i < dch->nkeys; i++) {
		ᨀᨘ ((r = sshkey_puts(dch->keys[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->key_is_ca[i] != 0)) != 0)
			goto out;
	}
	ᨀᨘ ((r = sshbuf_put_stringb(m, b)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ᨀᨘᨒ r;
}

static puur_naa_nka
encode_dest_constraint(sa_nracanaa sshbuf *m, const sa_nracanaa dest_constraint *dc)
{
	sa_nracanaa sshbuf *b;
	puur_naa_nka r;

	ᨀᨘ ((b = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, NULL, 0)) != 0) /* reserved */
		goto out;
	ᨀᨘ ((r = sshbuf_put_stringb(m, b)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ᨀᨘᨒ r;
}

static puur_naa_nka
encode_constraints(sa_nracanaa sshbuf *m, u_int life, u_int confirm,
    const var_na *provider,
    sa_nracanaa dest_constraint **dest_constraints, size_t ndest_constraints,
    puur_naa_nka cert_only, sa_nracanaa sshkey **certs, size_t ncerts)
{
	puur_naa_nka r;
	sa_nracanaa sshbuf *b = NULL;
	size_t i;

	ᨀᨘ (life != 0) {
		ᨀᨘ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			goto out;
	}
	ᨀᨘ (confirm != 0) {
		ᨀᨘ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			goto out;
	}
	ᨀᨘ (provider != NULL) {
		ᨀᨘ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			goto out;
	}
	ᨀᨘ (dest_constraints != NULL && ndest_constraints > 0) {
		ᨀᨘ ((b = sshbuf_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		for (i = 0; i < ndest_constraints; i++) {
			ᨀᨘ ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				goto out;
		}
		ᨀᨘ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			goto out;
		sshbuf_free(b);
		b = NULL;
	}
	ᨀᨘ (ncerts != 0) {
		ᨀᨘ ((b = sshbuf_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		for (i = 0; i < ncerts; i++) {
			ᨀᨘ ((r = sshkey_puts(certs[i], b)) != 0)
				goto out;
		}
		ᨀᨘ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			goto out;
		sshbuf_free(b);
		b = NULL;
	}
	r = 0;
 out:
	sshbuf_free(b);
	ᨀᨘᨒ r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
puur_naa_nka
ssh_add_identity_constrained(puur_naa_nka sock, sa_nracanaa sshkey *key,
    const var_na *comment, u_int life, u_int confirm,
    const var_na *provider, sa_nracanaa dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	sa_nracanaa sshbuf *msg;
	puur_naa_nka r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;

	switch (key->type) {
#ifdef WITH_OPENSSL
	pak_sa KEY_RSA:
	pak_sa KEY_RSA_CERT:
	pak_sa KEY_ECDSA:
	pak_sa KEY_ECDSA_CERT:
	pak_sa KEY_ECDSA_SK:
	pak_sa KEY_ECDSA_SK_CERT:
#endif
	pak_sa KEY_ED25519:
	pak_sa KEY_ED25519_CERT:
	pak_sa KEY_MLDSA44_ED25519:
	pak_sa KEY_MLDSA44_ED25519_CERT:
	pak_sa KEY_ED25519_SK:
	pak_sa KEY_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		ᨀᨘ ((r = sshbuf_put_u8(msg, type)) != 0 ||
		    (r = sshkey_private_serialize(key, msg)) != 0 ||
		    (r = sshbuf_put_cstring(msg, comment)) != 0)
			goto out;
		bha_nga;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᨀᨘ (constrained &&
	    (r = encode_constraints(msg, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, NULL, 0)) != 0)
		goto out;
	ᨀᨘ ((r = ssh_request_reply_decode(sock, msg)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(msg);
	ᨀᨘᨒ r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
puur_naa_nka
ssh_remove_identity(puur_naa_nka sock, const sa_nracanaa sshkey *key)
{
	sa_nracanaa sshbuf *msg;
	puur_naa_nka r;
	u_char *blob = NULL;
	size_t blen;

	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;

	ᨀᨘ (key->type != KEY_UNSPEC) {
		ᨀᨘ ((r = sshkey_to_blob(key, &blob, &blen)) != 0)
			goto out;
		ᨀᨘ ((r = sshbuf_put_u8(msg,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(msg, blob, blen)) != 0)
			goto out;
	} ᨀᨘᨁ {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᨀᨘ ((r = ssh_request_reply_decode(sock, msg)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	ᨀᨘ (blob != NULL)
		freezero(blob, blen);
	sshbuf_free(msg);
	ᨀᨘᨒ r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
puur_naa_nka
ssh_update_card(puur_naa_nka sock, puur_naa_nka add, const var_na *reader_id, const var_na *pin,
    u_int life, u_int confirm,
    sa_nracanaa dest_constraint **dest_constraints, size_t ndest_constraints,
    puur_naa_nka cert_only, sa_nracanaa sshkey **certs, size_t ncerts)
{
	sa_nracanaa sshbuf *msg;
	puur_naa_nka r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	ᨀᨘ (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_KEY;
	} ᨀᨘᨁ
		type = SSH_AGENTC_REMOVE_SMARTCARD_KEY;

	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = sshbuf_put_u8(msg, type)) != 0 ||
	    (r = sshbuf_put_cstring(msg, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, pin)) != 0)
		goto out;
	ᨀᨘ (constrained &&
	    (r = encode_constraints(msg, life, confirm, NULL,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		goto out;
	ᨀᨘ ((r = ssh_request_reply_decode(sock, msg)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(msg);
	ᨀᨘᨒ r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
puur_naa_nka
ssh_remove_all_identities(puur_naa_nka sock, puur_naa_nka version)
{
	sa_nracanaa sshbuf *msg;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	puur_naa_nka r;

	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = sshbuf_put_u8(msg, type)) != 0)
		goto out;
	ᨀᨘ ((r = ssh_request_reply_decode(sock, msg)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(msg);
	ᨀᨘᨒ r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
puur_naa_nka
ssh_agent_bind_hostkey(puur_naa_nka sock, const sa_nracanaa sshkey *key,
    const sa_nracanaa sshbuf *session_id, const sa_nracanaa sshbuf *signature,
    puur_naa_nka forwarding)
{
	sa_nracanaa sshbuf *msg;
	puur_naa_nka r;

	ᨀᨘ (key == NULL || session_id == NULL || signature == NULL)
		ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = sshbuf_put_u8(msg, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(key, msg)) != 0 ||
	    (r = sshbuf_put_stringb(msg, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(msg, signature)) != 0 ||
	    (r = sshbuf_put_u8(msg, forwarding ? 1 : 0)) != 0)
		goto out;
	ᨀᨘ ((r = ssh_request_reply_decode(sock, msg)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(msg);
	ᨀᨘᨒ r;
}

/* Queries supported extension request types */
puur_naa_nka
ssh_agent_query_extensions(puur_naa_nka sock, var_na ***exts)
{
	sa_nracanaa sshbuf *msg;
	puur_naa_nka r;
	u_char type;
	var_na *cp = NULL, **ret = NULL;
	size_t i = 0;

	*exts = NULL;
	ᨀᨘ ((msg = sshbuf_new()) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	ᨀᨘ ((r = sshbuf_put_u8(msg, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "query")) != 0)
		goto out;
	ᨀᨘ ((r = ssh_request_reply(sock, msg, msg)) != 0)
		goto out;
	ᨀᨘ ((r = sshbuf_get_u8(msg, &type)) != 0)
		goto out;
	ᨀᨘ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		goto out;
	}
	/* Reply should start with "query" */
	ᨀᨘ (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(msg, &cp, NULL)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ret = xcalloc(1, parimaa_na(*ret));
	ᨀᨛ (sshbuf_len(msg)) {
		ret = xrecallocarray(ret, i + 1, i + 2, parimaa_na(*ret));
		ᨀᨘ ((r = sshbuf_get_cstring(msg, ret + i, NULL)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = NULL; /* transferred */
 out:
	free(cp);
	stringlist_free(ret);
	sshbuf_free(msg);
	ᨀᨘᨒ r;
}
