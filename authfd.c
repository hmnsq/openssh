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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/un.h>
#અન્તર્ભાવ <sys/socket.h>

#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <errno.h>

#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
સ્થિર પૂર્ણાંક
decode_reply(u_char type)
{
	જો (agent_failed(type))
		પાછા SSH_ERR_AGENT_FAILURE;
	નહીંતર જો (type == SSH_AGENT_SUCCESS)
		પાછા 0;
	નહીંતર
		પાછા SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
પૂર્ણાંક
ssh_get_authentication_socket_path(અચલ અક્ષર *authsocket, પૂર્ણાંક *fdp)
{
	પૂર્ણાંક sock, oerrno;
	સંરચના sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, કદ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, કદ(sunaddr.sun_path));

	જો ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		પાછા SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	જો (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (સંરચના sockaddr *)&sunaddr, કદ(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}
	જો (fdp != ખાલી)
		*fdp = sock;
	નહીંતર
		close(sock);
	પાછા 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
પૂર્ણાંક
ssh_get_authentication_socket(પૂર્ણાંક *fdp)
{
	અચલ અક્ષર *authsocket;

	જો (fdp != ખાલી)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	જો (authsocket == ખાલી || *authsocket == '\0')
		પાછા SSH_ERR_AGENT_NOT_PRESENT;

	પાછા ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
સ્થિર પૂર્ણાંક
ssh_request_reply(પૂર્ણાંક sock, સંરચના sshbuf *request, સંરચના sshbuf *reply)
{
	પૂર્ણાંક r;
	size_t l, len;
	અક્ષર buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	જો (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		પાછા SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	જો (atomicio(પઠ, sock, buf, 4) != 4)
	    પાછા SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	જો (len > MAX_AGENT_REPLY_LEN)
		પાછા SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	જ્યારે (len > 0) {
		l = len;
		જો (l > કદ(buf))
			l = કદ(buf);
		જો (atomicio(પઠ, sock, buf, l) != l)
			પાછા SSH_ERR_AGENT_COMMUNICATION;
		જો ((r = sshbuf_put(reply, buf, l)) != 0)
			પાછા r;
		len -= l;
	}
	પાછા 0;
}

/* Communicate with agent: sent request, read and decode status reply */
સ્થિર પૂર્ણાંક
ssh_request_reply_decode(પૂર્ણાંક sock, સંરચના sshbuf *request)
{
	સંરચના sshbuf *reply;
	પૂર્ણાંક r;
	u_char type;

	જો ((reply = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	પાછા r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
શૂન્ય
ssh_close_authentication_socket(પૂર્ણાંક sock)
{
	જો (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != ખાલી)
		close(sock);
}

/* Lock/unlock agent */
પૂર્ણાંક
ssh_lock_agent(પૂર્ણાંક sock, પૂર્ણાંક lock, અચલ અક્ષર *password)
{
	પૂર્ણાંક r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	સંરચના sshbuf *સંદેશ;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u8(સંદેશ, type)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, સંદેશ)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(સંદેશ);
	પાછા r;
}


સ્થિર પૂર્ણાંક
deserialise_identity2(સંરચના sshbuf *ids, સંરચના sshkey **keyp, અક્ષર **commentp)
{
	પૂર્ણાંક r;
	અક્ષર *comment = ખાલી;
	અચલ u_char *blob;
	size_t blen;

	જો ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, ખાલી)) != 0)
		જાઓ out;
	જો ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		જાઓ out;
	જો (commentp != ખાલી) {
		*commentp = comment;
		comment = ખાલી;
	}
	r = 0;
 out:
	મુક્ત(comment);
	પાછા r;
}

/*
 * Fetch list of identities held by the agent.
 */
પૂર્ણાંક
ssh_fetch_identitylist(પૂર્ણાંક sock, સંરચના ssh_identitylist **idlp)
{
	u_char type;
	uint32_t અંક, i;
	સંરચના sshbuf *સંદેશ;
	સંરચના ssh_identitylist *idl = ખાલી;
	પૂર્ણાંક r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		જાઓ out;

	જો ((r = ssh_request_reply(sock, સંદેશ, સંદેશ)) != 0)
		જાઓ out;

	/* Get message type, and verify that we got a proper answer. */
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0)
		જાઓ out;
	જો (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		જાઓ out;
	} નહીંતર જો (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	જો ((r = sshbuf_get_u32(સંદેશ, &અંક)) != 0)
		જાઓ out;
	જો (અંક > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (અંક == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		જાઓ out;
	}

	/* Deserialise the response into a list of keys/comments */
	જો ((idl = calloc(1, કદ(*idl))) == ખાલી ||
	    (idl->ચાવીઓ = calloc(અંક, કદ(*idl->ચાવીઓ))) == ખાલી ||
	    (idl->comments = calloc(અંક, કદ(*idl->comments))) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	માટે (i = 0; i < અંક;) {
		જો ((r = deserialise_identity2(સંદેશ, &(idl->ચાવીઓ[i]),
		    &(idl->comments[i]))) != 0) {
			જો (r == SSH_ERR_ચાવી_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				અંક--;
				ચાલુ;
			} નહીંતર
				જાઓ out;
		}
		i++;
	}
	idl->nkeys = અંક;
	*idlp = idl;
	idl = ખાલી;
	r = 0;
 out:
	sshbuf_free(સંદેશ);
	જો (idl != ખાલી)
		ssh_free_identitylist(idl);
	પાછા r;
}

શૂન્ય
ssh_free_identitylist(સંરચના ssh_identitylist *idl)
{
	size_t i;

	જો (idl == ખાલી)
		પાછા;
	માટે (i = 0; i < idl->nkeys; i++) {
		જો (idl->ચાવીઓ != ખાલી)
			sshkey_free(idl->ચાવીઓ[i]);
		જો (idl->comments != ખાલી)
			મુક્ત(idl->comments[i]);
	}
	મુક્ત(idl->ચાવીઓ);
	મુક્ત(idl->comments);
	મુક્ત(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક
ssh_agent_has_ચાવી(પૂર્ણાંક sock, અચલ સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r, ret = SSH_ERR_ચાવી_NOT_FOUND;
	size_t i;
	સંરચના ssh_identitylist *idlist = ખાલી;

	જો ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		પાછા r;
	}

	માટે (i = 0; i < idlist->nkeys; i++) {
		જો (sshkey_equal_public(idlist->ચાવીઓ[i], ચાવી)) {
			ret = 0;
			તોડો;
		}
	}

	ssh_free_identitylist(idlist);
	પાછા ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
સ્થિર u_int
agent_encode_alg(અચલ સંરચના sshkey *ચાવી, અચલ અક્ષર *alg)
{
	જો (alg != ખાલી && sshkey_type_plain(ચાવી->type) == ચાવી_RSA) {
		જો (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			પાછા SSH_AGENT_RSA_SHA2_256;
		જો (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			પાછા SSH_AGENT_RSA_SHA2_512;
	}
	પાછા 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
પૂર્ણાંક
ssh_agent_sign(પૂર્ણાંક sock, અચલ સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen, અચલ અક્ષર *alg, u_int compat)
{
	સંરચના sshbuf *સંદેશ;
	u_char *sig = ખાલી, type = 0;
	size_t len = 0;
	u_int flags = 0;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	*sigp = ખાલી;
	*lenp = 0;

	જો (datalen > SSH_ચાવી_MAX_SIGN_DATA_SIZE)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(ચાવી, alg);
	જો ((r = sshbuf_put_u8(સંદેશ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(ચાવી, સંદેશ)) != 0 ||
	    (r = sshbuf_put_string(સંદેશ, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(સંદેશ, flags)) != 0)
		જાઓ out;
	જો ((r = ssh_request_reply(sock, સંદેશ, સંદેશ)) != 0)
		જાઓ out;
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0)
		જાઓ out;
	જો (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		જાઓ out;
	} નહીંતર જો (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((r = sshbuf_get_string(સંદેશ, &sig, &len)) != 0)
		જાઓ out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	જો (!sshkey_is_sk(ચાવી) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		જાઓ out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = ખાલી;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(સંદેશ);
	પાછા r;
}

/* Encode key for a message to the agent. */

સ્થિર પૂર્ણાંક
encode_dest_constraint_hop(સંરચના sshbuf *m,
    અચલ સંરચના dest_constraint_hop *dch)
{
	સંરચના sshbuf *b;
	u_int i;
	પૂર્ણાંક r;

	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, ખાલી, 0)) != 0) /* reserved */
		જાઓ out;
	માટે (i = 0; i < dch->nkeys; i++) {
		જો ((r = sshkey_puts(dch->ચાવીઓ[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->ચાવી_is_ca[i] != 0)) != 0)
			જાઓ out;
	}
	જો ((r = sshbuf_put_stringb(m, b)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

સ્થિર પૂર્ણાંક
encode_dest_constraint(સંરચના sshbuf *m, અચલ સંરચના dest_constraint *dc)
{
	સંરચના sshbuf *b;
	પૂર્ણાંક r;

	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, ખાલી, 0)) != 0) /* reserved */
		જાઓ out;
	જો ((r = sshbuf_put_stringb(m, b)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

સ્થિર પૂર્ણાંક
encode_constraints(સંરચના sshbuf *m, u_int life, u_int confirm,
    અચલ અક્ષર *provider,
    સંરચના dest_constraint **dest_constraints, size_t ndest_constraints,
    પૂર્ણાંક cert_only, સંરચના sshkey **certs, size_t ncerts)
{
	પૂર્ણાંક r;
	સંરચના sshbuf *b = ખાલી;
	size_t i;

	જો (life != 0) {
		જો ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			જાઓ out;
	}
	જો (confirm != 0) {
		જો ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			જાઓ out;
	}
	જો (provider != ખાલી) {
		જો ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			જાઓ out;
	}
	જો (dest_constraints != ખાલી && ndest_constraints > 0) {
		જો ((b = sshbuf_new()) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		માટે (i = 0; i < ndest_constraints; i++) {
			જો ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				જાઓ out;
		}
		જો ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			જાઓ out;
		sshbuf_free(b);
		b = ખાલી;
	}
	જો (ncerts != 0) {
		જો ((b = sshbuf_new()) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		માટે (i = 0; i < ncerts; i++) {
			જો ((r = sshkey_puts(certs[i], b)) != 0)
				જાઓ out;
		}
		જો ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			જાઓ out;
		sshbuf_free(b);
		b = ખાલી;
	}
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
પૂર્ણાંક
ssh_add_identity_constrained(પૂર્ણાંક sock, સંરચના sshkey *ચાવી,
    અચલ અક્ષર *comment, u_int life, u_int confirm,
    અચલ અક્ષર *provider, સંરચના dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	પસંદગી (ચાવી->type) {
#ifdef WITH_OPENSSL
	સ્થિતિ ચાવી_RSA:
	સ્થિતિ ચાવી_RSA_CERT:
	સ્થિતિ ચાવી_ECDSA:
	સ્થિતિ ચાવી_ECDSA_CERT:
	સ્થિતિ ચાવી_ECDSA_SK:
	સ્થિતિ ચાવી_ECDSA_SK_CERT:
#endif
	સ્થિતિ ચાવી_ED25519:
	સ્થિતિ ચાવી_ED25519_CERT:
	સ્થિતિ ચાવી_MLDSA44_ED25519:
	સ્થિતિ ચાવી_MLDSA44_ED25519_CERT:
	સ્થિતિ ચાવી_ED25519_SK:
	સ્થિતિ ચાવી_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		જો ((r = sshbuf_put_u8(સંદેશ, type)) != 0 ||
		    (r = sshkey_private_serialize(ચાવી, સંદેશ)) != 0 ||
		    (r = sshbuf_put_cstring(સંદેશ, comment)) != 0)
			જાઓ out;
		તોડો;
	મૂળભૂત:
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (constrained &&
	    (r = encode_constraints(સંદેશ, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, ખાલી, 0)) != 0)
		જાઓ out;
	જો ((r = ssh_request_reply_decode(sock, સંદેશ)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(સંદેશ);
	પાછા r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
પૂર્ણાંક
ssh_remove_identity(પૂર્ણાંક sock, અચલ સંરચના sshkey *ચાવી)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;
	u_char *blob = ખાલી;
	size_t blen;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	જો (ચાવી->type != ચાવી_UNSPEC) {
		જો ((r = sshkey_to_blob(ચાવી, &blob, &blen)) != 0)
			જાઓ out;
		જો ((r = sshbuf_put_u8(સંદેશ,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(સંદેશ, blob, blen)) != 0)
			જાઓ out;
	} નહીંતર {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો ((r = ssh_request_reply_decode(sock, સંદેશ)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	જો (blob != ખાલી)
		freezero(blob, blen);
	sshbuf_free(સંદેશ);
	પાછા r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
પૂર્ણાંક
ssh_update_card(પૂર્ણાંક sock, પૂર્ણાંક add, અચલ અક્ષર *reader_id, અચલ અક્ષર *pin,
    u_int life, u_int confirm,
    સંરચના dest_constraint **dest_constraints, size_t ndest_constraints,
    પૂર્ણાંક cert_only, સંરચના sshkey **certs, size_t ncerts)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	જો (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_ચાવી_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_ચાવી;
	} નહીંતર
		type = SSH_AGENTC_REMOVE_SMARTCARD_ચાવી;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u8(સંદેશ, type)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, pin)) != 0)
		જાઓ out;
	જો (constrained &&
	    (r = encode_constraints(સંદેશ, life, confirm, ખાલી,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		જાઓ out;
	જો ((r = ssh_request_reply_decode(sock, સંદેશ)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(સંદેશ);
	પાછા r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
પૂર્ણાંક
ssh_remove_all_identities(પૂર્ણાંક sock, પૂર્ણાંક version)
{
	સંરચના sshbuf *સંદેશ;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	પૂર્ણાંક r;

	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u8(સંદેશ, type)) != 0)
		જાઓ out;
	જો ((r = ssh_request_reply_decode(sock, સંદેશ)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(સંદેશ);
	પાછા r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
પૂર્ણાંક
ssh_agent_bind_hostkey(પૂર્ણાંક sock, અચલ સંરચના sshkey *ચાવી,
    અચલ સંરચના sshbuf *session_id, અચલ સંરચના sshbuf *signature,
    પૂર્ણાંક forwarding)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;

	જો (ચાવી == ખાલી || session_id == ખાલી || signature == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(ચાવી, સંદેશ)) != 0 ||
	    (r = sshbuf_put_stringb(સંદેશ, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(સંદેશ, signature)) != 0 ||
	    (r = sshbuf_put_u8(સંદેશ, forwarding ? 1 : 0)) != 0)
		જાઓ out;
	જો ((r = ssh_request_reply_decode(sock, સંદેશ)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(સંદેશ);
	પાછા r;
}

/* Queries supported extension request types */
પૂર્ણાંક
ssh_agent_query_extensions(પૂર્ણાંક sock, અક્ષર ***exts)
{
	સંરચના sshbuf *સંદેશ;
	પૂર્ણાંક r;
	u_char type;
	અક્ષર *cp = ખાલી, **ret = ખાલી;
	size_t i = 0;

	*exts = ખાલી;
	જો ((સંદેશ = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u8(સંદેશ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(સંદેશ, "query")) != 0)
		જાઓ out;
	જો ((r = ssh_request_reply(sock, સંદેશ, સંદેશ)) != 0)
		જાઓ out;
	જો ((r = sshbuf_get_u8(સંદેશ, &type)) != 0)
		જાઓ out;
	જો (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		જાઓ out;
	}
	/* Reply should start with "query" */
	જો (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(સંદેશ, &cp, ખાલી)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	ret = xcalloc(1, કદ(*ret));
	જ્યારે (sshbuf_len(સંદેશ)) {
		ret = xrecallocarray(ret, i + 1, i + 2, કદ(*ret));
		જો ((r = sshbuf_get_cstring(સંદેશ, ret + i, ખાલી)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = ખાલી; /* transferred */
 out:
	મુક્ત(cp);
	stringlist_free(ret);
	sshbuf_free(સંદેશ);
	પાછા r;
}
