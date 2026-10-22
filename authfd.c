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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_AGENT_ਜਵਾਬ_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
ਸਥਿਰ ਪੂਰਨ
decode_ਜਵਾਬ(u_char type)
{
	ਜੇ (agent_failed(type))
		ਵਾਪਸ SSH_ERR_AGENT_FAILURE;
	ਨਹੀਂਤਾਂ ਜੇ (type == SSH_AGENT_SUCCESS)
		ਵਾਪਸ 0;
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
ਪੂਰਨ
ssh_get_authentication_socket_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *authsocket, ਪੂਰਨ *fdp)
{
	ਪੂਰਨ sock, oerrno;
	ਬਣਤਰ sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, ਆਕਾਰ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_ਰਸਤਾ, authsocket, ਆਕਾਰ(sunaddr.sun_ਰਸਤਾ));

	ਜੇ ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	ਜੇ (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (ਬਣਤਰ sockaddr *)&sunaddr, ਆਕਾਰ(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}
	ਜੇ (fdp != ਨਿਰਾ)
		*fdp = sock;
	ਨਹੀਂਤਾਂ
		close(sock);
	ਵਾਪਸ 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
ਪੂਰਨ
ssh_get_authentication_socket(ਪੂਰਨ *fdp)
{
	ਅਚਲ ਅੱਖਰ *authsocket;

	ਜੇ (fdp != ਨਿਰਾ)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	ਜੇ (authsocket == ਨਿਰਾ || *authsocket == '\0')
		ਵਾਪਸ SSH_ERR_AGENT_NOT_PRESENT;

	ਵਾਪਸ ssh_get_authentication_socket_ਰਸਤਾ(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
ਸਥਿਰ ਪੂਰਨ
ssh_request_ਜਵਾਬ(ਪੂਰਨ sock, ਬਣਤਰ sshbuf *request, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	ਪੂਰਨ r;
	ਮਾਪ_t l, len;
	ਅੱਖਰ buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	ਜੇ (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		ਵਾਪਸ SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	ਜੇ (atomicio(ਪਠ, sock, buf, 4) != 4)
	    ਵਾਪਸ SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	ਜੇ (len > MAX_AGENT_ਜਵਾਬ_LEN)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(ਜਵਾਬ);
	ਜਦੋਂ (len > 0) {
		l = len;
		ਜੇ (l > ਆਕਾਰ(buf))
			l = ਆਕਾਰ(buf);
		ਜੇ (atomicio(ਪਠ, sock, buf, l) != l)
			ਵਾਪਸ SSH_ERR_AGENT_COMMUNICATION;
		ਜੇ ((r = sshbuf_put(ਜਵਾਬ, buf, l)) != 0)
			ਵਾਪਸ r;
		len -= l;
	}
	ਵਾਪਸ 0;
}

/* Communicate with agent: sent request, read and decode status reply */
ਸਥਿਰ ਪੂਰਨ
ssh_request_ਜਵਾਬ_decode(ਪੂਰਨ sock, ਬਣਤਰ sshbuf *request)
{
	ਬਣਤਰ sshbuf *ਜਵਾਬ;
	ਪੂਰਨ r;
	u_char type;

	ਜੇ ((ਜਵਾਬ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = ssh_request_ਜਵਾਬ(sock, request, ਜਵਾਬ)) != 0 ||
	    (r = sshbuf_get_u8(ਜਵਾਬ, &type)) != 0 ||
	    (r = decode_ਜਵਾਬ(type)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਜਵਾਬ);
	ਵਾਪਸ r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
ਖਾਲੀ
ssh_close_authentication_socket(ਪੂਰਨ sock)
{
	ਜੇ (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != ਨਿਰਾ)
		close(sock);
}

/* Lock/unlock agent */
ਪੂਰਨ
ssh_ਤਾਲਾ_agent(ਪੂਰਨ sock, ਪੂਰਨ ਤਾਲਾ, ਅਚਲ ਅੱਖਰ *password)
{
	ਪੂਰਨ r;
	u_char type = ਤਾਲਾ ? SSH_AGENTC_ਤਾਲਾ : SSH_AGENTC_UNLOCK;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, type)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, password)) != 0 ||
	    (r = ssh_request_ਜਵਾਬ_decode(sock, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}


ਸਥਿਰ ਪੂਰਨ
deserialise_identity2(ਬਣਤਰ sshbuf *ids, ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp)
{
	ਪੂਰਨ r;
	ਅੱਖਰ *comment = ਨਿਰਾ;
	ਅਚਲ u_char *blob;
	ਮਾਪ_t blen;

	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (commentp != ਨਿਰਾ) {
		*commentp = comment;
		comment = ਨਿਰਾ;
	}
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(comment);
	ਵਾਪਸ r;
}

/*
 * Fetch list of identities held by the agent.
 */
ਪੂਰਨ
ssh_fetch_identitylist(ਪੂਰਨ sock, ਬਣਤਰ ssh_identitylist **idlp)
{
	u_char type;
	uint32_t ਅੰਕ, i;
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਬਣਤਰ ssh_identitylist *idl = ਨਿਰਾ;
	ਪੂਰਨ r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = ssh_request_ਜਵਾਬ(sock, ਸੁਨੇਹਾ, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Get message type, and verify that we got a proper answer. */
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Get the number of entries in the response and check it for sanity. */
	ਜੇ ((r = sshbuf_get_u32(ਸੁਨੇਹਾ, &ਅੰਕ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (ਅੰਕ > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ਅੰਕ == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Deserialise the response into a list of keys/comments */
	ਜੇ ((idl = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*idl))) == ਨਿਰਾ ||
	    (idl->ਕੁੰਜੀਆਂ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਅੰਕ, ਆਕਾਰ(*idl->ਕੁੰਜੀਆਂ))) == ਨਿਰਾ ||
	    (idl->comments = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਅੰਕ, ਆਕਾਰ(*idl->comments))) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਲਈ (i = 0; i < ਅੰਕ;) {
		ਜੇ ((r = deserialise_identity2(ਸੁਨੇਹਾ, &(idl->ਕੁੰਜੀਆਂ[i]),
		    &(idl->comments[i]))) != 0) {
			ਜੇ (r == SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				ਅੰਕ--;
				ਜਾਰੀ;
			} ਨਹੀਂਤਾਂ
				ਜਾਓ ਬਾਹਰਲਾ;
		}
		i++;
	}
	idl->nkeys = ਅੰਕ;
	*idlp = idl;
	idl = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਸੁਨੇਹਾ);
	ਜੇ (idl != ਨਿਰਾ)
		ssh_free_identitylist(idl);
	ਵਾਪਸ r;
}

ਖਾਲੀ
ssh_free_identitylist(ਬਣਤਰ ssh_identitylist *idl)
{
	ਮਾਪ_t i;

	ਜੇ (idl == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < idl->nkeys; i++) {
		ਜੇ (idl->ਕੁੰਜੀਆਂ != ਨਿਰਾ)
			sshkey_free(idl->ਕੁੰਜੀਆਂ[i]);
		ਜੇ (idl->comments != ਨਿਰਾ)
			ਮੁਕਤ(idl->comments[i]);
	}
	ਮੁਕਤ(idl->ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(idl->comments);
	ਮੁਕਤ(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ
ssh_agent_has_ਕੁੰਜੀ(ਪੂਰਨ sock, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r, ret = SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
	ਮਾਪ_t i;
	ਬਣਤਰ ssh_identitylist *idlist = ਨਿਰਾ;

	ਜੇ ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		ਵਾਪਸ r;
	}

	ਲਈ (i = 0; i < idlist->nkeys; i++) {
		ਜੇ (sshkey_equal_ਜਨਤਕ(idlist->ਕੁੰਜੀਆਂ[i], ਕੁੰਜੀ)) {
			ret = 0;
			ਰੋਕੋ;
		}
	}

	ssh_free_identitylist(idlist);
	ਵਾਪਸ ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
ਸਥਿਰ u_int
agent_encode_alg(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *alg)
{
	ਜੇ (alg != ਨਿਰਾ && sshkey_type_plain(ਕੁੰਜੀ->type) == ਕੁੰਜੀ_RSA) {
		ਜੇ (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			ਵਾਪਸ SSH_AGENT_RSA_SHA2_256;
		ਜੇ (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			ਵਾਪਸ SSH_AGENT_RSA_SHA2_512;
	}
	ਵਾਪਸ 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
ਪੂਰਨ
ssh_agent_sign(ਪੂਰਨ sock, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen, ਅਚਲ ਅੱਖਰ *alg, u_int compat)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_char *sig = ਨਿਰਾ, type = 0;
	ਮਾਪ_t len = 0;
	u_int flags = 0;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	*sigp = ਨਿਰਾ;
	*lenp = 0;

	ਜੇ (datalen > SSH_ਕੁੰਜੀ_MAX_SIGN_ਅੰਕੜੇ_ਮਾਪ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(ਕੁੰਜੀ, alg);
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(ਕੁੰਜੀ, ਸੁਨੇਹਾ)) != 0 ||
	    (r = sshbuf_put_string(ਸੁਨੇਹਾ, ਅੰਕੜੇ, datalen)) != 0 ||
	    (r = sshbuf_put_u32(ਸੁਨੇਹਾ, flags)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_request_ਜਵਾਬ(sock, ਸੁਨੇਹਾ, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_string(ਸੁਨੇਹਾ, &sig, &len)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	ਜੇ (!sshkey_is_sk(ਕੁੰਜੀ) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = ਨਿਰਾ;
	len = 0;
	r = 0;
 ਬਾਹਰਲਾ:
	freezero(sig, len);
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}

/* Encode key for a message to the agent. */

ਸਥਿਰ ਪੂਰਨ
encode_dest_constraint_hop(ਬਣਤਰ sshbuf *m,
    ਅਚਲ ਬਣਤਰ dest_constraint_hop *dch)
{
	ਬਣਤਰ sshbuf *b;
	u_int i;
	ਪੂਰਨ r;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, ਨਿਰਾ, 0)) != 0) /* reserved */
		ਜਾਓ ਬਾਹਰਲਾ;
	ਲਈ (i = 0; i < dch->nkeys; i++) {
		ਜੇ ((r = sshkey_puts(dch->ਕੁੰਜੀਆਂ[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->ਕੁੰਜੀ_is_ca[i] != 0)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_stringb(m, b)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
encode_dest_constraint(ਬਣਤਰ sshbuf *m, ਅਚਲ ਬਣਤਰ dest_constraint *dc)
{
	ਬਣਤਰ sshbuf *b;
	ਪੂਰਨ r;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->ਮੰਜ਼ਿਲ)) != 0 ||
	    (r = sshbuf_put_string(b, ਨਿਰਾ, 0)) != 0) /* reserved */
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshbuf_put_stringb(m, b)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
encode_constraints(ਬਣਤਰ sshbuf *m, u_int life, u_int confirm,
    ਅਚਲ ਅੱਖਰ *provider,
    ਬਣਤਰ dest_constraint **dest_constraints, ਮਾਪ_t ndest_constraints,
    ਪੂਰਨ cert_only, ਬਣਤਰ sshkey **certs, ਮਾਪ_t ncerts)
{
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਮਾਪ_t i;

	ਜੇ (life != 0) {
		ਜੇ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (confirm != 0) {
		ਜੇ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (provider != ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (dest_constraints != ਨਿਰਾ && ndest_constraints > 0) {
		ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਲਈ (i = 0; i < ndest_constraints; i++) {
			ਜੇ ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		sshbuf_free(b);
		b = ਨਿਰਾ;
	}
	ਜੇ (ncerts != 0) {
		ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਲਈ (i = 0; i < ncerts; i++) {
			ਜੇ ((r = sshkey_puts(certs[i], b)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		sshbuf_free(b);
		b = ਨਿਰਾ;
	}
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ਪੂਰਨ
ssh_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_constrained(ਪੂਰਨ sock, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *comment, u_int life, u_int confirm,
    ਅਚਲ ਅੱਖਰ *provider, ਬਣਤਰ dest_constraint **dest_constraints,
    ਮਾਪ_t ndest_constraints)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	ਚੋਣ (ਕੁੰਜੀ->type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
	ਹਾਲਤ ਕੁੰਜੀ_RSA_CERT:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
#ਜੇ_ਅੰਤ
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_CERT:
	ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519:
	ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519_CERT:
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ਜੋੜੋ_ID_CONSTRAINED :
		    SSH2_AGENTC_ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ;
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, type)) != 0 ||
		    (r = sshkey_ਨਿੱਜੀ_serialize(ਕੁੰਜੀ, ਸੁਨੇਹਾ)) != 0 ||
		    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, comment)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
	ਮੂਲ:
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (constrained &&
	    (r = encode_constraints(ਸੁਨੇਹਾ, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, ਨਿਰਾ, 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_request_ਜਵਾਬ_decode(sock, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ਪੂਰਨ
ssh_remove_ਪਛਾਣ_ਤੱਤ(ਪੂਰਨ sock, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;
	u_char *blob = ਨਿਰਾ;
	ਮਾਪ_t blen;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	ਜੇ (ਕੁੰਜੀ->type != ਕੁੰਜੀ_UNSPEC) {
		ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_blob(ਕੁੰਜੀ, &blob, &blen)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ,
		    SSH2_AGENTC_REMOVE_ਪਛਾਣ_ਤੱਤ)) != 0 ||
		    (r = sshbuf_put_string(ਸੁਨੇਹਾ, blob, blen)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = ssh_request_ਜਵਾਬ_decode(sock, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (blob != ਨਿਰਾ)
		freezero(blob, blen);
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ਪੂਰਨ
ssh_update_card(ਪੂਰਨ sock, ਪੂਰਨ ਜੋੜੋ, ਅਚਲ ਅੱਖਰ *reader_id, ਅਚਲ ਅੱਖਰ *pin,
    u_int life, u_int confirm,
    ਬਣਤਰ dest_constraint **dest_constraints, ਮਾਪ_t ndest_constraints,
    ਪੂਰਨ cert_only, ਬਣਤਰ sshkey **certs, ਮਾਪ_t ncerts)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	ਜੇ (ਜੋੜੋ) {
		type = constrained ?
		    SSH_AGENTC_ਜੋੜੋ_SMARTCARD_ਕੁੰਜੀ_CONSTRAINED :
		    SSH_AGENTC_ਜੋੜੋ_SMARTCARD_ਕੁੰਜੀ;
	} ਨਹੀਂਤਾਂ
		type = SSH_AGENTC_REMOVE_SMARTCARD_ਕੁੰਜੀ;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, type)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, pin)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (constrained &&
	    (r = encode_constraints(ਸੁਨੇਹਾ, life, confirm, ਨਿਰਾ,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_request_ਜਵਾਬ_decode(sock, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
ਪੂਰਨ
ssh_remove_all_identities(ਪੂਰਨ sock, ਪੂਰਨ ਸੰਸਕਰਣ)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	u_char type = (ਸੰਸਕਰਣ == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	ਪੂਰਨ r;

	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, type)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_request_ਜਵਾਬ_decode(sock, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
ਪੂਰਨ
ssh_agent_bind_hostkey(ਪੂਰਨ sock, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ ਬਣਤਰ sshbuf *session_id, ਅਚਲ ਬਣਤਰ sshbuf *signature,
    ਪੂਰਨ forwarding)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || session_id == ਨਿਰਾ || signature == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(ਕੁੰਜੀ, ਸੁਨੇਹਾ)) != 0 ||
	    (r = sshbuf_put_stringb(ਸੁਨੇਹਾ, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(ਸੁਨੇਹਾ, signature)) != 0 ||
	    (r = sshbuf_put_u8(ਸੁਨੇਹਾ, forwarding ? 1 : 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_request_ਜਵਾਬ_decode(sock, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}

/* Queries supported extension request types */
ਪੂਰਨ
ssh_agent_query_extensions(ਪੂਰਨ sock, ਅੱਖਰ ***exts)
{
	ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;
	u_char type;
	ਅੱਖਰ *cp = ਨਿਰਾ, **ret = ਨਿਰਾ;
	ਮਾਪ_t i = 0;

	*exts = ਨਿਰਾ;
	ਜੇ ((ਸੁਨੇਹਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u8(ਸੁਨੇਹਾ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ਸੁਨੇਹਾ, "query")) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_request_ਜਵਾਬ(sock, ਸੁਨੇਹਾ, ਸੁਨੇਹਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshbuf_get_u8(ਸੁਨੇਹਾ, &type)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Reply should start with "query" */
	ਜੇ (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(ਸੁਨੇਹਾ, &cp, ਨਿਰਾ)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ret = xcalloc(1, ਆਕਾਰ(*ret));
	ਜਦੋਂ (sshbuf_len(ਸੁਨੇਹਾ)) {
		ret = xrecallocarray(ret, i + 1, i + 2, ਆਕਾਰ(*ret));
		ਜੇ ((r = sshbuf_get_cstring(ਸੁਨੇਹਾ, ret + i, ਨਿਰਾ)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = ਨਿਰਾ; /* transferred */
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(cp);
	stringlist_free(ret);
	sshbuf_free(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}
