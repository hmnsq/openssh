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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <errno.h>

#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
decode_reply(u_char type)
{
	ಯದಿ (agent_failed(type))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_FAILURE;
	ಅನ್ಯಥಾ ಯದಿ (type == SSH_AGENT_SUCCESS)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_get_authentication_socket_path(ಧ್ರುವ ವರ್ಣ *authsocket, ಪೂರ್ಣಾಙ್ಕ *fdp)
{
	ಪೂರ್ಣಾಙ್ಕ sock, oerrno;
	ಸಂರಚನಾ sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, ಪರಿಮಾಣ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, ಪರಿಮಾಣ(sunaddr.sun_path));

	ಯದಿ ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	ಯದಿ (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (ಸಂರಚನಾ sockaddr *)&sunaddr, ಪರಿಮಾಣ(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}
	ಯದಿ (fdp != ರಿಕ್ತ)
		*fdp = sock;
	ಅನ್ಯಥಾ
		close(sock);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_get_authentication_socket(ಪೂರ್ಣಾಙ್ಕ *fdp)
{
	ಧ್ರುವ ವರ್ಣ *authsocket;

	ಯದಿ (fdp != ರಿಕ್ತ)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	ಯದಿ (authsocket == ರಿಕ್ತ || *authsocket == '\0')
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_NOT_PRESENT;

	ಪ್ರತ್ಯಾಗಮ ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_request_reply(ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *request, ಸಂರಚನಾ sshbuf *reply)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t l, len;
	ವರ್ಣ buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	ಯದಿ (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	ಯದಿ (atomicio(ಪಠ, sock, buf, 4) != 4)
	    ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	ಯದಿ (len > MAX_AGENT_REPLY_LEN)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	ಯಾವತ್ (len > 0) {
		l = len;
		ಯದಿ (l > ಪರಿಮಾಣ(buf))
			l = ಪರಿಮಾಣ(buf);
		ಯದಿ (atomicio(ಪಠ, sock, buf, l) != l)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_COMMUNICATION;
		ಯದಿ ((r = sshbuf_put(reply, buf, l)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
		len -= l;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Communicate with agent: sent request, read and decode status reply */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_request_reply_decode(ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshbuf *request)
{
	ಸಂರಚನಾ sshbuf *reply;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char type;

	ಯದಿ ((reply = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
ಶೂನ್ಯ
ssh_close_authentication_socket(ಪೂರ್ಣಾಙ್ಕ sock)
{
	ಯದಿ (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != ರಿಕ್ತ)
		close(sock);
}

/* Lock/unlock agent */
ಪೂರ್ಣಾಙ್ಕ
ssh_lock_agent(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ lock, ಧ್ರುವ ವರ್ಣ *password)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_identity2(ಸಂರಚನಾ sshbuf *ids, ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *comment = ರಿಕ್ತ;
	ಧ್ರುವ u_char *blob;
	size_t blen;

	ಯದಿ ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (commentp != ರಿಕ್ತ) {
		*commentp = comment;
		comment = ರಿಕ್ತ;
	}
	r = 0;
 out:
	ಮುಕ್ತ(comment);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Fetch list of identities held by the agent.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_fetch_identitylist(ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ ssh_identitylist **idlp)
{
	u_char type;
	uint32_t ಅಂಕೆ, i;
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಸಂರಚನಾ ssh_identitylist *idl = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = ssh_request_reply(sock, ಸಂದೇಶ, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;

	/* Get message type, and verify that we got a proper answer. */
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	ಯದಿ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಅಂಕೆ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (ಅಂಕೆ > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (ಅಂಕೆ == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		ಗಚ್ಛ out;
	}

	/* Deserialise the response into a list of keys/comments */
	ಯದಿ ((idl = calloc(1, ಪರಿಮಾಣ(*idl))) == ರಿಕ್ತ ||
	    (idl->ಕೀಲಿಗಳು = calloc(ಅಂಕೆ, ಪರಿಮಾಣ(*idl->ಕೀಲಿಗಳು))) == ರಿಕ್ತ ||
	    (idl->comments = calloc(ಅಂಕೆ, ಪರಿಮಾಣ(*idl->comments))) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ;) {
		ಯದಿ ((r = deserialise_identity2(ಸಂದೇಶ, &(idl->ಕೀಲಿಗಳು[i]),
		    &(idl->comments[i]))) != 0) {
			ಯದಿ (r == SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				ಅಂಕೆ--;
				ಅನುವರ್ತ;
			} ಅನ್ಯಥಾ
				ಗಚ್ಛ out;
		}
		i++;
	}
	idl->nkeys = ಅಂಕೆ;
	*idlp = idl;
	idl = ರಿಕ್ತ;
	r = 0;
 out:
	sshbuf_free(ಸಂದೇಶ);
	ಯದಿ (idl != ರಿಕ್ತ)
		ssh_free_identitylist(idl);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಶೂನ್ಯ
ssh_free_identitylist(ಸಂರಚನಾ ssh_identitylist *idl)
{
	size_t i;

	ಯದಿ (idl == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < idl->nkeys; i++) {
		ಯದಿ (idl->ಕೀಲಿಗಳು != ರಿಕ್ತ)
			sshkey_free(idl->ಕೀಲಿಗಳು[i]);
		ಯದಿ (idl->comments != ರಿಕ್ತ)
			ಮುಕ್ತ(idl->comments[i]);
	}
	ಮುಕ್ತ(idl->ಕೀಲಿಗಳು);
	ಮುಕ್ತ(idl->comments);
	ಮುಕ್ತ(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_agent_has_ಕೀಲಿ(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r, ret = SSH_ERR_ಕೀಲಿ_NOT_FOUND;
	size_t i;
	ಸಂರಚನಾ ssh_identitylist *idlist = ರಿಕ್ತ;

	ಯದಿ ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತಿ (i = 0; i < idlist->nkeys; i++) {
		ಯದಿ (sshkey_equal_public(idlist->ಕೀಲಿಗಳು[i], ಕೀಲಿ)) {
			ret = 0;
			ಭಙ್ಗ;
		}
	}

	ssh_free_identitylist(idlist);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
ಸ್ಥಿರ u_int
agent_encode_alg(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *alg)
{
	ಯದಿ (alg != ರಿಕ್ತ && sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA) {
		ಯದಿ (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			ಪ್ರತ್ಯಾಗಮ SSH_AGENT_RSA_SHA2_256;
		ಯದಿ (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			ಪ್ರತ್ಯಾಗಮ SSH_AGENT_RSA_SHA2_512;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
ಪೂರ್ಣಾಙ್ಕ
ssh_agent_sign(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen, ಧ್ರುವ ವರ್ಣ *alg, u_int compat)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_char *sig = ರಿಕ್ತ, type = 0;
	size_t len = 0;
	u_int flags = 0;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	*sigp = ರಿಕ್ತ;
	*lenp = 0;

	ಯದಿ (datalen > SSH_ಕೀಲಿ_MAX_SIGN_DATA_SIZE)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(ಕೀಲಿ, alg);
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(ಕೀಲಿ, ಸಂದೇಶ)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, flags)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_request_reply(sock, ಸಂದೇಶ, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ ಯದಿ (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_string(ಸಂದೇಶ, &sig, &len)) != 0)
		ಗಚ್ಛ out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	ಯದಿ (!sshkey_is_sk(ಕೀಲಿ) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		ಗಚ್ಛ out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = ರಿಕ್ತ;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Encode key for a message to the agent. */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
encode_dest_constraint_hop(ಸಂರಚನಾ sshbuf *m,
    ಧ್ರುವ ಸಂರಚನಾ dest_constraint_hop *dch)
{
	ಸಂರಚನಾ sshbuf *b;
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, ರಿಕ್ತ, 0)) != 0) /* reserved */
		ಗಚ್ಛ out;
	ಪ್ರತಿ (i = 0; i < dch->nkeys; i++) {
		ಯದಿ ((r = sshkey_puts(dch->ಕೀಲಿಗಳು[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->ಕೀಲಿ_is_ca[i] != 0)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_stringb(m, b)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
encode_dest_constraint(ಸಂರಚನಾ sshbuf *m, ಧ್ರುವ ಸಂರಚನಾ dest_constraint *dc)
{
	ಸಂರಚನಾ sshbuf *b;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, ರಿಕ್ತ, 0)) != 0) /* reserved */
		ಗಚ್ಛ out;
	ಯದಿ ((r = sshbuf_put_stringb(m, b)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
encode_constraints(ಸಂರಚನಾ sshbuf *m, u_int life, u_int confirm,
    ಧ್ರುವ ವರ್ಣ *provider,
    ಸಂರಚನಾ dest_constraint **dest_constraints, size_t ndest_constraints,
    ಪೂರ್ಣಾಙ್ಕ cert_only, ಸಂರಚನಾ sshkey **certs, size_t ncerts)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	size_t i;

	ಯದಿ (life != 0) {
		ಯದಿ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ (confirm != 0) {
		ಯದಿ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ (provider != ರಿಕ್ತ) {
		ಯದಿ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ (dest_constraints != ರಿಕ್ತ && ndest_constraints > 0) {
		ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಪ್ರತಿ (i = 0; i < ndest_constraints; i++) {
			ಯದಿ ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			ಗಚ್ಛ out;
		sshbuf_free(b);
		b = ರಿಕ್ತ;
	}
	ಯದಿ (ncerts != 0) {
		ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಪ್ರತಿ (i = 0; i < ncerts; i++) {
			ಯದಿ ((r = sshkey_puts(certs[i], b)) != 0)
				ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			ಗಚ್ಛ out;
		sshbuf_free(b);
		b = ರಿಕ್ತ;
	}
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_add_identity_constrained(ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *comment, u_int life, u_int confirm,
    ಧ್ರುವ ವರ್ಣ *provider, ಸಂರಚನಾ dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ ಕೀಲಿ_RSA:
	ಪಕ್ಷ ಕೀಲಿ_RSA_CERT:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
#endif
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
	ಪಕ್ಷ ಕೀಲಿ_ED25519_CERT:
	ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519:
	ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519_CERT:
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0 ||
		    (r = sshkey_private_serialize(ಕೀಲಿ, ಸಂದೇಶ)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ, comment)) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (constrained &&
	    (r = encode_constraints(ಸಂದೇಶ, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, ರಿಕ್ತ, 0)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_request_reply_decode(sock, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_remove_identity(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char *blob = ರಿಕ್ತ;
	size_t blen;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	ಯದಿ (ಕೀಲಿ->type != ಕೀಲಿ_UNSPEC) {
		ಯದಿ ((r = sshkey_to_blob(ಕೀಲಿ, &blob, &blen)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(ಸಂದೇಶ, blob, blen)) != 0)
			ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = ssh_request_reply_decode(sock, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	ಯದಿ (blob != ರಿಕ್ತ)
		freezero(blob, blen);
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_update_card(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ add, ಧ್ರುವ ವರ್ಣ *reader_id, ಧ್ರುವ ವರ್ಣ *pin,
    u_int life, u_int confirm,
    ಸಂರಚನಾ dest_constraint **dest_constraints, size_t ndest_constraints,
    ಪೂರ್ಣಾಙ್ಕ cert_only, ಸಂರಚನಾ sshkey **certs, size_t ncerts)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	ಯದಿ (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_ಕೀಲಿ_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_ಕೀಲಿ;
	} ಅನ್ಯಥಾ
		type = SSH_AGENTC_REMOVE_SMARTCARD_ಕೀಲಿ;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, pin)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (constrained &&
	    (r = encode_constraints(ಸಂದೇಶ, life, confirm, ರಿಕ್ತ,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_request_reply_decode(sock, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
ಪೂರ್ಣಾಙ್ಕ
ssh_remove_all_identities(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ version)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_request_reply_decode(sock, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
ಪೂರ್ಣಾಙ್ಕ
ssh_agent_bind_hostkey(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *session_id, ಧ್ರುವ ಸಂರಚನಾ sshbuf *signature,
    ಪೂರ್ಣಾಙ್ಕ forwarding)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || session_id == ರಿಕ್ತ || signature == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(ಕೀಲಿ, ಸಂದೇಶ)) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, signature)) != 0 ||
	    (r = sshbuf_put_u8(ಸಂದೇಶ, forwarding ? 1 : 0)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_request_reply_decode(sock, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Queries supported extension request types */
ಪೂರ್ಣಾಙ್ಕ
ssh_agent_query_extensions(ಪೂರ್ಣಾಙ್ಕ sock, ವರ್ಣ ***exts)
{
	ಸಂರಚನಾ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char type;
	ವರ್ಣ *cp = ರಿಕ್ತ, **ret = ರಿಕ್ತ;
	size_t i = 0;

	*exts = ರಿಕ್ತ;
	ಯದಿ ((ಸಂದೇಶ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "query")) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = ssh_request_reply(sock, ಸಂದೇಶ, ಸಂದೇಶ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ಗಚ್ಛ out;
	}
	/* Reply should start with "query" */
	ಯದಿ (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(ಸಂದೇಶ, &cp, ರಿಕ್ತ)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ret = xcalloc(1, ಪರಿಮಾಣ(*ret));
	ಯಾವತ್ (sshbuf_len(ಸಂದೇಶ)) {
		ret = xrecallocarray(ret, i + 1, i + 2, ಪರಿಮಾಣ(*ret));
		ಯದಿ ((r = sshbuf_get_cstring(ಸಂದೇಶ, ret + i, ರಿಕ್ತ)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = ರಿಕ್ತ; /* transferred */
 out:
	ಮುಕ್ತ(cp);
	stringlist_free(ret);
	sshbuf_free(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}
