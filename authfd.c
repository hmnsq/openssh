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

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#ವ್ಯಾಖ್ಯಾನಿಸು MAX_AGENT_ಉತ್ತರ_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#ವ್ಯಾಖ್ಯಾನಿಸು agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
decode_ಉತ್ತರ(u_char type)
{
	ಆದರೆ (agent_failed(type))
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_FAILURE;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type == SSH_AGENT_SUCCESS)
		ಹಿಂತಿರುಗಿ 0;
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
ಪೂರ್ಣಾಂಕ
ssh_get_authentication_socket_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *authsocket, ಪೂರ್ಣಾಂಕ *fdp)
{
	ಪೂರ್ಣಾಂಕ sock, oerrno;
	ರಚನೆ sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, ಗಾತ್ರ(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_ಮಾರ್ಗ, authsocket, ಗಾತ್ರ(sunaddr.sun_ಮಾರ್ಗ));

	ಆದರೆ ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	ಆದರೆ (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (ರಚನೆ sockaddr *)&sunaddr, ಗಾತ್ರ(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}
	ಆದರೆ (fdp != ಖಾಲಿ)
		*fdp = sock;
	ಇಲ್ಲದಿದ್ದರೆ
		close(sock);
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
ಪೂರ್ಣಾಂಕ
ssh_get_authentication_socket(ಪೂರ್ಣಾಂಕ *fdp)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *authsocket;

	ಆದರೆ (fdp != ಖಾಲಿ)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	ಆದರೆ (authsocket == ಖಾಲಿ || *authsocket == '\0')
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_NOT_PRESENT;

	ಹಿಂತಿರುಗಿ ssh_get_authentication_socket_ಮಾರ್ಗ(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_request_ಉತ್ತರ(ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *request, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t l, len;
	ಅಕ್ಷರ buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	ಆದರೆ (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	ಆದರೆ (atomicio(ಪಠ, sock, buf, 4) != 4)
	    ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	ಆದರೆ (len > MAX_AGENT_ಉತ್ತರ_LEN)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(ಉತ್ತರ);
	ಆಗ (len > 0) {
		l = len;
		ಆದರೆ (l > ಗಾತ್ರ(buf))
			l = ಗಾತ್ರ(buf);
		ಆದರೆ (atomicio(ಪಠ, sock, buf, l) != l)
			ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_COMMUNICATION;
		ಆದರೆ ((r = sshbuf_put(ಉತ್ತರ, buf, l)) != 0)
			ಹಿಂತಿರುಗಿ r;
		len -= l;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Communicate with agent: sent request, read and decode status reply */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_request_ಉತ್ತರ_decode(ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshbuf *request)
{
	ರಚನೆ sshbuf *ಉತ್ತರ;
	ಪೂರ್ಣಾಂಕ r;
	u_char type;

	ಆದರೆ ((ಉತ್ತರ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = ssh_request_ಉತ್ತರ(sock, request, ಉತ್ತರ)) != 0 ||
	    (r = sshbuf_get_u8(ಉತ್ತರ, &type)) != 0 ||
	    (r = decode_ಉತ್ತರ(type)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(ಉತ್ತರ);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
ಶೂನ್ಯ
ssh_close_authentication_socket(ಪೂರ್ಣಾಂಕ sock)
{
	ಆದರೆ (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != ಖಾಲಿ)
		close(sock);
}

/* Lock/unlock agent */
ಪೂರ್ಣಾಂಕ
ssh_ಬೀಗ_agent(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ ಬೀಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password)
{
	ಪೂರ್ಣಾಂಕ r;
	u_char type = ಬೀಗ ? SSH_AGENTC_ಬೀಗ : SSH_AGENTC_UNLOCK;
	ರಚನೆ sshbuf *ಸಂದೇಶ;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, password)) != 0 ||
	    (r = ssh_request_ಉತ್ತರ_decode(sock, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
deserialise_identity2(ರಚನೆ sshbuf *ids, ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp)
{
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *comment = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *blob;
	ಗಾತ್ರ_t blen;

	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (commentp != ಖಾಲಿ) {
		*commentp = comment;
		comment = ಖಾಲಿ;
	}
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(comment);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Fetch list of identities held by the agent.
 */
ಪೂರ್ಣಾಂಕ
ssh_fetch_identitylist(ಪೂರ್ಣಾಂಕ sock, ರಚನೆ ssh_identitylist **idlp)
{
	u_char type;
	uint32_t ಅಂಕೆ, i;
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ರಚನೆ ssh_identitylist *idl = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = ssh_request_ಉತ್ತರ(sock, ಸಂದೇಶ, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Get message type, and verify that we got a proper answer. */
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Get the number of entries in the response and check it for sanity. */
	ಆದರೆ ((r = sshbuf_get_u32(ಸಂದೇಶ, &ಅಂಕೆ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (ಅಂಕೆ > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ಅಂಕೆ == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Deserialise the response into a list of keys/comments */
	ಆದರೆ ((idl = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*idl))) == ಖಾಲಿ ||
	    (idl->ಕೀಲಿಗಳು = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(ಅಂಕೆ, ಗಾತ್ರ(*idl->ಕೀಲಿಗಳು))) == ಖಾಲಿ ||
	    (idl->comments = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(ಅಂಕೆ, ಗಾತ್ರ(*idl->comments))) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ;) {
		ಆದರೆ ((r = deserialise_identity2(ಸಂದೇಶ, &(idl->ಕೀಲಿಗಳು[i]),
		    &(idl->comments[i]))) != 0) {
			ಆದರೆ (r == SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				ಅಂಕೆ--;
				ಮುಂದುವರಿ;
			} ಇಲ್ಲದಿದ್ದರೆ
				ಹೋಗು ಹೊರಹೋಗು;
		}
		i++;
	}
	idl->nkeys = ಅಂಕೆ;
	*idlp = idl;
	idl = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(ಸಂದೇಶ);
	ಆದರೆ (idl != ಖಾಲಿ)
		ssh_free_identitylist(idl);
	ಹಿಂತಿರುಗಿ r;
}

ಶೂನ್ಯ
ssh_free_identitylist(ರಚನೆ ssh_identitylist *idl)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (idl == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < idl->nkeys; i++) {
		ಆದರೆ (idl->ಕೀಲಿಗಳು != ಖಾಲಿ)
			sshkey_free(idl->ಕೀಲಿಗಳು[i]);
		ಆದರೆ (idl->comments != ಖಾಲಿ)
			ಬಿಡುಗಡೆ(idl->comments[i]);
	}
	ಬಿಡುಗಡೆ(idl->ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(idl->comments);
	ಬಿಡುಗಡೆ(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ
ssh_agent_has_ಕೀಲಿ(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r, ret = SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
	ಗಾತ್ರ_t i;
	ರಚನೆ ssh_identitylist *idlist = ಖಾಲಿ;

	ಆದರೆ ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		ಹಿಂತಿರುಗಿ r;
	}

	ಗಾಗಿ (i = 0; i < idlist->nkeys; i++) {
		ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(idlist->ಕೀಲಿಗಳು[i], ಕೀಲಿ)) {
			ret = 0;
			ನಿಲ್ಲಿಸು;
		}
	}

	ssh_free_identitylist(idlist);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
ಸ್ಥಿರ u_int
agent_encode_alg(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg)
{
	ಆದರೆ (alg != ಖಾಲಿ && sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA) {
		ಆದರೆ (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			ಹಿಂತಿರುಗಿ SSH_AGENT_RSA_SHA2_256;
		ಆದರೆ (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			ಹಿಂತಿರುಗಿ SSH_AGENT_RSA_SHA2_512;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
ಪೂರ್ಣಾಂಕ
ssh_agent_sign(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_char *sig = ಖಾಲಿ, type = 0;
	ಗಾತ್ರ_t len = 0;
	u_int flags = 0;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	*sigp = ಖಾಲಿ;
	*lenp = 0;

	ಆದರೆ (datalen > SSH_ಕೀಲಿ_MAX_SIGN_ದತ್ತಾಂಶ_ಗಾತ್ರ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(ಕೀಲಿ, alg);
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(ಕೀಲಿ, ಸಂದೇಶ)) != 0 ||
	    (r = sshbuf_put_string(ಸಂದೇಶ, ದತ್ತಾಂಶ, datalen)) != 0 ||
	    (r = sshbuf_put_u32(ಸಂದೇಶ, flags)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_request_ಉತ್ತರ(sock, ಸಂದೇಶ, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_string(ಸಂದೇಶ, &sig, &len)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	ಆದರೆ (!sshkey_is_sk(ಕೀಲಿ) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = ಖಾಲಿ;
	len = 0;
	r = 0;
 ಹೊರಹೋಗು:
	freezero(sig, len);
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}

/* Encode key for a message to the agent. */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
encode_dest_constraint_hop(ರಚನೆ sshbuf *m,
    ಸ್ಥಿರಾಂಕ ರಚನೆ dest_constraint_hop *dch)
{
	ರಚನೆ sshbuf *b;
	u_int i;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, ಖಾಲಿ, 0)) != 0) /* reserved */
		ಹೋಗು ಹೊರಹೋಗು;
	ಗಾಗಿ (i = 0; i < dch->nkeys; i++) {
		ಆದರೆ ((r = sshkey_puts(dch->ಕೀಲಿಗಳು[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->ಕೀಲಿ_is_ca[i] != 0)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_stringb(m, b)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
encode_dest_constraint(ರಚನೆ sshbuf *m, ಸ್ಥಿರಾಂಕ ರಚನೆ dest_constraint *dc)
{
	ರಚನೆ sshbuf *b;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->ಗಮ್ಯ)) != 0 ||
	    (r = sshbuf_put_string(b, ಖಾಲಿ, 0)) != 0) /* reserved */
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshbuf_put_stringb(m, b)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
encode_constraints(ರಚನೆ sshbuf *m, u_int life, u_int confirm,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider,
    ರಚನೆ dest_constraint **dest_constraints, ಗಾತ್ರ_t ndest_constraints,
    ಪೂರ್ಣಾಂಕ cert_only, ರಚನೆ sshkey **certs, ಗಾತ್ರ_t ncerts)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಗಾತ್ರ_t i;

	ಆದರೆ (life != 0) {
		ಆದರೆ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (confirm != 0) {
		ಆದರೆ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (provider != ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (dest_constraints != ಖಾಲಿ && ndest_constraints > 0) {
		ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಗಾಗಿ (i = 0; i < ndest_constraints; i++) {
			ಆದರೆ ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		sshbuf_free(b);
		b = ಖಾಲಿ;
	}
	ಆದರೆ (ncerts != 0) {
		ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಗಾಗಿ (i = 0; i < ncerts; i++) {
			ಆದರೆ ((r = sshkey_puts(certs[i], b)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		sshbuf_free(b);
		b = ಖಾಲಿ;
	}
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ಪೂರ್ಣಾಂಕ
ssh_ಕೂಡಿಸು_ತಟಸ್ಥ_constrained(ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment, u_int life, u_int confirm,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider, ರಚನೆ dest_constraint **dest_constraints,
    ಗಾತ್ರ_t ndest_constraints)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	ಆಯ್ಕೆ (ಕೀಲಿ->type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA_CERT:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
#ಆದರೆ_ಅಂತ್ಯ
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_CERT:
	ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519:
	ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519_CERT:
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ಕೂಡಿಸು_ID_CONSTRAINED :
		    SSH2_AGENTC_ಕೂಡಿಸು_ತಟಸ್ಥ;
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0 ||
		    (r = sshkey_ಖಾಸಗಿ_serialize(ಕೀಲಿ, ಸಂದೇಶ)) != 0 ||
		    (r = sshbuf_put_cstring(ಸಂದೇಶ, comment)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (constrained &&
	    (r = encode_constraints(ಸಂದೇಶ, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, ಖಾಲಿ, 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_request_ಉತ್ತರ_decode(sock, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ಪೂರ್ಣಾಂಕ
ssh_remove_ತಟಸ್ಥ(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;
	u_char *blob = ಖಾಲಿ;
	ಗಾತ್ರ_t blen;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	ಆದರೆ (ಕೀಲಿ->type != ಕೀಲಿ_UNSPEC) {
		ಆದರೆ ((r = sshkey_ಗಮ್ಯ_blob(ಕೀಲಿ, &blob, &blen)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ,
		    SSH2_AGENTC_REMOVE_ತಟಸ್ಥ)) != 0 ||
		    (r = sshbuf_put_string(ಸಂದೇಶ, blob, blen)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = ssh_request_ಉತ್ತರ_decode(sock, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (blob != ಖಾಲಿ)
		freezero(blob, blen);
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ಪೂರ್ಣಾಂಕ
ssh_update_card(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ ಕೂಡಿಸು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reader_id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin,
    u_int life, u_int confirm,
    ರಚನೆ dest_constraint **dest_constraints, ಗಾತ್ರ_t ndest_constraints,
    ಪೂರ್ಣಾಂಕ cert_only, ರಚನೆ sshkey **certs, ಗಾತ್ರ_t ncerts)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	ಆದರೆ (ಕೂಡಿಸು) {
		type = constrained ?
		    SSH_AGENTC_ಕೂಡಿಸು_SMARTCARD_ಕೀಲಿ_CONSTRAINED :
		    SSH_AGENTC_ಕೂಡಿಸು_SMARTCARD_ಕೀಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ
		type = SSH_AGENTC_REMOVE_SMARTCARD_ಕೀಲಿ;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, pin)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (constrained &&
	    (r = encode_constraints(ಸಂದೇಶ, life, confirm, ಖಾಲಿ,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_request_ಉತ್ತರ_decode(sock, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
ಪೂರ್ಣಾಂಕ
ssh_remove_all_identities(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ ಆವೃತ್ತಿ)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	u_char type = (ಆವೃತ್ತಿ == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, type)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_request_ಉತ್ತರ_decode(sock, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
ಪೂರ್ಣಾಂಕ
ssh_agent_bind_hostkey(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *session_id, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *signature,
    ಪೂರ್ಣಾಂಕ forwarding)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || session_id == ಖಾಲಿ || signature == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(ಕೀಲಿ, ಸಂದೇಶ)) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(ಸಂದೇಶ, signature)) != 0 ||
	    (r = sshbuf_put_u8(ಸಂದೇಶ, forwarding ? 1 : 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_request_ಉತ್ತರ_decode(sock, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}

/* Queries supported extension request types */
ಪೂರ್ಣಾಂಕ
ssh_agent_query_extensions(ಪೂರ್ಣಾಂಕ sock, ಅಕ್ಷರ ***exts)
{
	ರಚನೆ sshbuf *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;
	u_char type;
	ಅಕ್ಷರ *cp = ಖಾಲಿ, **ret = ಖಾಲಿ;
	ಗಾತ್ರ_t i = 0;

	*exts = ಖಾಲಿ;
	ಆದರೆ ((ಸಂದೇಶ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u8(ಸಂದೇಶ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ಸಂದೇಶ, "query")) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_request_ಉತ್ತರ(sock, ಸಂದೇಶ, ಸಂದೇಶ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshbuf_get_u8(ಸಂದೇಶ, &type)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Reply should start with "query" */
	ಆದರೆ (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(ಸಂದೇಶ, &cp, ಖಾಲಿ)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ret = xcalloc(1, ಗಾತ್ರ(*ret));
	ಆಗ (sshbuf_len(ಸಂದೇಶ)) {
		ret = xrecallocarray(ret, i + 1, i + 2, ಗಾತ್ರ(*ret));
		ಆದರೆ ((r = sshbuf_get_cstring(ಸಂದೇಶ, ret + i, ಖಾಲಿ)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = ಖಾಲಿ; /* transferred */
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(cp);
	stringlist_free(ret);
	sshbuf_free(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}
