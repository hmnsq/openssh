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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/un.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <errno.h>

#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
സ്ഥിതം പൂർണ്ണസംഖ്യ
decode_reply(u_char type)
{
	എങ്കിൽ (agent_failed(type))
		തിരികെ SSH_ERR_AGENT_FAILURE;
	അല്ലെങ്കിൽ എങ്കിൽ (type == SSH_AGENT_SUCCESS)
		തിരികെ 0;
	അല്ലെങ്കിൽ
		തിരികെ SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
പൂർണ്ണസംഖ്യ
ssh_get_authentication_socket_path(സ്ഥിരം അക്ഷരം *authsocket, പൂർണ്ണസംഖ്യ *fdp)
{
	പൂർണ്ണസംഖ്യ sock, oerrno;
	ഘടന sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, വലുപ്പം(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, വലുപ്പം(sunaddr.sun_path));

	എങ്കിൽ ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		തിരികെ SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	എങ്കിൽ (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (ഘടന sockaddr *)&sunaddr, വലുപ്പം(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}
	എങ്കിൽ (fdp != ശൂന്യ)
		*fdp = sock;
	അല്ലെങ്കിൽ
		close(sock);
	തിരികെ 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
പൂർണ്ണസംഖ്യ
ssh_get_authentication_socket(പൂർണ്ണസംഖ്യ *fdp)
{
	സ്ഥിരം അക്ഷരം *authsocket;

	എങ്കിൽ (fdp != ശൂന്യ)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	എങ്കിൽ (authsocket == ശൂന്യ || *authsocket == '\0')
		തിരികെ SSH_ERR_AGENT_NOT_PRESENT;

	തിരികെ ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_request_reply(പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *request, ഘടന sshbuf *reply)
{
	പൂർണ്ണസംഖ്യ r;
	size_t l, len;
	അക്ഷരം buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	എങ്കിൽ (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		തിരികെ SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	എങ്കിൽ (atomicio(പഠ, sock, buf, 4) != 4)
	    തിരികെ SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	എങ്കിൽ (len > MAX_AGENT_REPLY_LEN)
		തിരികെ SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	ആകുമ്പോൾ (len > 0) {
		l = len;
		എങ്കിൽ (l > വലുപ്പം(buf))
			l = വലുപ്പം(buf);
		എങ്കിൽ (atomicio(പഠ, sock, buf, l) != l)
			തിരികെ SSH_ERR_AGENT_COMMUNICATION;
		എങ്കിൽ ((r = sshbuf_put(reply, buf, l)) != 0)
			തിരികെ r;
		len -= l;
	}
	തിരികെ 0;
}

/* Communicate with agent: sent request, read and decode status reply */
സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_request_reply_decode(പൂർണ്ണസംഖ്യ sock, ഘടന sshbuf *request)
{
	ഘടന sshbuf *reply;
	പൂർണ്ണസംഖ്യ r;
	u_char type;

	എങ്കിൽ ((reply = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	തിരികെ r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
ശൂന്യം
ssh_close_authentication_socket(പൂർണ്ണസംഖ്യ sock)
{
	എങ്കിൽ (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != ശൂന്യ)
		close(sock);
}

/* Lock/unlock agent */
പൂർണ്ണസംഖ്യ
ssh_lock_agent(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ lock, സ്ഥിരം അക്ഷരം *password)
{
	പൂർണ്ണസംഖ്യ r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	ഘടന sshbuf *സന്ദേശം;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, type)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, സന്ദേശം)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(സന്ദേശം);
	തിരികെ r;
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_identity2(ഘടന sshbuf *ids, ഘടന sshkey **keyp, അക്ഷരം **commentp)
{
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *comment = ശൂന്യ;
	സ്ഥിരം u_char *blob;
	size_t blen;

	എങ്കിൽ ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, ശൂന്യ)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		പോകുക out;
	എങ്കിൽ (commentp != ശൂന്യ) {
		*commentp = comment;
		comment = ശൂന്യ;
	}
	r = 0;
 out:
	സ്വതന്ത്രം(comment);
	തിരികെ r;
}

/*
 * Fetch list of identities held by the agent.
 */
പൂർണ്ണസംഖ്യ
ssh_fetch_identitylist(പൂർണ്ണസംഖ്യ sock, ഘടന ssh_identitylist **idlp)
{
	u_char type;
	uint32_t അക്കം, i;
	ഘടന sshbuf *സന്ദേശം;
	ഘടന ssh_identitylist *idl = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = ssh_request_reply(sock, സന്ദേശം, സന്ദേശം)) != 0)
		പോകുക out;

	/* Get message type, and verify that we got a proper answer. */
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0)
		പോകുക out;
	എങ്കിൽ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	എങ്കിൽ ((r = sshbuf_get_u32(സന്ദേശം, &അക്കം)) != 0)
		പോകുക out;
	എങ്കിൽ (അക്കം > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (അക്കം == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		പോകുക out;
	}

	/* Deserialise the response into a list of keys/comments */
	എങ്കിൽ ((idl = calloc(1, വലുപ്പം(*idl))) == ശൂന്യ ||
	    (idl->താക്കോലുകൾ = calloc(അക്കം, വലുപ്പം(*idl->താക്കോലുകൾ))) == ശൂന്യ ||
	    (idl->comments = calloc(അക്കം, വലുപ്പം(*idl->comments))) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	വേണ്ടി (i = 0; i < അക്കം;) {
		എങ്കിൽ ((r = deserialise_identity2(സന്ദേശം, &(idl->താക്കോലുകൾ[i]),
		    &(idl->comments[i]))) != 0) {
			എങ്കിൽ (r == SSH_ERR_താക്കോൽ_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				അക്കം--;
				തുടരുക;
			} അല്ലെങ്കിൽ
				പോകുക out;
		}
		i++;
	}
	idl->nkeys = അക്കം;
	*idlp = idl;
	idl = ശൂന്യ;
	r = 0;
 out:
	sshbuf_free(സന്ദേശം);
	എങ്കിൽ (idl != ശൂന്യ)
		ssh_free_identitylist(idl);
	തിരികെ r;
}

ശൂന്യം
ssh_free_identitylist(ഘടന ssh_identitylist *idl)
{
	size_t i;

	എങ്കിൽ (idl == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < idl->nkeys; i++) {
		എങ്കിൽ (idl->താക്കോലുകൾ != ശൂന്യ)
			sshkey_free(idl->താക്കോലുകൾ[i]);
		എങ്കിൽ (idl->comments != ശൂന്യ)
			സ്വതന്ത്രം(idl->comments[i]);
	}
	സ്വതന്ത്രം(idl->താക്കോലുകൾ);
	സ്വതന്ത്രം(idl->comments);
	സ്വതന്ത്രം(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ
ssh_agent_has_താക്കോൽ(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r, ret = SSH_ERR_താക്കോൽ_NOT_FOUND;
	size_t i;
	ഘടന ssh_identitylist *idlist = ശൂന്യ;

	എങ്കിൽ ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		തിരികെ r;
	}

	വേണ്ടി (i = 0; i < idlist->nkeys; i++) {
		എങ്കിൽ (sshkey_equal_public(idlist->താക്കോലുകൾ[i], താക്കോൽ)) {
			ret = 0;
			നിർത്തുക;
		}
	}

	ssh_free_identitylist(idlist);
	തിരികെ ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
സ്ഥിതം u_int
agent_encode_alg(സ്ഥിരം ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *alg)
{
	എങ്കിൽ (alg != ശൂന്യ && sshkey_type_plain(താക്കോൽ->type) == താക്കോൽ_RSA) {
		എങ്കിൽ (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			തിരികെ SSH_AGENT_RSA_SHA2_256;
		എങ്കിൽ (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			തിരികെ SSH_AGENT_RSA_SHA2_512;
	}
	തിരികെ 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
പൂർണ്ണസംഖ്യ
ssh_agent_sign(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen, സ്ഥിരം അക്ഷരം *alg, u_int compat)
{
	ഘടന sshbuf *സന്ദേശം;
	u_char *sig = ശൂന്യ, type = 0;
	size_t len = 0;
	u_int flags = 0;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	*sigp = ശൂന്യ;
	*lenp = 0;

	എങ്കിൽ (datalen > SSH_താക്കോൽ_MAX_SIGN_DATA_SIZE)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(താക്കോൽ, alg);
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(താക്കോൽ, സന്ദേശം)) != 0 ||
	    (r = sshbuf_put_string(സന്ദേശം, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(സന്ദേശം, flags)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_request_reply(sock, സന്ദേശം, സന്ദേശം)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0)
		പോകുക out;
	എങ്കിൽ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_string(സന്ദേശം, &sig, &len)) != 0)
		പോകുക out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	എങ്കിൽ (!sshkey_is_sk(താക്കോൽ) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		പോകുക out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = ശൂന്യ;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(സന്ദേശം);
	തിരികെ r;
}

/* Encode key for a message to the agent. */

സ്ഥിതം പൂർണ്ണസംഖ്യ
encode_dest_constraint_hop(ഘടന sshbuf *m,
    സ്ഥിരം ഘടന dest_constraint_hop *dch)
{
	ഘടന sshbuf *b;
	u_int i;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, ശൂന്യ, 0)) != 0) /* reserved */
		പോകുക out;
	വേണ്ടി (i = 0; i < dch->nkeys; i++) {
		എങ്കിൽ ((r = sshkey_puts(dch->താക്കോലുകൾ[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->താക്കോൽ_is_ca[i] != 0)) != 0)
			പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_stringb(m, b)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
encode_dest_constraint(ഘടന sshbuf *m, സ്ഥിരം ഘടന dest_constraint *dc)
{
	ഘടന sshbuf *b;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, ശൂന്യ, 0)) != 0) /* reserved */
		പോകുക out;
	എങ്കിൽ ((r = sshbuf_put_stringb(m, b)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
encode_constraints(ഘടന sshbuf *m, u_int life, u_int confirm,
    സ്ഥിരം അക്ഷരം *provider,
    ഘടന dest_constraint **dest_constraints, size_t ndest_constraints,
    പൂർണ്ണസംഖ്യ cert_only, ഘടന sshkey **certs, size_t ncerts)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *b = ശൂന്യ;
	size_t i;

	എങ്കിൽ (life != 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			പോകുക out;
	}
	എങ്കിൽ (confirm != 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			പോകുക out;
	}
	എങ്കിൽ (provider != ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			പോകുക out;
	}
	എങ്കിൽ (dest_constraints != ശൂന്യ && ndest_constraints > 0) {
		എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		വേണ്ടി (i = 0; i < ndest_constraints; i++) {
			എങ്കിൽ ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			പോകുക out;
		sshbuf_free(b);
		b = ശൂന്യ;
	}
	എങ്കിൽ (ncerts != 0) {
		എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		വേണ്ടി (i = 0; i < ncerts; i++) {
			എങ്കിൽ ((r = sshkey_puts(certs[i], b)) != 0)
				പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			പോകുക out;
		sshbuf_free(b);
		b = ശൂന്യ;
	}
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
പൂർണ്ണസംഖ്യ
ssh_add_identity_constrained(പൂർണ്ണസംഖ്യ sock, ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം അക്ഷരം *comment, u_int life, u_int confirm,
    സ്ഥിരം അക്ഷരം *provider, ഘടന dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ താക്കോൽ_RSA:
	അവസ്ഥ താക്കോൽ_RSA_CERT:
	അവസ്ഥ താക്കോൽ_ECDSA:
	അവസ്ഥ താക്കോൽ_ECDSA_CERT:
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
	അവസ്ഥ താക്കോൽ_ECDSA_SK_CERT:
#endif
	അവസ്ഥ താക്കോൽ_ED25519:
	അവസ്ഥ താക്കോൽ_ED25519_CERT:
	അവസ്ഥ താക്കോൽ_MLDSA44_ED25519:
	അവസ്ഥ താക്കോൽ_MLDSA44_ED25519_CERT:
	അവസ്ഥ താക്കോൽ_ED25519_SK:
	അവസ്ഥ താക്കോൽ_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, type)) != 0 ||
		    (r = sshkey_private_serialize(താക്കോൽ, സന്ദേശം)) != 0 ||
		    (r = sshbuf_put_cstring(സന്ദേശം, comment)) != 0)
			പോകുക out;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (constrained &&
	    (r = encode_constraints(സന്ദേശം, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, ശൂന്യ, 0)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_request_reply_decode(sock, സന്ദേശം)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(സന്ദേശം);
	തിരികെ r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
പൂർണ്ണസംഖ്യ
ssh_remove_identity(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;
	u_char *blob = ശൂന്യ;
	size_t blen;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	എങ്കിൽ (താക്കോൽ->type != താക്കോൽ_UNSPEC) {
		എങ്കിൽ ((r = sshkey_to_blob(താക്കോൽ, &blob, &blen)) != 0)
			പോകുക out;
		എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(സന്ദേശം, blob, blen)) != 0)
			പോകുക out;
	} അല്ലെങ്കിൽ {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ ((r = ssh_request_reply_decode(sock, സന്ദേശം)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	എങ്കിൽ (blob != ശൂന്യ)
		freezero(blob, blen);
	sshbuf_free(സന്ദേശം);
	തിരികെ r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
പൂർണ്ണസംഖ്യ
ssh_update_card(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ add, സ്ഥിരം അക്ഷരം *reader_id, സ്ഥിരം അക്ഷരം *pin,
    u_int life, u_int confirm,
    ഘടന dest_constraint **dest_constraints, size_t ndest_constraints,
    പൂർണ്ണസംഖ്യ cert_only, ഘടന sshkey **certs, size_t ncerts)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	എങ്കിൽ (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_താക്കോൽ_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_താക്കോൽ;
	} അല്ലെങ്കിൽ
		type = SSH_AGENTC_REMOVE_SMARTCARD_താക്കോൽ;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, type)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, pin)) != 0)
		പോകുക out;
	എങ്കിൽ (constrained &&
	    (r = encode_constraints(സന്ദേശം, life, confirm, ശൂന്യ,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_request_reply_decode(sock, സന്ദേശം)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(സന്ദേശം);
	തിരികെ r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
പൂർണ്ണസംഖ്യ
ssh_remove_all_identities(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ version)
{
	ഘടന sshbuf *സന്ദേശം;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, type)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_request_reply_decode(sock, സന്ദേശം)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(സന്ദേശം);
	തിരികെ r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
പൂർണ്ണസംഖ്യ
ssh_agent_bind_hostkey(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം ഘടന sshbuf *session_id, സ്ഥിരം ഘടന sshbuf *signature,
    പൂർണ്ണസംഖ്യ forwarding)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ || session_id == ശൂന്യ || signature == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(താക്കോൽ, സന്ദേശം)) != 0 ||
	    (r = sshbuf_put_stringb(സന്ദേശം, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(സന്ദേശം, signature)) != 0 ||
	    (r = sshbuf_put_u8(സന്ദേശം, forwarding ? 1 : 0)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_request_reply_decode(sock, സന്ദേശം)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(സന്ദേശം);
	തിരികെ r;
}

/* Queries supported extension request types */
പൂർണ്ണസംഖ്യ
ssh_agent_query_extensions(പൂർണ്ണസംഖ്യ sock, അക്ഷരം ***exts)
{
	ഘടന sshbuf *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;
	u_char type;
	അക്ഷരം *cp = ശൂന്യ, **ret = ശൂന്യ;
	size_t i = 0;

	*exts = ശൂന്യ;
	എങ്കിൽ ((സന്ദേശം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u8(സന്ദേശം, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(സന്ദേശം, "query")) != 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_request_reply(sock, സന്ദേശം, സന്ദേശം)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = sshbuf_get_u8(സന്ദേശം, &type)) != 0)
		പോകുക out;
	എങ്കിൽ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		പോകുക out;
	}
	/* Reply should start with "query" */
	എങ്കിൽ (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(സന്ദേശം, &cp, ശൂന്യ)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	ret = xcalloc(1, വലുപ്പം(*ret));
	ആകുമ്പോൾ (sshbuf_len(സന്ദേശം)) {
		ret = xrecallocarray(ret, i + 1, i + 2, വലുപ്പം(*ret));
		എങ്കിൽ ((r = sshbuf_get_cstring(സന്ദേശം, ret + i, ശൂന്യ)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = ശൂന്യ; /* transferred */
 out:
	സ്വതന്ത്രം(cp);
	stringlist_free(ret);
	sshbuf_free(സന്ദേശം);
	തിരികെ r;
}
