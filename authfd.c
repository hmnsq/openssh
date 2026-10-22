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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/un.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <errno.h>

#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
நிலையான முழு
decode_reply(u_char type)
{
	எனில் (agent_failed(type))
		திரும்பு SSH_ERR_AGENT_FAILURE;
	இல்லையெனில் எனில் (type == SSH_AGENT_SUCCESS)
		திரும்பு 0;
	இல்லையெனில்
		திரும்பு SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
முழு
ssh_get_authentication_socket_path(மாறிலி எழுத்து *authsocket, முழு *fdp)
{
	முழு sock, oerrno;
	கட்டமைப்பு sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, அளவு(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, அளவு(sunaddr.sun_path));

	எனில் ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		திரும்பு SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	எனில் (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (கட்டமைப்பு sockaddr *)&sunaddr, அளவு(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}
	எனில் (fdp != வெற்று)
		*fdp = sock;
	இல்லையெனில்
		close(sock);
	திரும்பு 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
முழு
ssh_get_authentication_socket(முழு *fdp)
{
	மாறிலி எழுத்து *authsocket;

	எனில் (fdp != வெற்று)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	எனில் (authsocket == வெற்று || *authsocket == '\0')
		திரும்பு SSH_ERR_AGENT_NOT_PRESENT;

	திரும்பு ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
நிலையான முழு
ssh_request_reply(முழு sock, கட்டமைப்பு sshbuf *request, கட்டமைப்பு sshbuf *reply)
{
	முழு r;
	size_t l, len;
	எழுத்து buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	எனில் (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		திரும்பு SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	எனில் (atomicio(பட, sock, buf, 4) != 4)
	    திரும்பு SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	எனில் (len > MAX_AGENT_REPLY_LEN)
		திரும்பு SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	போது (len > 0) {
		l = len;
		எனில் (l > அளவு(buf))
			l = அளவு(buf);
		எனில் (atomicio(பட, sock, buf, l) != l)
			திரும்பு SSH_ERR_AGENT_COMMUNICATION;
		எனில் ((r = sshbuf_put(reply, buf, l)) != 0)
			திரும்பு r;
		len -= l;
	}
	திரும்பு 0;
}

/* Communicate with agent: sent request, read and decode status reply */
நிலையான முழு
ssh_request_reply_decode(முழு sock, கட்டமைப்பு sshbuf *request)
{
	கட்டமைப்பு sshbuf *reply;
	முழு r;
	u_char type;

	எனில் ((reply = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	திரும்பு r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
வெறுமை
ssh_close_authentication_socket(முழு sock)
{
	எனில் (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != வெற்று)
		close(sock);
}

/* Lock/unlock agent */
முழு
ssh_lock_agent(முழு sock, முழு lock, மாறிலி எழுத்து *password)
{
	முழு r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	கட்டமைப்பு sshbuf *செய்தி;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u8(செய்தி, type)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, செய்தி)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(செய்தி);
	திரும்பு r;
}


நிலையான முழு
deserialise_identity2(கட்டமைப்பு sshbuf *ids, கட்டமைப்பு sshkey **keyp, எழுத்து **commentp)
{
	முழு r;
	எழுத்து *comment = வெற்று;
	மாறிலி u_char *blob;
	size_t blen;

	எனில் ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, வெற்று)) != 0)
		செல் out;
	எனில் ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		செல் out;
	எனில் (commentp != வெற்று) {
		*commentp = comment;
		comment = வெற்று;
	}
	r = 0;
 out:
	விடுவி(comment);
	திரும்பு r;
}

/*
 * Fetch list of identities held by the agent.
 */
முழு
ssh_fetch_identitylist(முழு sock, கட்டமைப்பு ssh_identitylist **idlp)
{
	u_char type;
	uint32_t இலக்கம், i;
	கட்டமைப்பு sshbuf *செய்தி;
	கட்டமைப்பு ssh_identitylist *idl = வெற்று;
	முழு r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		செல் out;

	எனில் ((r = ssh_request_reply(sock, செய்தி, செய்தி)) != 0)
		செல் out;

	/* Get message type, and verify that we got a proper answer. */
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0)
		செல் out;
	எனில் (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		செல் out;
	} இல்லையெனில் எனில் (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	எனில் ((r = sshbuf_get_u32(செய்தி, &இலக்கம்)) != 0)
		செல் out;
	எனில் (இலக்கம் > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (இலக்கம் == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		செல் out;
	}

	/* Deserialise the response into a list of keys/comments */
	எனில் ((idl = calloc(1, அளவு(*idl))) == வெற்று ||
	    (idl->சாவிகள் = calloc(இலக்கம், அளவு(*idl->சாவிகள்))) == வெற்று ||
	    (idl->comments = calloc(இலக்கம், அளவு(*idl->comments))) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	க்கு (i = 0; i < இலக்கம்;) {
		எனில் ((r = deserialise_identity2(செய்தி, &(idl->சாவிகள்[i]),
		    &(idl->comments[i]))) != 0) {
			எனில் (r == SSH_ERR_சாவி_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				இலக்கம்--;
				தொடர்;
			} இல்லையெனில்
				செல் out;
		}
		i++;
	}
	idl->nkeys = இலக்கம்;
	*idlp = idl;
	idl = வெற்று;
	r = 0;
 out:
	sshbuf_free(செய்தி);
	எனில் (idl != வெற்று)
		ssh_free_identitylist(idl);
	திரும்பு r;
}

வெறுமை
ssh_free_identitylist(கட்டமைப்பு ssh_identitylist *idl)
{
	size_t i;

	எனில் (idl == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < idl->nkeys; i++) {
		எனில் (idl->சாவிகள் != வெற்று)
			sshkey_free(idl->சாவிகள்[i]);
		எனில் (idl->comments != வெற்று)
			விடுவி(idl->comments[i]);
	}
	விடுவி(idl->சாவிகள்);
	விடுவி(idl->comments);
	விடுவி(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
முழு
ssh_agent_has_சாவி(முழு sock, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	முழு r, ret = SSH_ERR_சாவி_NOT_FOUND;
	size_t i;
	கட்டமைப்பு ssh_identitylist *idlist = வெற்று;

	எனில் ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		திரும்பு r;
	}

	க்கு (i = 0; i < idlist->nkeys; i++) {
		எனில் (sshkey_equal_public(idlist->சாவிகள்[i], சாவி)) {
			ret = 0;
			நிறுத்து;
		}
	}

	ssh_free_identitylist(idlist);
	திரும்பு ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
நிலையான u_int
agent_encode_alg(மாறிலி கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *alg)
{
	எனில் (alg != வெற்று && sshkey_type_plain(சாவி->type) == சாவி_RSA) {
		எனில் (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			திரும்பு SSH_AGENT_RSA_SHA2_256;
		எனில் (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			திரும்பு SSH_AGENT_RSA_SHA2_512;
	}
	திரும்பு 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
முழு
ssh_agent_sign(முழு sock, மாறிலி கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen, மாறிலி எழுத்து *alg, u_int compat)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_char *sig = வெற்று, type = 0;
	size_t len = 0;
	u_int flags = 0;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	*sigp = வெற்று;
	*lenp = 0;

	எனில் (datalen > SSH_சாவி_MAX_SIGN_DATA_SIZE)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(சாவி, alg);
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(சாவி, செய்தி)) != 0 ||
	    (r = sshbuf_put_string(செய்தி, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(செய்தி, flags)) != 0)
		செல் out;
	எனில் ((r = ssh_request_reply(sock, செய்தி, செய்தி)) != 0)
		செல் out;
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0)
		செல் out;
	எனில் (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		செல் out;
	} இல்லையெனில் எனில் (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((r = sshbuf_get_string(செய்தி, &sig, &len)) != 0)
		செல் out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	எனில் (!sshkey_is_sk(சாவி) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		செல் out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = வெற்று;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(செய்தி);
	திரும்பு r;
}

/* Encode key for a message to the agent. */

நிலையான முழு
encode_dest_constraint_hop(கட்டமைப்பு sshbuf *m,
    மாறிலி கட்டமைப்பு dest_constraint_hop *dch)
{
	கட்டமைப்பு sshbuf *b;
	u_int i;
	முழு r;

	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, வெற்று, 0)) != 0) /* reserved */
		செல் out;
	க்கு (i = 0; i < dch->nkeys; i++) {
		எனில் ((r = sshkey_puts(dch->சாவிகள்[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->சாவி_is_ca[i] != 0)) != 0)
			செல் out;
	}
	எனில் ((r = sshbuf_put_stringb(m, b)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

நிலையான முழு
encode_dest_constraint(கட்டமைப்பு sshbuf *m, மாறிலி கட்டமைப்பு dest_constraint *dc)
{
	கட்டமைப்பு sshbuf *b;
	முழு r;

	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, வெற்று, 0)) != 0) /* reserved */
		செல் out;
	எனில் ((r = sshbuf_put_stringb(m, b)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

நிலையான முழு
encode_constraints(கட்டமைப்பு sshbuf *m, u_int life, u_int confirm,
    மாறிலி எழுத்து *provider,
    கட்டமைப்பு dest_constraint **dest_constraints, size_t ndest_constraints,
    முழு cert_only, கட்டமைப்பு sshkey **certs, size_t ncerts)
{
	முழு r;
	கட்டமைப்பு sshbuf *b = வெற்று;
	size_t i;

	எனில் (life != 0) {
		எனில் ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			செல் out;
	}
	எனில் (confirm != 0) {
		எனில் ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			செல் out;
	}
	எனில் (provider != வெற்று) {
		எனில் ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			செல் out;
	}
	எனில் (dest_constraints != வெற்று && ndest_constraints > 0) {
		எனில் ((b = sshbuf_new()) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		க்கு (i = 0; i < ndest_constraints; i++) {
			எனில் ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				செல் out;
		}
		எனில் ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			செல் out;
		sshbuf_free(b);
		b = வெற்று;
	}
	எனில் (ncerts != 0) {
		எனில் ((b = sshbuf_new()) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		க்கு (i = 0; i < ncerts; i++) {
			எனில் ((r = sshkey_puts(certs[i], b)) != 0)
				செல் out;
		}
		எனில் ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			செல் out;
		sshbuf_free(b);
		b = வெற்று;
	}
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
முழு
ssh_add_identity_constrained(முழு sock, கட்டமைப்பு sshkey *சாவி,
    மாறிலி எழுத்து *comment, u_int life, u_int confirm,
    மாறிலி எழுத்து *provider, கட்டமைப்பு dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	தேர்வு (சாவி->type) {
#ifdef WITH_OPENSSL
	நிலை சாவி_RSA:
	நிலை சாவி_RSA_CERT:
	நிலை சாவி_ECDSA:
	நிலை சாவி_ECDSA_CERT:
	நிலை சாவி_ECDSA_SK:
	நிலை சாவி_ECDSA_SK_CERT:
#endif
	நிலை சாவி_ED25519:
	நிலை சாவி_ED25519_CERT:
	நிலை சாவி_MLDSA44_ED25519:
	நிலை சாவி_MLDSA44_ED25519_CERT:
	நிலை சாவி_ED25519_SK:
	நிலை சாவி_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		எனில் ((r = sshbuf_put_u8(செய்தி, type)) != 0 ||
		    (r = sshkey_private_serialize(சாவி, செய்தி)) != 0 ||
		    (r = sshbuf_put_cstring(செய்தி, comment)) != 0)
			செல் out;
		நிறுத்து;
	இயல்பு:
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (constrained &&
	    (r = encode_constraints(செய்தி, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, வெற்று, 0)) != 0)
		செல் out;
	எனில் ((r = ssh_request_reply_decode(sock, செய்தி)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(செய்தி);
	திரும்பு r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
முழு
ssh_remove_identity(முழு sock, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;
	u_char *blob = வெற்று;
	size_t blen;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	எனில் (சாவி->type != சாவி_UNSPEC) {
		எனில் ((r = sshkey_to_blob(சாவி, &blob, &blen)) != 0)
			செல் out;
		எனில் ((r = sshbuf_put_u8(செய்தி,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(செய்தி, blob, blen)) != 0)
			செல் out;
	} இல்லையெனில் {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் ((r = ssh_request_reply_decode(sock, செய்தி)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	எனில் (blob != வெற்று)
		freezero(blob, blen);
	sshbuf_free(செய்தி);
	திரும்பு r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
முழு
ssh_update_card(முழு sock, முழு add, மாறிலி எழுத்து *reader_id, மாறிலி எழுத்து *pin,
    u_int life, u_int confirm,
    கட்டமைப்பு dest_constraint **dest_constraints, size_t ndest_constraints,
    முழு cert_only, கட்டமைப்பு sshkey **certs, size_t ncerts)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	எனில் (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_சாவி_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_சாவி;
	} இல்லையெனில்
		type = SSH_AGENTC_REMOVE_SMARTCARD_சாவி;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u8(செய்தி, type)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, pin)) != 0)
		செல் out;
	எனில் (constrained &&
	    (r = encode_constraints(செய்தி, life, confirm, வெற்று,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		செல் out;
	எனில் ((r = ssh_request_reply_decode(sock, செய்தி)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(செய்தி);
	திரும்பு r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
முழு
ssh_remove_all_identities(முழு sock, முழு version)
{
	கட்டமைப்பு sshbuf *செய்தி;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	முழு r;

	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u8(செய்தி, type)) != 0)
		செல் out;
	எனில் ((r = ssh_request_reply_decode(sock, செய்தி)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(செய்தி);
	திரும்பு r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
முழு
ssh_agent_bind_hostkey(முழு sock, மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி கட்டமைப்பு sshbuf *session_id, மாறிலி கட்டமைப்பு sshbuf *signature,
    முழு forwarding)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;

	எனில் (சாவி == வெற்று || session_id == வெற்று || signature == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(சாவி, செய்தி)) != 0 ||
	    (r = sshbuf_put_stringb(செய்தி, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(செய்தி, signature)) != 0 ||
	    (r = sshbuf_put_u8(செய்தி, forwarding ? 1 : 0)) != 0)
		செல் out;
	எனில் ((r = ssh_request_reply_decode(sock, செய்தி)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(செய்தி);
	திரும்பு r;
}

/* Queries supported extension request types */
முழு
ssh_agent_query_extensions(முழு sock, எழுத்து ***exts)
{
	கட்டமைப்பு sshbuf *செய்தி;
	முழு r;
	u_char type;
	எழுத்து *cp = வெற்று, **ret = வெற்று;
	size_t i = 0;

	*exts = வெற்று;
	எனில் ((செய்தி = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u8(செய்தி, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(செய்தி, "query")) != 0)
		செல் out;
	எனில் ((r = ssh_request_reply(sock, செய்தி, செய்தி)) != 0)
		செல் out;
	எனில் ((r = sshbuf_get_u8(செய்தி, &type)) != 0)
		செல் out;
	எனில் (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		செல் out;
	}
	/* Reply should start with "query" */
	எனில் (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(செய்தி, &cp, வெற்று)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	ret = xcalloc(1, அளவு(*ret));
	போது (sshbuf_len(செய்தி)) {
		ret = xrecallocarray(ret, i + 1, i + 2, அளவு(*ret));
		எனில் ((r = sshbuf_get_cstring(செய்தி, ret + i, வெற்று)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = வெற்று; /* transferred */
 out:
	விடுவி(cp);
	stringlist_free(ret);
	sshbuf_free(செய்தி);
	திரும்பு r;
}
