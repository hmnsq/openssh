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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>

#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
decode_reply(u_char type)
{
	ଯଦି (agent_failed(type))
		ଫେରନ୍ତୁ SSH_ERR_AGENT_FAILURE;
	ଅନ୍ୟଥା ଯଦି (type == SSH_AGENT_SUCCESS)
		ଫେରନ୍ତୁ 0;
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_get_authentication_socket_path(ଅଚଳ ଅକ୍ଷର *authsocket, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fdp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, oerrno;
	ସଂରଚନା sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, ଆକାର(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, ଆକାର(sunaddr.sun_path));

	ଯଦି ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	ଯଦି (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (ସଂରଚନା sockaddr *)&sunaddr, ଆକାର(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}
	ଯଦି (fdp != ଖାଲି)
		*fdp = sock;
	ଅନ୍ୟଥା
		close(sock);
	ଫେରନ୍ତୁ 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_get_authentication_socket(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fdp)
{
	ଅଚଳ ଅକ୍ଷର *authsocket;

	ଯଦି (fdp != ଖାଲି)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	ଯଦି (authsocket == ଖାଲି || *authsocket == '\0')
		ଫେରନ୍ତୁ SSH_ERR_AGENT_NOT_PRESENT;

	ଫେରନ୍ତୁ ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_request_reply(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *request, ସଂରଚନା sshbuf *reply)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t l, len;
	ଅକ୍ଷର buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	ଯଦି (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		ଫେରନ୍ତୁ SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	ଯଦି (atomicio(ପଠ, sock, buf, 4) != 4)
	    ଫେରନ୍ତୁ SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	ଯଦି (len > MAX_AGENT_REPLY_LEN)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	ଯେତେବେଳେ (len > 0) {
		l = len;
		ଯଦି (l > ଆକାର(buf))
			l = ଆକାର(buf);
		ଯଦି (atomicio(ପଠ, sock, buf, l) != l)
			ଫେରନ୍ତୁ SSH_ERR_AGENT_COMMUNICATION;
		ଯଦି ((r = sshbuf_put(reply, buf, l)) != 0)
			ଫେରନ୍ତୁ r;
		len -= l;
	}
	ଫେରନ୍ତୁ 0;
}

/* Communicate with agent: sent request, read and decode status reply */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_request_reply_decode(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshbuf *request)
{
	ସଂରଚନା sshbuf *reply;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char type;

	ଯଦି ((reply = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	ଫେରନ୍ତୁ r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
ଶୂନ୍ୟ
ssh_close_authentication_socket(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock)
{
	ଯଦି (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != ଖାଲି)
		close(sock);
}

/* Lock/unlock agent */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_lock_agent(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lock, ଅଚଳ ଅକ୍ଷର *password)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, type)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}


ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_identity2(ସଂରଚନା sshbuf *ids, ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *comment = ଖାଲି;
	ଅଚଳ u_char *blob;
	size_t blen;

	ଯଦି ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		ଯାଅ out;
	ଯଦି (commentp != ଖାଲି) {
		*commentp = comment;
		comment = ଖାଲି;
	}
	r = 0;
 out:
	ମୁକ୍ତ(comment);
	ଫେରନ୍ତୁ r;
}

/*
 * Fetch list of identities held by the agent.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_fetch_identitylist(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା ssh_identitylist **idlp)
{
	u_char type;
	uint32_t ଅଙ୍କ, i;
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ସଂରଚନା ssh_identitylist *idl = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		ଯାଅ out;

	ଯଦି ((r = ssh_request_reply(sock, ସନ୍ଦେଶ, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;

	/* Get message type, and verify that we got a proper answer. */
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0)
		ଯାଅ out;
	ଯଦି (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	ଯଦି ((r = sshbuf_get_u32(ସନ୍ଦେଶ, &ଅଙ୍କ)) != 0)
		ଯାଅ out;
	ଯଦି (ଅଙ୍କ > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (ଅଙ୍କ == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		ଯାଅ out;
	}

	/* Deserialise the response into a list of keys/comments */
	ଯଦି ((idl = calloc(1, ଆକାର(*idl))) == ଖାଲି ||
	    (idl->ଚାବିଗୁଡ଼ିକ = calloc(ଅଙ୍କ, ଆକାର(*idl->ଚାବିଗୁଡ଼ିକ))) == ଖାଲି ||
	    (idl->comments = calloc(ଅଙ୍କ, ଆକାର(*idl->comments))) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ପାଇଁ (i = 0; i < ଅଙ୍କ;) {
		ଯଦି ((r = deserialise_identity2(ସନ୍ଦେଶ, &(idl->ଚାବିଗୁଡ଼ିକ[i]),
		    &(idl->comments[i]))) != 0) {
			ଯଦି (r == SSH_ERR_ଚାବି_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				ଅଙ୍କ--;
				ଜାରି;
			} ଅନ୍ୟଥା
				ଯାଅ out;
		}
		i++;
	}
	idl->nkeys = ଅଙ୍କ;
	*idlp = idl;
	idl = ଖାଲି;
	r = 0;
 out:
	sshbuf_free(ସନ୍ଦେଶ);
	ଯଦି (idl != ଖାଲି)
		ssh_free_identitylist(idl);
	ଫେରନ୍ତୁ r;
}

ଶୂନ୍ୟ
ssh_free_identitylist(ସଂରଚନା ssh_identitylist *idl)
{
	size_t i;

	ଯଦି (idl == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < idl->nkeys; i++) {
		ଯଦି (idl->ଚାବିଗୁଡ଼ିକ != ଖାଲି)
			sshkey_free(idl->ଚାବିଗୁଡ଼ିକ[i]);
		ଯଦି (idl->comments != ଖାଲି)
			ମୁକ୍ତ(idl->comments[i]);
	}
	ମୁକ୍ତ(idl->ଚାବିଗୁଡ଼ିକ);
	ମୁକ୍ତ(idl->comments);
	ମୁକ୍ତ(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_agent_has_ଚାବି(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = SSH_ERR_ଚାବି_NOT_FOUND;
	size_t i;
	ସଂରଚନା ssh_identitylist *idlist = ଖାଲି;

	ଯଦି ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		ଫେରନ୍ତୁ r;
	}

	ପାଇଁ (i = 0; i < idlist->nkeys; i++) {
		ଯଦି (sshkey_equal_public(idlist->ଚାବିଗୁଡ଼ିକ[i], ଚାବି)) {
			ret = 0;
			ଭାଙ୍ଗ;
		}
	}

	ssh_free_identitylist(idlist);
	ଫେରନ୍ତୁ ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
ସ୍ଥିର u_int
agent_encode_alg(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *alg)
{
	ଯଦି (alg != ଖାଲି && sshkey_type_plain(ଚାବି->type) == ଚାବି_RSA) {
		ଯଦି (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			ଫେରନ୍ତୁ SSH_AGENT_RSA_SHA2_256;
		ଯଦି (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			ଫେରନ୍ତୁ SSH_AGENT_RSA_SHA2_512;
	}
	ଫେରନ୍ତୁ 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_agent_sign(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_char *sig = ଖାଲି, type = 0;
	size_t len = 0;
	u_int flags = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	*sigp = ଖାଲି;
	*lenp = 0;

	ଯଦି (datalen > SSH_ଚାବି_MAX_SIGN_DATA_SIZE)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(ଚାବି, alg);
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(ଚାବି, ସନ୍ଦେଶ)) != 0 ||
	    (r = sshbuf_put_string(ସନ୍ଦେଶ, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(ସନ୍ଦେଶ, flags)) != 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_request_reply(sock, ସନ୍ଦେଶ, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0)
		ଯାଅ out;
	ଯଦି (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_string(ସନ୍ଦେଶ, &sig, &len)) != 0)
		ଯାଅ out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	ଯଦି (!sshkey_is_sk(ଚାବି) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		ଯାଅ out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = ଖାଲି;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}

/* Encode key for a message to the agent. */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
encode_dest_constraint_hop(ସଂରଚନା sshbuf *m,
    ଅଚଳ ସଂରଚନା dest_constraint_hop *dch)
{
	ସଂରଚନା sshbuf *b;
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, ଖାଲି, 0)) != 0) /* reserved */
		ଯାଅ out;
	ପାଇଁ (i = 0; i < dch->nkeys; i++) {
		ଯଦି ((r = sshkey_puts(dch->ଚାବିଗୁଡ଼ିକ[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->ଚାବି_is_ca[i] != 0)) != 0)
			ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_stringb(m, b)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
encode_dest_constraint(ସଂରଚନା sshbuf *m, ଅଚଳ ସଂରଚନା dest_constraint *dc)
{
	ସଂରଚନା sshbuf *b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, ଖାଲି, 0)) != 0) /* reserved */
		ଯାଅ out;
	ଯଦି ((r = sshbuf_put_stringb(m, b)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
encode_constraints(ସଂରଚନା sshbuf *m, u_int life, u_int confirm,
    ଅଚଳ ଅକ୍ଷର *provider,
    ସଂରଚନା dest_constraint **dest_constraints, size_t ndest_constraints,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only, ସଂରଚନା sshkey **certs, size_t ncerts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	size_t i;

	ଯଦି (life != 0) {
		ଯଦି ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			ଯାଅ out;
	}
	ଯଦି (confirm != 0) {
		ଯଦି ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			ଯାଅ out;
	}
	ଯଦି (provider != ଖାଲି) {
		ଯଦି ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			ଯାଅ out;
	}
	ଯଦି (dest_constraints != ଖାଲି && ndest_constraints > 0) {
		ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ପାଇଁ (i = 0; i < ndest_constraints; i++) {
			ଯଦି ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			ଯାଅ out;
		sshbuf_free(b);
		b = ଖାଲି;
	}
	ଯଦି (ncerts != 0) {
		ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ପାଇଁ (i = 0; i < ncerts; i++) {
			ଯଦି ((r = sshkey_puts(certs[i], b)) != 0)
				ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			ଯାଅ out;
		sshbuf_free(b);
		b = ଖାଲି;
	}
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_add_identity_constrained(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ଅକ୍ଷର *comment, u_int life, u_int confirm,
    ଅଚଳ ଅକ୍ଷର *provider, ସଂରଚନା dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	ବାଛ (ଚାବି->type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି ଚାବି_RSA:
	ସ୍ଥିତି ଚାବି_RSA_CERT:
	ସ୍ଥିତି ଚାବି_ECDSA:
	ସ୍ଥିତି ଚାବି_ECDSA_CERT:
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
	ସ୍ଥିତି ଚାବି_ECDSA_SK_CERT:
#endif
	ସ୍ଥିତି ଚାବି_ED25519:
	ସ୍ଥିତି ଚାବି_ED25519_CERT:
	ସ୍ଥିତି ଚାବି_MLDSA44_ED25519:
	ସ୍ଥିତି ଚାବି_MLDSA44_ED25519_CERT:
	ସ୍ଥିତି ଚାବି_ED25519_SK:
	ସ୍ଥିତି ଚାବି_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, type)) != 0 ||
		    (r = sshkey_private_serialize(ଚାବି, ସନ୍ଦେଶ)) != 0 ||
		    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, comment)) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (constrained &&
	    (r = encode_constraints(ସନ୍ଦେଶ, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, ଖାଲି, 0)) != 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_request_reply_decode(sock, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_remove_identity(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char *blob = ଖାଲି;
	size_t blen;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	ଯଦି (ଚାବି->type != ଚାବି_UNSPEC) {
		ଯଦି ((r = sshkey_to_blob(ଚାବି, &blob, &blen)) != 0)
			ଯାଅ out;
		ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(ସନ୍ଦେଶ, blob, blen)) != 0)
			ଯାଅ out;
	} ଅନ୍ୟଥା {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି ((r = ssh_request_reply_decode(sock, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	ଯଦି (blob != ଖାଲି)
		freezero(blob, blen);
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_update_card(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା add, ଅଚଳ ଅକ୍ଷର *reader_id, ଅଚଳ ଅକ୍ଷର *pin,
    u_int life, u_int confirm,
    ସଂରଚନା dest_constraint **dest_constraints, size_t ndest_constraints,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only, ସଂରଚନା sshkey **certs, size_t ncerts)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	ଯଦି (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_ଚାବି_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_ଚାବି;
	} ଅନ୍ୟଥା
		type = SSH_AGENTC_REMOVE_SMARTCARD_ଚାବି;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, type)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, pin)) != 0)
		ଯାଅ out;
	ଯଦି (constrained &&
	    (r = encode_constraints(ସନ୍ଦେଶ, life, confirm, ଖାଲି,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_request_reply_decode(sock, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_remove_all_identities(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା version)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, type)) != 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_request_reply_decode(sock, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_agent_bind_hostkey(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ସଂରଚନା sshbuf *session_id, ଅଚଳ ସଂରଚନା sshbuf *signature,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା forwarding)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ଚାବି == ଖାଲି || session_id == ଖାଲି || signature == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(ଚାବି, ସନ୍ଦେଶ)) != 0 ||
	    (r = sshbuf_put_stringb(ସନ୍ଦେଶ, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(ସନ୍ଦେଶ, signature)) != 0 ||
	    (r = sshbuf_put_u8(ସନ୍ଦେଶ, forwarding ? 1 : 0)) != 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_request_reply_decode(sock, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}

/* Queries supported extension request types */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_agent_query_extensions(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅକ୍ଷର ***exts)
{
	ସଂରଚନା sshbuf *ସନ୍ଦେଶ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char type;
	ଅକ୍ଷର *cp = ଖାଲି, **ret = ଖାଲି;
	size_t i = 0;

	*exts = ଖାଲି;
	ଯଦି ((ସନ୍ଦେଶ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u8(ସନ୍ଦେଶ, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(ସନ୍ଦେଶ, "query")) != 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_request_reply(sock, ସନ୍ଦେଶ, ସନ୍ଦେଶ)) != 0)
		ଯାଅ out;
	ଯଦି ((r = sshbuf_get_u8(ସନ୍ଦେଶ, &type)) != 0)
		ଯାଅ out;
	ଯଦି (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		ଯାଅ out;
	}
	/* Reply should start with "query" */
	ଯଦି (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(ସନ୍ଦେଶ, &cp, ଖାଲି)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ret = xcalloc(1, ଆକାର(*ret));
	ଯେତେବେଳେ (sshbuf_len(ସନ୍ଦେଶ)) {
		ret = xrecallocarray(ret, i + 1, i + 2, ଆକାର(*ret));
		ଯଦି ((r = sshbuf_get_cstring(ସନ୍ଦେଶ, ret + i, ଖାଲି)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = ଖାଲି; /* transferred */
 out:
	ମୁକ୍ତ(cp);
	stringlist_free(ret);
	sshbuf_free(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}
