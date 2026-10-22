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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/un.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <errno.h>

#అన్తర్భావ "ssh.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "xmalloc.h"

#నిర్వచించు MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#నిర్వచించు MAX_AGENT_జవాబు_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#నిర్వచించు agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
స్థిర పూర్ణాంకం
decode_జవాబు(u_char type)
{
	ఒకవేళ (agent_failed(type))
		తిరిగి SSH_ERR_AGENT_FAILURE;
	లేకపోతే ఒకవేళ (type == SSH_AGENT_SUCCESS)
		తిరిగి 0;
	లేకపోతే
		తిరిగి SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
పూర్ణాంకం
ssh_get_authentication_socket_మార్గం(స్థిరరాశి అక్షరం *authsocket, పూర్ణాంకం *fdp)
{
	పూర్ణాంకం sock, oerrno;
	నిర్మాణం sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, పరిమాణం(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_మార్గం, authsocket, పరిమాణం(sunaddr.sun_మార్గం));

	ఒకవేళ ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		తిరిగి SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	ఒకవేళ (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (నిర్మాణం sockaddr *)&sunaddr, పరిమాణం(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}
	ఒకవేళ (fdp != ఖాళీ)
		*fdp = sock;
	లేకపోతే
		close(sock);
	తిరిగి 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
పూర్ణాంకం
ssh_get_authentication_socket(పూర్ణాంకం *fdp)
{
	స్థిరరాశి అక్షరం *authsocket;

	ఒకవేళ (fdp != ఖాళీ)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	ఒకవేళ (authsocket == ఖాళీ || *authsocket == '\0')
		తిరిగి SSH_ERR_AGENT_NOT_PRESENT;

	తిరిగి ssh_get_authentication_socket_మార్గం(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
స్థిర పూర్ణాంకం
ssh_request_జవాబు(పూర్ణాంకం sock, నిర్మాణం sshbuf *request, నిర్మాణం sshbuf *జవాబు)
{
	పూర్ణాంకం r;
	కొలత_t l, len;
	అక్షరం buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	ఒకవేళ (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		తిరిగి SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	ఒకవేళ (atomicio(పఠ, sock, buf, 4) != 4)
	    తిరిగి SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	ఒకవేళ (len > MAX_AGENT_జవాబు_LEN)
		తిరిగి SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(జవాబు);
	అయితే (len > 0) {
		l = len;
		ఒకవేళ (l > పరిమాణం(buf))
			l = పరిమాణం(buf);
		ఒకవేళ (atomicio(పఠ, sock, buf, l) != l)
			తిరిగి SSH_ERR_AGENT_COMMUNICATION;
		ఒకవేళ ((r = sshbuf_put(జవాబు, buf, l)) != 0)
			తిరిగి r;
		len -= l;
	}
	తిరిగి 0;
}

/* Communicate with agent: sent request, read and decode status reply */
స్థిర పూర్ణాంకం
ssh_request_జవాబు_decode(పూర్ణాంకం sock, నిర్మాణం sshbuf *request)
{
	నిర్మాణం sshbuf *జవాబు;
	పూర్ణాంకం r;
	u_char type;

	ఒకవేళ ((జవాబు = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = ssh_request_జవాబు(sock, request, జవాబు)) != 0 ||
	    (r = sshbuf_get_u8(జవాబు, &type)) != 0 ||
	    (r = decode_జవాబు(type)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(జవాబు);
	తిరిగి r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
శూన్య
ssh_close_authentication_socket(పూర్ణాంకం sock)
{
	ఒకవేళ (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != ఖాళీ)
		close(sock);
}

/* Lock/unlock agent */
పూర్ణాంకం
ssh_తాళం_agent(పూర్ణాంకం sock, పూర్ణాంకం తాళం, స్థిరరాశి అక్షరం *password)
{
	పూర్ణాంకం r;
	u_char type = తాళం ? SSH_AGENTC_తాళం : SSH_AGENTC_UNLOCK;
	నిర్మాణం sshbuf *సందేశం;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, type)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, password)) != 0 ||
	    (r = ssh_request_జవాబు_decode(sock, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(సందేశం);
	తిరిగి r;
}


స్థిర పూర్ణాంకం
deserialise_identity2(నిర్మాణం sshbuf *ids, నిర్మాణం sshkey **keyp, అక్షరం **commentp)
{
	పూర్ణాంకం r;
	అక్షరం *comment = ఖాళీ;
	స్థిరరాశి u_char *blob;
	కొలత_t blen;

	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (commentp != ఖాళీ) {
		*commentp = comment;
		comment = ఖాళీ;
	}
	r = 0;
 బహిర్గతం:
	విడుదల(comment);
	తిరిగి r;
}

/*
 * Fetch list of identities held by the agent.
 */
పూర్ణాంకం
ssh_fetch_identitylist(పూర్ణాంకం sock, నిర్మాణం ssh_identitylist **idlp)
{
	u_char type;
	uint32_t అంకె, i;
	నిర్మాణం sshbuf *సందేశం;
	నిర్మాణం ssh_identitylist *idl = ఖాళీ;
	పూర్ణాంకం r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = ssh_request_జవాబు(sock, సందేశం, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Get message type, and verify that we got a proper answer. */
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/* Get the number of entries in the response and check it for sanity. */
	ఒకవేళ ((r = sshbuf_get_u32(సందేశం, &అంకె)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (అంకె > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (అంకె == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		వెళ్ళు బహిర్గతం;
	}

	/* Deserialise the response into a list of keys/comments */
	ఒకవేళ ((idl = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*idl))) == ఖాళీ ||
	    (idl->కీలకాలు = సున్నా_జ్ఞాపకం_ఇవ్వు(అంకె, పరిమాణం(*idl->కీలకాలు))) == ఖాళీ ||
	    (idl->comments = సున్నా_జ్ఞాపకం_ఇవ్వు(అంకె, పరిమాణం(*idl->comments))) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	కొరకు (i = 0; i < అంకె;) {
		ఒకవేళ ((r = deserialise_identity2(సందేశం, &(idl->కీలకాలు[i]),
		    &(idl->comments[i]))) != 0) {
			ఒకవేళ (r == SSH_ERR_కీలకం_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				అంకె--;
				కొనసాగు;
			} లేకపోతే
				వెళ్ళు బహిర్గతం;
		}
		i++;
	}
	idl->nkeys = అంకె;
	*idlp = idl;
	idl = ఖాళీ;
	r = 0;
 బహిర్గతం:
	sshbuf_free(సందేశం);
	ఒకవేళ (idl != ఖాళీ)
		ssh_free_identitylist(idl);
	తిరిగి r;
}

శూన్య
ssh_free_identitylist(నిర్మాణం ssh_identitylist *idl)
{
	కొలత_t i;

	ఒకవేళ (idl == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < idl->nkeys; i++) {
		ఒకవేళ (idl->కీలకాలు != ఖాళీ)
			sshkey_free(idl->కీలకాలు[i]);
		ఒకవేళ (idl->comments != ఖాళీ)
			విడుదల(idl->comments[i]);
	}
	విడుదల(idl->కీలకాలు);
	విడుదల(idl->comments);
	విడుదల(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం
ssh_agent_has_కీలకం(పూర్ణాంకం sock, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r, ret = SSH_ERR_కీలకం_NOT_దొరికింది;
	కొలత_t i;
	నిర్మాణం ssh_identitylist *idlist = ఖాళీ;

	ఒకవేళ ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		తిరిగి r;
	}

	కొరకు (i = 0; i < idlist->nkeys; i++) {
		ఒకవేళ (sshkey_equal_ప్రజా(idlist->కీలకాలు[i], కీలకం)) {
			ret = 0;
			ఆపు;
		}
	}

	ssh_free_identitylist(idlist);
	తిరిగి ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
స్థిర u_int
agent_encode_alg(స్థిరరాశి నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *alg)
{
	ఒకవేళ (alg != ఖాళీ && sshkey_type_plain(కీలకం->type) == కీలకం_RSA) {
		ఒకవేళ (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			తిరిగి SSH_AGENT_RSA_SHA2_256;
		ఒకవేళ (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			తిరిగి SSH_AGENT_RSA_SHA2_512;
	}
	తిరిగి 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
పూర్ణాంకం
ssh_agent_sign(పూర్ణాంకం sock, స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen, స్థిరరాశి అక్షరం *alg, u_int compat)
{
	నిర్మాణం sshbuf *సందేశం;
	u_char *sig = ఖాళీ, type = 0;
	కొలత_t len = 0;
	u_int flags = 0;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	*sigp = ఖాళీ;
	*lenp = 0;

	ఒకవేళ (datalen > SSH_కీలకం_MAX_SIGN_దత్తాంశం_కొలత)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(కీలకం, alg);
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(కీలకం, సందేశం)) != 0 ||
	    (r = sshbuf_put_string(సందేశం, దత్తాంశం, datalen)) != 0 ||
	    (r = sshbuf_put_u32(సందేశం, flags)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_request_జవాబు(sock, సందేశం, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_string(సందేశం, &sig, &len)) != 0)
		వెళ్ళు బహిర్గతం;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	ఒకవేళ (!sshkey_is_sk(కీలకం) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = ఖాళీ;
	len = 0;
	r = 0;
 బహిర్గతం:
	freezero(sig, len);
	sshbuf_free(సందేశం);
	తిరిగి r;
}

/* Encode key for a message to the agent. */

స్థిర పూర్ణాంకం
encode_dest_constraint_hop(నిర్మాణం sshbuf *m,
    స్థిరరాశి నిర్మాణం dest_constraint_hop *dch)
{
	నిర్మాణం sshbuf *b;
	u_int i;
	పూర్ణాంకం r;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, ఖాళీ, 0)) != 0) /* reserved */
		వెళ్ళు బహిర్గతం;
	కొరకు (i = 0; i < dch->nkeys; i++) {
		ఒకవేళ ((r = sshkey_puts(dch->కీలకాలు[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->కీలకం_is_ca[i] != 0)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_stringb(m, b)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
encode_dest_constraint(నిర్మాణం sshbuf *m, స్థిరరాశి నిర్మాణం dest_constraint *dc)
{
	నిర్మాణం sshbuf *b;
	పూర్ణాంకం r;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->గమ్యం)) != 0 ||
	    (r = sshbuf_put_string(b, ఖాళీ, 0)) != 0) /* reserved */
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshbuf_put_stringb(m, b)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
encode_constraints(నిర్మాణం sshbuf *m, u_int life, u_int confirm,
    స్థిరరాశి అక్షరం *provider,
    నిర్మాణం dest_constraint **dest_constraints, కొలత_t ndest_constraints,
    పూర్ణాంకం cert_only, నిర్మాణం sshkey **certs, కొలత_t ncerts)
{
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *b = ఖాళీ;
	కొలత_t i;

	ఒకవేళ (life != 0) {
		ఒకవేళ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (confirm != 0) {
		ఒకవేళ ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (provider != ఖాళీ) {
		ఒకవేళ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (dest_constraints != ఖాళీ && ndest_constraints > 0) {
		ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		కొరకు (i = 0; i < ndest_constraints; i++) {
			ఒకవేళ ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			వెళ్ళు బహిర్గతం;
		sshbuf_free(b);
		b = ఖాళీ;
	}
	ఒకవేళ (ncerts != 0) {
		ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		కొరకు (i = 0; i < ncerts; i++) {
			ఒకవేళ ((r = sshkey_puts(certs[i], b)) != 0)
				వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			వెళ్ళు బహిర్గతం;
		sshbuf_free(b);
		b = ఖాళీ;
	}
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
పూర్ణాంకం
ssh_కూడు_తటస్థం_constrained(పూర్ణాంకం sock, నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి అక్షరం *comment, u_int life, u_int confirm,
    స్థిరరాశి అక్షరం *provider, నిర్మాణం dest_constraint **dest_constraints,
    కొలత_t ndest_constraints)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	ఎంపిక (కీలకం->type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి కీలకం_RSA:
	స్థితి కీలకం_RSA_CERT:
	స్థితి కీలకం_ECDSA:
	స్థితి కీలకం_ECDSA_CERT:
	స్థితి కీలకం_ECDSA_SK:
	స్థితి కీలకం_ECDSA_SK_CERT:
#అయితే_ముగింపు
	స్థితి కీలకం_ED25519:
	స్థితి కీలకం_ED25519_CERT:
	స్థితి కీలకం_MLDSA44_ED25519:
	స్థితి కీలకం_MLDSA44_ED25519_CERT:
	స్థితి కీలకం_ED25519_SK:
	స్థితి కీలకం_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_కూడు_ID_CONSTRAINED :
		    SSH2_AGENTC_కూడు_తటస్థం;
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం, type)) != 0 ||
		    (r = sshkey_వ్యక్తిగత_serialize(కీలకం, సందేశం)) != 0 ||
		    (r = sshbuf_put_cstring(సందేశం, comment)) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
	అప్రమేయ:
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (constrained &&
	    (r = encode_constraints(సందేశం, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, ఖాళీ, 0)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_request_జవాబు_decode(sock, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(సందేశం);
	తిరిగి r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
పూర్ణాంకం
ssh_remove_తటస్థం(పూర్ణాంకం sock, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;
	u_char *blob = ఖాళీ;
	కొలత_t blen;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	ఒకవేళ (కీలకం->type != కీలకం_UNSPEC) {
		ఒకవేళ ((r = sshkey_గమ్యం_blob(కీలకం, &blob, &blen)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ ((r = sshbuf_put_u8(సందేశం,
		    SSH2_AGENTC_REMOVE_తటస్థం)) != 0 ||
		    (r = sshbuf_put_string(సందేశం, blob, blen)) != 0)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = ssh_request_జవాబు_decode(sock, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	ఒకవేళ (blob != ఖాళీ)
		freezero(blob, blen);
	sshbuf_free(సందేశం);
	తిరిగి r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
పూర్ణాంకం
ssh_update_card(పూర్ణాంకం sock, పూర్ణాంకం కూడు, స్థిరరాశి అక్షరం *reader_id, స్థిరరాశి అక్షరం *pin,
    u_int life, u_int confirm,
    నిర్మాణం dest_constraint **dest_constraints, కొలత_t ndest_constraints,
    పూర్ణాంకం cert_only, నిర్మాణం sshkey **certs, కొలత_t ncerts)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	ఒకవేళ (కూడు) {
		type = constrained ?
		    SSH_AGENTC_కూడు_SMARTCARD_కీలకం_CONSTRAINED :
		    SSH_AGENTC_కూడు_SMARTCARD_కీలకం;
	} లేకపోతే
		type = SSH_AGENTC_REMOVE_SMARTCARD_కీలకం;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, type)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, pin)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (constrained &&
	    (r = encode_constraints(సందేశం, life, confirm, ఖాళీ,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_request_జవాబు_decode(sock, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(సందేశం);
	తిరిగి r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
పూర్ణాంకం
ssh_remove_all_identities(పూర్ణాంకం sock, పూర్ణాంకం సంస్కరణ)
{
	నిర్మాణం sshbuf *సందేశం;
	u_char type = (సంస్కరణ == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	పూర్ణాంకం r;

	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, type)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_request_జవాబు_decode(sock, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(సందేశం);
	తిరిగి r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
పూర్ణాంకం
ssh_agent_bind_hostkey(పూర్ణాంకం sock, స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి నిర్మాణం sshbuf *session_id, స్థిరరాశి నిర్మాణం sshbuf *signature,
    పూర్ణాంకం forwarding)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;

	ఒకవేళ (కీలకం == ఖాళీ || session_id == ఖాళీ || signature == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(కీలకం, సందేశం)) != 0 ||
	    (r = sshbuf_put_stringb(సందేశం, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(సందేశం, signature)) != 0 ||
	    (r = sshbuf_put_u8(సందేశం, forwarding ? 1 : 0)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_request_జవాబు_decode(sock, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(సందేశం);
	తిరిగి r;
}

/* Queries supported extension request types */
పూర్ణాంకం
ssh_agent_query_extensions(పూర్ణాంకం sock, అక్షరం ***exts)
{
	నిర్మాణం sshbuf *సందేశం;
	పూర్ణాంకం r;
	u_char type;
	అక్షరం *cp = ఖాళీ, **ret = ఖాళీ;
	కొలత_t i = 0;

	*exts = ఖాళీ;
	ఒకవేళ ((సందేశం = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u8(సందేశం, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(సందేశం, "query")) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_request_జవాబు(sock, సందేశం, సందేశం)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshbuf_get_u8(సందేశం, &type)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		వెళ్ళు బహిర్గతం;
	}
	/* Reply should start with "query" */
	ఒకవేళ (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(సందేశం, &cp, ఖాళీ)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ret = xcalloc(1, పరిమాణం(*ret));
	అయితే (sshbuf_len(సందేశం)) {
		ret = xrecallocarray(ret, i + 1, i + 2, పరిమాణం(*ret));
		ఒకవేళ ((r = sshbuf_get_cstring(సందేశం, ret + i, ఖాళీ)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = ఖాళీ; /* transferred */
 బహిర్గతం:
	విడుదల(cp);
	stringlist_free(ret);
	sshbuf_free(సందేశం);
	తిరిగి r;
}
