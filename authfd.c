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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/un.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <errno.h>

#अन्तर्भाव "ssh.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "xmalloc.h"

#परिभाषय MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#परिभाषय MAX_AGENT_प्रत्युत्तरम्_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#परिभाषय agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
स्थिर पूर्णाङ्क
decode_प्रत्युत्तरम्(u_char type)
{
	यदि (agent_failed(type))
		प्रत्यागम SSH_ERR_AGENT_FAILURE;
	अन्यथा यदि (type == SSH_AGENT_SUCCESS)
		प्रत्यागम 0;
	अन्यथा
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
पूर्णाङ्क
ssh_get_authentication_socket_मार्गः(ध्रुव वर्ण *authsocket, पूर्णाङ्क *fdp)
{
	पूर्णाङ्क sock, oerrno;
	संरचना sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	स्मृतिं_पूरय(&sunaddr, 0, परिमाण(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_मार्गः, authsocket, परिमाण(sunaddr.sun_मार्गः));

	यदि ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	यदि (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (संरचना sockaddr *)&sunaddr, परिमाण(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	यदि (fdp != रिक्त)
		*fdp = sock;
	अन्यथा
		close(sock);
	प्रत्यागम 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
पूर्णाङ्क
ssh_get_authentication_socket(पूर्णाङ्क *fdp)
{
	ध्रुव वर्ण *authsocket;

	यदि (fdp != रिक्त)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	यदि (authsocket == रिक्त || *authsocket == '\0')
		प्रत्यागम SSH_ERR_AGENT_NOT_PRESENT;

	प्रत्यागम ssh_get_authentication_socket_मार्गः(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
स्थिर पूर्णाङ्क
ssh_request_प्रत्युत्तरम्(पूर्णाङ्क sock, संरचना sshbuf *request, संरचना sshbuf *प्रत्युत्तरम्)
{
	पूर्णाङ्क r;
	आकार_t l, len;
	वर्ण buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	यदि (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		प्रत्यागम SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	यदि (atomicio(पठ, sock, buf, 4) != 4)
	    प्रत्यागम SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	यदि (len > MAX_AGENT_प्रत्युत्तरम्_LEN)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(प्रत्युत्तरम्);
	यावत् (len > 0) {
		l = len;
		यदि (l > परिमाण(buf))
			l = परिमाण(buf);
		यदि (atomicio(पठ, sock, buf, l) != l)
			प्रत्यागम SSH_ERR_AGENT_COMMUNICATION;
		यदि ((r = sshbuf_put(प्रत्युत्तरम्, buf, l)) != 0)
			प्रत्यागम r;
		len -= l;
	}
	प्रत्यागम 0;
}

/* Communicate with agent: sent request, read and decode status reply */
स्थिर पूर्णाङ्क
ssh_request_प्रत्युत्तरम्_decode(पूर्णाङ्क sock, संरचना sshbuf *request)
{
	संरचना sshbuf *प्रत्युत्तरम्;
	पूर्णाङ्क r;
	u_char type;

	यदि ((प्रत्युत्तरम् = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = ssh_request_प्रत्युत्तरम्(sock, request, प्रत्युत्तरम्)) != 0 ||
	    (r = sshbuf_get_u8(प्रत्युत्तरम्, &type)) != 0 ||
	    (r = decode_प्रत्युत्तरम्(type)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(प्रत्युत्तरम्);
	प्रत्यागम r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
शून्य
ssh_close_authentication_socket(पूर्णाङ्क sock)
{
	यदि (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != रिक्त)
		close(sock);
}

/* Lock/unlock agent */
पूर्णाङ्क
ssh_तालकम्_agent(पूर्णाङ्क sock, पूर्णाङ्क तालकम्, ध्रुव वर्ण *password)
{
	पूर्णाङ्क r;
	u_char type = तालकम् ? SSH_AGENTC_तालकम् : SSH_AGENTC_UNLOCK;
	संरचना sshbuf *सन्देशः;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u8(सन्देशः, type)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, password)) != 0 ||
	    (r = ssh_request_प्रत्युत्तरम्_decode(sock, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(सन्देशः);
	प्रत्यागम r;
}


स्थिर पूर्णाङ्क
deserialise_identity2(संरचना sshbuf *ids, संरचना sshkey **keyp, वर्ण **commentp)
{
	पूर्णाङ्क r;
	वर्ण *comment = रिक्त;
	ध्रुव u_char *blob;
	आकार_t blen;

	यदि ((r = sshbuf_get_string_प्रत्यक्षम्(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, रिक्त)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (commentp != रिक्त) {
		*commentp = comment;
		comment = रिक्त;
	}
	r = 0;
 बहिर्गमनम्:
	मुक्त(comment);
	प्रत्यागम r;
}

/*
 * Fetch list of identities held by the agent.
 */
पूर्णाङ्क
ssh_fetch_identitylist(पूर्णाङ्क sock, संरचना ssh_identitylist **idlp)
{
	u_char type;
	uint32_t अङ्कः, i;
	संरचना sshbuf *सन्देशः;
	संरचना ssh_identitylist *idl = रिक्त;
	पूर्णाङ्क r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		गच्छ बहिर्गमनम्;

	यदि ((r = ssh_request_प्रत्युत्तरम्(sock, सन्देशः, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;

	/* Get message type, and verify that we got a proper answer. */
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		गच्छ बहिर्गमनम्;
	} अन्यथा यदि (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}

	/* Get the number of entries in the response and check it for sanity. */
	यदि ((r = sshbuf_get_u32(सन्देशः, &अङ्कः)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (अङ्कः > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (अङ्कः == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		गच्छ बहिर्गमनम्;
	}

	/* Deserialise the response into a list of keys/comments */
	यदि ((idl = शून्यस्मृतिं_देहि(1, परिमाण(*idl))) == रिक्त ||
	    (idl->कुञ्चिकाः = शून्यस्मृतिं_देहि(अङ्कः, परिमाण(*idl->कुञ्चिकाः))) == रिक्त ||
	    (idl->comments = शून्यस्मृतिं_देहि(अङ्कः, परिमाण(*idl->comments))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	प्रति (i = 0; i < अङ्कः;) {
		यदि ((r = deserialise_identity2(सन्देशः, &(idl->कुञ्चिकाः[i]),
		    &(idl->comments[i]))) != 0) {
			यदि (r == SSH_ERR_कुञ्चिका_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				अङ्कः--;
				अनुवर्त;
			} अन्यथा
				गच्छ बहिर्गमनम्;
		}
		i++;
	}
	idl->nkeys = अङ्कः;
	*idlp = idl;
	idl = रिक्त;
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(सन्देशः);
	यदि (idl != रिक्त)
		ssh_free_identitylist(idl);
	प्रत्यागम r;
}

शून्य
ssh_free_identitylist(संरचना ssh_identitylist *idl)
{
	आकार_t i;

	यदि (idl == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < idl->nkeys; i++) {
		यदि (idl->कुञ्चिकाः != रिक्त)
			sshkey_free(idl->कुञ्चिकाः[i]);
		यदि (idl->comments != रिक्त)
			मुक्त(idl->comments[i]);
	}
	मुक्त(idl->कुञ्चिकाः);
	मुक्त(idl->comments);
	मुक्त(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
पूर्णाङ्क
ssh_agent_has_कुञ्चिका(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r, ret = SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
	आकार_t i;
	संरचना ssh_identitylist *idlist = रिक्त;

	यदि ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		प्रत्यागम r;
	}

	प्रति (i = 0; i < idlist->nkeys; i++) {
		यदि (sshkey_equal_लौकिकम्(idlist->कुञ्चिकाः[i], कुञ्चिका)) {
			ret = 0;
			भङ्ग;
		}
	}

	ssh_free_identitylist(idlist);
	प्रत्यागम ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
स्थिर u_int
agent_encode_alg(ध्रुव संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *alg)
{
	यदि (alg != रिक्त && sshkey_type_plain(कुञ्चिका->type) == कुञ्चिका_RSA) {
		यदि (वाक्यं_तुलय(alg, "rsa-sha2-256") == 0 ||
		    वाक्यं_तुलय(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			प्रत्यागम SSH_AGENT_RSA_SHA2_256;
		यदि (वाक्यं_तुलय(alg, "rsa-sha2-512") == 0 ||
		    वाक्यं_तुलय(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			प्रत्यागम SSH_AGENT_RSA_SHA2_512;
	}
	प्रत्यागम 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
पूर्णाङ्क
ssh_agent_sign(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen, ध्रुव वर्ण *alg, u_int compat)
{
	संरचना sshbuf *सन्देशः;
	u_char *sig = रिक्त, type = 0;
	आकार_t len = 0;
	u_int flags = 0;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	*sigp = रिक्त;
	*lenp = 0;

	यदि (datalen > SSH_कुञ्चिका_MAX_SIGN_दत्त_आकार)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(कुञ्चिका, alg);
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(कुञ्चिका, सन्देशः)) != 0 ||
	    (r = sshbuf_put_string(सन्देशः, दत्त, datalen)) != 0 ||
	    (r = sshbuf_put_u32(सन्देशः, flags)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_request_प्रत्युत्तरम्(sock, सन्देशः, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		गच्छ बहिर्गमनम्;
	} अन्यथा यदि (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_get_string(सन्देशः, &sig, &len)) != 0)
		गच्छ बहिर्गमनम्;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	यदि (!sshkey_is_sk(कुञ्चिका) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = रिक्त;
	len = 0;
	r = 0;
 बहिर्गमनम्:
	freezero(sig, len);
	sshbuf_free(सन्देशः);
	प्रत्यागम r;
}

/* Encode key for a message to the agent. */

स्थिर पूर्णाङ्क
encode_dest_constraint_hop(संरचना sshbuf *m,
    ध्रुव संरचना dest_constraint_hop *dch)
{
	संरचना sshbuf *b;
	u_int i;
	पूर्णाङ्क r;

	यदि ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, रिक्त, 0)) != 0) /* reserved */
		गच्छ बहिर्गमनम्;
	प्रति (i = 0; i < dch->nkeys; i++) {
		यदि ((r = sshkey_puts(dch->कुञ्चिकाः[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->कुञ्चिका_is_ca[i] != 0)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_stringb(m, b)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
encode_dest_constraint(संरचना sshbuf *m, ध्रुव संरचना dest_constraint *dc)
{
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	यदि ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->गन्तव्यम्)) != 0 ||
	    (r = sshbuf_put_string(b, रिक्त, 0)) != 0) /* reserved */
		गच्छ बहिर्गमनम्;
	यदि ((r = sshbuf_put_stringb(m, b)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
encode_constraints(संरचना sshbuf *m, u_int life, u_int confirm,
    ध्रुव वर्ण *provider,
    संरचना dest_constraint **dest_constraints, आकार_t ndest_constraints,
    पूर्णाङ्क cert_only, संरचना sshkey **certs, आकार_t ncerts)
{
	पूर्णाङ्क r;
	संरचना sshbuf *b = रिक्त;
	आकार_t i;

	यदि (life != 0) {
		यदि ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि (confirm != 0) {
		यदि ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि (provider != रिक्त) {
		यदि ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि (dest_constraints != रिक्त && ndest_constraints > 0) {
		यदि ((b = sshbuf_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		प्रति (i = 0; i < ndest_constraints; i++) {
			यदि ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				गच्छ बहिर्गमनम्;
		}
		यदि ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			गच्छ बहिर्गमनम्;
		sshbuf_free(b);
		b = रिक्त;
	}
	यदि (ncerts != 0) {
		यदि ((b = sshbuf_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		प्रति (i = 0; i < ncerts; i++) {
			यदि ((r = sshkey_puts(certs[i], b)) != 0)
				गच्छ बहिर्गमनम्;
		}
		यदि ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			गच्छ बहिर्गमनम्;
		sshbuf_free(b);
		b = रिक्त;
	}
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णाङ्क
ssh_सङ्कलय_तटस्थः_constrained(पूर्णाङ्क sock, संरचना sshkey *कुञ्चिका,
    ध्रुव वर्ण *comment, u_int life, u_int confirm,
    ध्रुव वर्ण *provider, संरचना dest_constraint **dest_constraints,
    आकार_t ndest_constraints)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	विकल्प (कुञ्चिका->type) {
#यदि_परिभाषितम् WITH_OPENSSL
	पक्ष कुञ्चिका_RSA:
	पक्ष कुञ्चिका_RSA_CERT:
	पक्ष कुञ्चिका_ECDSA:
	पक्ष कुञ्चिका_ECDSA_CERT:
	पक्ष कुञ्चिका_ECDSA_SK:
	पक्ष कुञ्चिका_ECDSA_SK_CERT:
#यदि_अन्तः
	पक्ष कुञ्चिका_ED25519:
	पक्ष कुञ्चिका_ED25519_CERT:
	पक्ष कुञ्चिका_MLDSA44_ED25519:
	पक्ष कुञ्चिका_MLDSA44_ED25519_CERT:
	पक्ष कुञ्चिका_ED25519_SK:
	पक्ष कुञ्चिका_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_सङ्कलय_ID_CONSTRAINED :
		    SSH2_AGENTC_सङ्कलय_तटस्थः;
		यदि ((r = sshbuf_put_u8(सन्देशः, type)) != 0 ||
		    (r = sshkey_वैयक्तिकम्_serialize(कुञ्चिका, सन्देशः)) != 0 ||
		    (r = sshbuf_put_cstring(सन्देशः, comment)) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
	स्वभाव:
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	यदि (constrained &&
	    (r = encode_constraints(सन्देशः, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, रिक्त, 0)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_request_प्रत्युत्तरम्_decode(sock, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(सन्देशः);
	प्रत्यागम r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णाङ्क
ssh_remove_तटस्थः(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;
	u_char *blob = रिक्त;
	आकार_t blen;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	यदि (कुञ्चिका->type != कुञ्चिका_UNSPEC) {
		यदि ((r = sshkey_गन्तव्यम्_blob(कुञ्चिका, &blob, &blen)) != 0)
			गच्छ बहिर्गमनम्;
		यदि ((r = sshbuf_put_u8(सन्देशः,
		    SSH2_AGENTC_REMOVE_तटस्थः)) != 0 ||
		    (r = sshbuf_put_string(सन्देशः, blob, blen)) != 0)
			गच्छ बहिर्गमनम्;
	} अन्यथा {
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = ssh_request_प्रत्युत्तरम्_decode(sock, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	यदि (blob != रिक्त)
		freezero(blob, blen);
	sshbuf_free(सन्देशः);
	प्रत्यागम r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णाङ्क
ssh_update_card(पूर्णाङ्क sock, पूर्णाङ्क सङ्कलय, ध्रुव वर्ण *reader_id, ध्रुव वर्ण *pin,
    u_int life, u_int confirm,
    संरचना dest_constraint **dest_constraints, आकार_t ndest_constraints,
    पूर्णाङ्क cert_only, संरचना sshkey **certs, आकार_t ncerts)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	यदि (सङ्कलय) {
		type = constrained ?
		    SSH_AGENTC_सङ्कलय_SMARTCARD_कुञ्चिका_CONSTRAINED :
		    SSH_AGENTC_सङ्कलय_SMARTCARD_कुञ्चिका;
	} अन्यथा
		type = SSH_AGENTC_REMOVE_SMARTCARD_कुञ्चिका;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u8(सन्देशः, type)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, pin)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (constrained &&
	    (r = encode_constraints(सन्देशः, life, confirm, रिक्त,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_request_प्रत्युत्तरम्_decode(sock, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(सन्देशः);
	प्रत्यागम r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
पूर्णाङ्क
ssh_remove_all_identities(पूर्णाङ्क sock, पूर्णाङ्क संस्करणम्)
{
	संरचना sshbuf *सन्देशः;
	u_char type = (संस्करणम् == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	पूर्णाङ्क r;

	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u8(सन्देशः, type)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_request_प्रत्युत्तरम्_decode(sock, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(सन्देशः);
	प्रत्यागम r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
पूर्णाङ्क
ssh_agent_bind_hostkey(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव संरचना sshbuf *session_id, ध्रुव संरचना sshbuf *signature,
    पूर्णाङ्क forwarding)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;

	यदि (कुञ्चिका == रिक्त || session_id == रिक्त || signature == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(कुञ्चिका, सन्देशः)) != 0 ||
	    (r = sshbuf_put_stringb(सन्देशः, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(सन्देशः, signature)) != 0 ||
	    (r = sshbuf_put_u8(सन्देशः, forwarding ? 1 : 0)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_request_प्रत्युत्तरम्_decode(sock, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(सन्देशः);
	प्रत्यागम r;
}

/* Queries supported extension request types */
पूर्णाङ्क
ssh_agent_query_extensions(पूर्णाङ्क sock, वर्ण ***exts)
{
	संरचना sshbuf *सन्देशः;
	पूर्णाङ्क r;
	u_char type;
	वर्ण *cp = रिक्त, **ret = रिक्त;
	आकार_t i = 0;

	*exts = रिक्त;
	यदि ((सन्देशः = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u8(सन्देशः, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(सन्देशः, "query")) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = ssh_request_प्रत्युत्तरम्(sock, सन्देशः, सन्देशः)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = sshbuf_get_u8(सन्देशः, &type)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		गच्छ बहिर्गमनम्;
	}
	/* Reply should start with "query" */
	यदि (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(सन्देशः, &cp, रिक्त)) != 0 ||
	   वाक्यं_तुलय(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	ret = xcalloc(1, परिमाण(*ret));
	यावत् (sshbuf_len(सन्देशः)) {
		ret = xrecallocarray(ret, i + 1, i + 2, परिमाण(*ret));
		यदि ((r = sshbuf_get_cstring(सन्देशः, ret + i, रिक्त)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = रिक्त; /* transferred */
 बहिर्गमनम्:
	मुक्त(cp);
	stringlist_free(ret);
	sshbuf_free(सन्देशः);
	प्रत्यागम r;
}
