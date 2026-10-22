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

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
स्थिर पूर्णांक
decode_reply(u_char type)
{
	जर (agent_failed(type))
		परत SSH_ERR_AGENT_FAILURE;
	अन्यथा जर (type == SSH_AGENT_SUCCESS)
		परत 0;
	अन्यथा
		परत SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
पूर्णांक
ssh_get_authentication_socket_path(स्थिरांक अक्षर *authsocket, पूर्णांक *fdp)
{
	पूर्णांक sock, oerrno;
	संरचना sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	स_रखो(&sunaddr, 0, आकार(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, आकार(sunaddr.sun_path));

	जर ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		परत SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	जर (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (संरचना sockaddr *)&sunaddr, आकार(sunaddr)) == -1) {
		oerrno = त्रुटि_सं;
		बंद(sock);
		त्रुटि_सं = oerrno;
		परत SSH_ERR_SYSTEM_ERROR;
	}
	जर (fdp != रिक्त)
		*fdp = sock;
	अन्यथा
		बंद(sock);
	परत 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
पूर्णांक
ssh_get_authentication_socket(पूर्णांक *fdp)
{
	स्थिरांक अक्षर *authsocket;

	जर (fdp != रिक्त)
		*fdp = -1;

	authsocket = दो_पर्या(SSH_AUTHSOCKET_ENV_NAME);
	जर (authsocket == रिक्त || *authsocket == '\0')
		परत SSH_ERR_AGENT_NOT_PRESENT;

	परत ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
स्थिर पूर्णांक
ssh_request_reply(पूर्णांक sock, संरचना sshbuf *request, संरचना sshbuf *reply)
{
	पूर्णांक r;
	माप_प्रकार l, len;
	अक्षर buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	जर (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		परत SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	जर (atomicio(पठ, sock, buf, 4) != 4)
	    परत SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	जर (len > MAX_AGENT_REPLY_LEN)
		परत SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	पर्यंत (len > 0) {
		l = len;
		जर (l > आकार(buf))
			l = आकार(buf);
		जर (atomicio(पठ, sock, buf, l) != l)
			परत SSH_ERR_AGENT_COMMUNICATION;
		जर ((r = sshbuf_put(reply, buf, l)) != 0)
			परत r;
		len -= l;
	}
	परत 0;
}

/* Communicate with agent: sent request, read and decode status reply */
स्थिर पूर्णांक
ssh_request_reply_decode(पूर्णांक sock, संरचना sshbuf *request)
{
	संरचना sshbuf *reply;
	पूर्णांक r;
	u_char type;

	जर ((reply = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	परत r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
शून्य
ssh_close_authentication_socket(पूर्णांक sock)
{
	जर (sock != -1 && दो_पर्या(SSH_AUTHSOCKET_ENV_NAME) != रिक्त)
		बंद(sock);
}

/* Lock/unlock agent */
पूर्णांक
ssh_lock_agent(पूर्णांक sock, पूर्णांक lock, स्थिरांक अक्षर *password)
{
	पूर्णांक r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	संरचना sshbuf *संदेश;

	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u8(संदेश, type)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	परत r;
}


स्थिर पूर्णांक
deserialise_identity2(संरचना sshbuf *ids, संरचना sshkey **keyp, अक्षर **commentp)
{
	पूर्णांक r;
	अक्षर *comment = रिक्त;
	स्थिरांक u_char *blob;
	माप_प्रकार blen;

	जर ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, रिक्त)) != 0)
		जा out;
	जर ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		जा out;
	जर (commentp != रिक्त) {
		*commentp = comment;
		comment = रिक्त;
	}
	r = 0;
 out:
	मुक्त(comment);
	परत r;
}

/*
 * Fetch list of identities held by the agent.
 */
पूर्णांक
ssh_fetch_identitylist(पूर्णांक sock, संरचना ssh_identitylist **idlp)
{
	u_char type;
	uint32_t अंक, i;
	संरचना sshbuf *संदेश;
	संरचना ssh_identitylist *idl = रिक्त;
	पूर्णांक r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u8(संदेश, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		जा out;

	जर ((r = ssh_request_reply(sock, संदेश, संदेश)) != 0)
		जा out;

	/* Get message type, and verify that we got a proper answer. */
	जर ((r = sshbuf_get_u8(संदेश, &type)) != 0)
		जा out;
	जर (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		जा out;
	} अन्यथा जर (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	जर ((r = sshbuf_get_u32(संदेश, &अंक)) != 0)
		जा out;
	जर (अंक > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (अंक == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		जा out;
	}

	/* Deserialise the response into a list of keys/comments */
	जर ((idl = सुस्मृति(1, आकार(*idl))) == रिक्त ||
	    (idl->किल्ल्या = सुस्मृति(अंक, आकार(*idl->किल्ल्या))) == रिक्त ||
	    (idl->comments = सुस्मृति(अंक, आकार(*idl->comments))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	साठी (i = 0; i < अंक;) {
		जर ((r = deserialise_identity2(संदेश, &(idl->किल्ल्या[i]),
		    &(idl->comments[i]))) != 0) {
			जर (r == SSH_ERR_किल्ली_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				अंक--;
				सुरूठेवा;
			} अन्यथा
				जा out;
		}
		i++;
	}
	idl->nkeys = अंक;
	*idlp = idl;
	idl = रिक्त;
	r = 0;
 out:
	sshbuf_free(संदेश);
	जर (idl != रिक्त)
		ssh_free_identitylist(idl);
	परत r;
}

शून्य
ssh_free_identitylist(संरचना ssh_identitylist *idl)
{
	माप_प्रकार i;

	जर (idl == रिक्त)
		परत;
	साठी (i = 0; i < idl->nkeys; i++) {
		जर (idl->किल्ल्या != रिक्त)
			sshkey_free(idl->किल्ल्या[i]);
		जर (idl->comments != रिक्त)
			मुक्त(idl->comments[i]);
	}
	मुक्त(idl->किल्ल्या);
	मुक्त(idl->comments);
	मुक्त(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक
ssh_agent_has_किल्ली(पूर्णांक sock, स्थिरांक संरचना sshkey *किल्ली)
{
	पूर्णांक r, ret = SSH_ERR_किल्ली_NOT_FOUND;
	माप_प्रकार i;
	संरचना ssh_identitylist *idlist = रिक्त;

	जर ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		परत r;
	}

	साठी (i = 0; i < idlist->nkeys; i++) {
		जर (sshkey_equal_public(idlist->किल्ल्या[i], किल्ली)) {
			ret = 0;
			थांबा;
		}
	}

	ssh_free_identitylist(idlist);
	परत ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
स्थिर u_int
agent_encode_alg(स्थिरांक संरचना sshkey *किल्ली, स्थिरांक अक्षर *alg)
{
	जर (alg != रिक्त && sshkey_type_plain(किल्ली->type) == किल्ली_RSA) {
		जर (म_भेद(alg, "rsa-sha2-256") == 0 ||
		    म_भेद(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			परत SSH_AGENT_RSA_SHA2_256;
		जर (म_भेद(alg, "rsa-sha2-512") == 0 ||
		    म_भेद(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			परत SSH_AGENT_RSA_SHA2_512;
	}
	परत 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
पूर्णांक
ssh_agent_sign(पूर्णांक sock, स्थिरांक संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen, स्थिरांक अक्षर *alg, u_int compat)
{
	संरचना sshbuf *संदेश;
	u_char *sig = रिक्त, type = 0;
	माप_प्रकार len = 0;
	u_int flags = 0;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*sigp = रिक्त;
	*lenp = 0;

	जर (datalen > SSH_किल्ली_MAX_SIGN_DATA_SIZE)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(किल्ली, alg);
	जर ((r = sshbuf_put_u8(संदेश, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(किल्ली, संदेश)) != 0 ||
	    (r = sshbuf_put_string(संदेश, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, flags)) != 0)
		जा out;
	जर ((r = ssh_request_reply(sock, संदेश, संदेश)) != 0)
		जा out;
	जर ((r = sshbuf_get_u8(संदेश, &type)) != 0)
		जा out;
	जर (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		जा out;
	} अन्यथा जर (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर ((r = sshbuf_get_string(संदेश, &sig, &len)) != 0)
		जा out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	जर (!sshkey_is_sk(किल्ली) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		जा out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = रिक्त;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(संदेश);
	परत r;
}

/* Encode key for a message to the agent. */

स्थिर पूर्णांक
encode_dest_constraint_hop(संरचना sshbuf *m,
    स्थिरांक संरचना dest_constraint_hop *dch)
{
	संरचना sshbuf *b;
	u_int i;
	पूर्णांक r;

	जर ((b = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, रिक्त, 0)) != 0) /* reserved */
		जा out;
	साठी (i = 0; i < dch->nkeys; i++) {
		जर ((r = sshkey_puts(dch->किल्ल्या[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->किल्ली_is_ca[i] != 0)) != 0)
			जा out;
	}
	जर ((r = sshbuf_put_stringb(m, b)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	परत r;
}

स्थिर पूर्णांक
encode_dest_constraint(संरचना sshbuf *m, स्थिरांक संरचना dest_constraint *dc)
{
	संरचना sshbuf *b;
	पूर्णांक r;

	जर ((b = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, रिक्त, 0)) != 0) /* reserved */
		जा out;
	जर ((r = sshbuf_put_stringb(m, b)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	परत r;
}

स्थिर पूर्णांक
encode_constraints(संरचना sshbuf *m, u_int life, u_int confirm,
    स्थिरांक अक्षर *provider,
    संरचना dest_constraint **dest_constraints, माप_प्रकार ndest_constraints,
    पूर्णांक cert_only, संरचना sshkey **certs, माप_प्रकार ncerts)
{
	पूर्णांक r;
	संरचना sshbuf *b = रिक्त;
	माप_प्रकार i;

	जर (life != 0) {
		जर ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			जा out;
	}
	जर (confirm != 0) {
		जर ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			जा out;
	}
	जर (provider != रिक्त) {
		जर ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			जा out;
	}
	जर (dest_constraints != रिक्त && ndest_constraints > 0) {
		जर ((b = sshbuf_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		साठी (i = 0; i < ndest_constraints; i++) {
			जर ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				जा out;
		}
		जर ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			जा out;
		sshbuf_free(b);
		b = रिक्त;
	}
	जर (ncerts != 0) {
		जर ((b = sshbuf_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		साठी (i = 0; i < ncerts; i++) {
			जर ((r = sshkey_puts(certs[i], b)) != 0)
				जा out;
		}
		जर ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			जा out;
		sshbuf_free(b);
		b = रिक्त;
	}
	r = 0;
 out:
	sshbuf_free(b);
	परत r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णांक
ssh_add_identity_constrained(पूर्णांक sock, संरचना sshkey *किल्ली,
    स्थिरांक अक्षर *comment, u_int life, u_int confirm,
    स्थिरांक अक्षर *provider, संरचना dest_constraint **dest_constraints,
    माप_प्रकार ndest_constraints)
{
	संरचना sshbuf *संदेश;
	पूर्णांक r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;

	निवड (किल्ली->type) {
#ifdef WITH_OPENSSL
	स्थिती किल्ली_RSA:
	स्थिती किल्ली_RSA_CERT:
	स्थिती किल्ली_ECDSA:
	स्थिती किल्ली_ECDSA_CERT:
	स्थिती किल्ली_ECDSA_SK:
	स्थिती किल्ली_ECDSA_SK_CERT:
#endif
	स्थिती किल्ली_ED25519:
	स्थिती किल्ली_ED25519_CERT:
	स्थिती किल्ली_MLDSA44_ED25519:
	स्थिती किल्ली_MLDSA44_ED25519_CERT:
	स्थिती किल्ली_ED25519_SK:
	स्थिती किल्ली_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		जर ((r = sshbuf_put_u8(संदेश, type)) != 0 ||
		    (r = sshkey_private_serialize(किल्ली, संदेश)) != 0 ||
		    (r = sshbuf_put_cstring(संदेश, comment)) != 0)
			जा out;
		थांबा;
	पूर्वनिर्धारित:
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	जर (constrained &&
	    (r = encode_constraints(संदेश, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, रिक्त, 0)) != 0)
		जा out;
	जर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	परत r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णांक
ssh_remove_identity(पूर्णांक sock, स्थिरांक संरचना sshkey *किल्ली)
{
	संरचना sshbuf *संदेश;
	पूर्णांक r;
	u_char *blob = रिक्त;
	माप_प्रकार blen;

	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;

	जर (किल्ली->type != किल्ली_UNSPEC) {
		जर ((r = sshkey_to_blob(किल्ली, &blob, &blen)) != 0)
			जा out;
		जर ((r = sshbuf_put_u8(संदेश,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(संदेश, blob, blen)) != 0)
			जा out;
	} अन्यथा {
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	जर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	जर (blob != रिक्त)
		freezero(blob, blen);
	sshbuf_free(संदेश);
	परत r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णांक
ssh_update_card(पूर्णांक sock, पूर्णांक add, स्थिरांक अक्षर *reader_id, स्थिरांक अक्षर *pin,
    u_int life, u_int confirm,
    संरचना dest_constraint **dest_constraints, माप_प्रकार ndest_constraints,
    पूर्णांक cert_only, संरचना sshkey **certs, माप_प्रकार ncerts)
{
	संरचना sshbuf *संदेश;
	पूर्णांक r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	जर (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_किल्ली_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_किल्ली;
	} अन्यथा
		type = SSH_AGENTC_REMOVE_SMARTCARD_किल्ली;

	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u8(संदेश, type)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, pin)) != 0)
		जा out;
	जर (constrained &&
	    (r = encode_constraints(संदेश, life, confirm, रिक्त,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		जा out;
	जर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	परत r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
पूर्णांक
ssh_remove_all_identities(पूर्णांक sock, पूर्णांक version)
{
	संरचना sshbuf *संदेश;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	पूर्णांक r;

	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u8(संदेश, type)) != 0)
		जा out;
	जर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	परत r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
पूर्णांक
ssh_agent_bind_hostkey(पूर्णांक sock, स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक संरचना sshbuf *session_id, स्थिरांक संरचना sshbuf *signature,
    पूर्णांक forwarding)
{
	संरचना sshbuf *संदेश;
	पूर्णांक r;

	जर (किल्ली == रिक्त || session_id == रिक्त || signature == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u8(संदेश, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(किल्ली, संदेश)) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, signature)) != 0 ||
	    (r = sshbuf_put_u8(संदेश, forwarding ? 1 : 0)) != 0)
		जा out;
	जर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	परत r;
}

/* Queries supported extension request types */
पूर्णांक
ssh_agent_query_extensions(पूर्णांक sock, अक्षर ***exts)
{
	संरचना sshbuf *संदेश;
	पूर्णांक r;
	u_char type;
	अक्षर *cp = रिक्त, **ret = रिक्त;
	माप_प्रकार i = 0;

	*exts = रिक्त;
	जर ((संदेश = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u8(संदेश, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "query")) != 0)
		जा out;
	जर ((r = ssh_request_reply(sock, संदेश, संदेश)) != 0)
		जा out;
	जर ((r = sshbuf_get_u8(संदेश, &type)) != 0)
		जा out;
	जर (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		जा out;
	}
	/* Reply should start with "query" */
	जर (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(संदेश, &cp, रिक्त)) != 0 ||
	   म_भेद(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	ret = xcalloc(1, आकार(*ret));
	पर्यंत (sshbuf_len(संदेश)) {
		ret = xrecallocarray(ret, i + 1, i + 2, आकार(*ret));
		जर ((r = sshbuf_get_cstring(संदेश, ret + i, रिक्त)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = रिक्त; /* transferred */
 out:
	मुक्त(cp);
	stringlist_free(ret);
	sshbuf_free(संदेश);
	परत r;
}
