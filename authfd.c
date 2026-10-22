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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/un.h>
#समावेश <sys/socket.h>

#समावेश <fcntl.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <unistd.h>
#समावेश <errno.h>

#समावेश "ssh.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "authfd.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "atomicio.h"
#समावेश "ssherr.h"
#समावेश "xmalloc.h"

#घोषणा MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#घोषणा MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#घोषणा agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
अटल पूर्णांक
decode_reply(u_char type)
{
	अगर (agent_failed(type))
		वापस SSH_ERR_AGENT_FAILURE;
	अन्यथा अगर (type == SSH_AGENT_SUCCESS)
		वापस 0;
	अन्यथा
		वापस SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
पूर्णांक
ssh_get_authentication_socket_path(स्थिर अक्षर *authsocket, पूर्णांक *fdp)
{
	पूर्णांक sock, oerrno;
	काष्ठा sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	स_रखो(&sunaddr, 0, माप(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, माप(sunaddr.sun_path));

	अगर ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		वापस SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	अगर (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (काष्ठा sockaddr *)&sunaddr, माप(sunaddr)) == -1) {
		oerrno = त्रुटि_सं;
		बंद(sock);
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	}
	अगर (fdp != शून्य)
		*fdp = sock;
	अन्यथा
		बंद(sock);
	वापस 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
पूर्णांक
ssh_get_authentication_socket(पूर्णांक *fdp)
{
	स्थिर अक्षर *authsocket;

	अगर (fdp != शून्य)
		*fdp = -1;

	authsocket = दो_पर्या(SSH_AUTHSOCKET_ENV_NAME);
	अगर (authsocket == शून्य || *authsocket == '\0')
		वापस SSH_ERR_AGENT_NOT_PRESENT;

	वापस ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
अटल पूर्णांक
ssh_request_reply(पूर्णांक sock, काष्ठा sshbuf *request, काष्ठा sshbuf *reply)
{
	पूर्णांक r;
	माप_प्रकार l, len;
	अक्षर buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	अगर (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		वापस SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	अगर (atomicio(पढ़ो, sock, buf, 4) != 4)
	    वापस SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	अगर (len > MAX_AGENT_REPLY_LEN)
		वापस SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	जबतक (len > 0) {
		l = len;
		अगर (l > माप(buf))
			l = माप(buf);
		अगर (atomicio(पढ़ो, sock, buf, l) != l)
			वापस SSH_ERR_AGENT_COMMUNICATION;
		अगर ((r = sshbuf_put(reply, buf, l)) != 0)
			वापस r;
		len -= l;
	}
	वापस 0;
}

/* Communicate with agent: sent request, read and decode status reply */
अटल पूर्णांक
ssh_request_reply_decode(पूर्णांक sock, काष्ठा sshbuf *request)
{
	काष्ठा sshbuf *reply;
	पूर्णांक r;
	u_char type;

	अगर ((reply = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	वापस r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
व्योम
ssh_close_authentication_socket(पूर्णांक sock)
{
	अगर (sock != -1 && दो_पर्या(SSH_AUTHSOCKET_ENV_NAME) != शून्य)
		बंद(sock);
}

/* Lock/unlock agent */
पूर्णांक
ssh_lock_agent(पूर्णांक sock, पूर्णांक lock, स्थिर अक्षर *password)
{
	पूर्णांक r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	काष्ठा sshbuf *संदेश;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u8(संदेश, type)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	वापस r;
}


अटल पूर्णांक
deserialise_identity2(काष्ठा sshbuf *ids, काष्ठा sshkey **keyp, अक्षर **commentp)
{
	पूर्णांक r;
	अक्षर *comment = शून्य;
	स्थिर u_char *blob;
	माप_प्रकार blen;

	अगर ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, शून्य)) != 0)
		जाओ out;
	अगर ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		जाओ out;
	अगर (commentp != शून्य) {
		*commentp = comment;
		comment = शून्य;
	}
	r = 0;
 out:
	मुक्त(comment);
	वापस r;
}

/*
 * Fetch list of identities held by the agent.
 */
पूर्णांक
ssh_fetch_identitylist(पूर्णांक sock, काष्ठा ssh_identitylist **idlp)
{
	u_char type;
	uint32_t अंक, i;
	काष्ठा sshbuf *संदेश;
	काष्ठा ssh_identitylist *idl = शून्य;
	पूर्णांक r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		जाओ out;

	अगर ((r = ssh_request_reply(sock, संदेश, संदेश)) != 0)
		जाओ out;

	/* Get message type, and verify that we got a proper answer. */
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0)
		जाओ out;
	अगर (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		जाओ out;
	} अन्यथा अगर (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	अगर ((r = sshbuf_get_u32(संदेश, &अंक)) != 0)
		जाओ out;
	अगर (अंक > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (अंक == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		जाओ out;
	}

	/* Deserialise the response into a list of keys/comments */
	अगर ((idl = सुस्मृति(1, माप(*idl))) == शून्य ||
	    (idl->कुंजियाँ = सुस्मृति(अंक, माप(*idl->कुंजियाँ))) == शून्य ||
	    (idl->comments = सुस्मृति(अंक, माप(*idl->comments))) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	क्रम (i = 0; i < अंक;) {
		अगर ((r = deserialise_identity2(संदेश, &(idl->कुंजियाँ[i]),
		    &(idl->comments[i]))) != 0) {
			अगर (r == SSH_ERR_कुंजी_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				अंक--;
				जारी;
			} अन्यथा
				जाओ out;
		}
		i++;
	}
	idl->nkeys = अंक;
	*idlp = idl;
	idl = शून्य;
	r = 0;
 out:
	sshbuf_free(संदेश);
	अगर (idl != शून्य)
		ssh_free_identitylist(idl);
	वापस r;
}

व्योम
ssh_free_identitylist(काष्ठा ssh_identitylist *idl)
{
	माप_प्रकार i;

	अगर (idl == शून्य)
		वापस;
	क्रम (i = 0; i < idl->nkeys; i++) {
		अगर (idl->कुंजियाँ != शून्य)
			sshkey_free(idl->कुंजियाँ[i]);
		अगर (idl->comments != शून्य)
			मुक्त(idl->comments[i]);
	}
	मुक्त(idl->कुंजियाँ);
	मुक्त(idl->comments);
	मुक्त(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक
ssh_agent_has_कुंजी(पूर्णांक sock, स्थिर काष्ठा sshkey *कुंजी)
{
	पूर्णांक r, ret = SSH_ERR_कुंजी_NOT_FOUND;
	माप_प्रकार i;
	काष्ठा ssh_identitylist *idlist = शून्य;

	अगर ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		वापस r;
	}

	क्रम (i = 0; i < idlist->nkeys; i++) {
		अगर (sshkey_equal_public(idlist->कुंजियाँ[i], कुंजी)) {
			ret = 0;
			अवरोध;
		}
	}

	ssh_free_identitylist(idlist);
	वापस ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
अटल u_int
agent_encode_alg(स्थिर काष्ठा sshkey *कुंजी, स्थिर अक्षर *alg)
{
	अगर (alg != शून्य && sshkey_type_plain(कुंजी->type) == कुंजी_RSA) {
		अगर (म_भेद(alg, "rsa-sha2-256") == 0 ||
		    म_भेद(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			वापस SSH_AGENT_RSA_SHA2_256;
		अगर (म_भेद(alg, "rsa-sha2-512") == 0 ||
		    म_भेद(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			वापस SSH_AGENT_RSA_SHA2_512;
	}
	वापस 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
पूर्णांक
ssh_agent_sign(पूर्णांक sock, स्थिर काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen, स्थिर अक्षर *alg, u_int compat)
{
	काष्ठा sshbuf *संदेश;
	u_char *sig = शून्य, type = 0;
	माप_प्रकार len = 0;
	u_int flags = 0;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*sigp = शून्य;
	*lenp = 0;

	अगर (datalen > SSH_कुंजी_MAX_SIGN_तथ्य_आकार)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(कुंजी, alg);
	अगर ((r = sshbuf_put_u8(संदेश, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(कुंजी, संदेश)) != 0 ||
	    (r = sshbuf_put_string(संदेश, तथ्य, datalen)) != 0 ||
	    (r = sshbuf_put_u32(संदेश, flags)) != 0)
		जाओ out;
	अगर ((r = ssh_request_reply(sock, संदेश, संदेश)) != 0)
		जाओ out;
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0)
		जाओ out;
	अगर (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		जाओ out;
	} अन्यथा अगर (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((r = sshbuf_get_string(संदेश, &sig, &len)) != 0)
		जाओ out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	अगर (!sshkey_is_sk(कुंजी) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		जाओ out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = शून्य;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(संदेश);
	वापस r;
}

/* Encode key for a message to the agent. */

अटल पूर्णांक
encode_dest_constraint_hop(काष्ठा sshbuf *m,
    स्थिर काष्ठा dest_constraint_hop *dch)
{
	काष्ठा sshbuf *b;
	u_int i;
	पूर्णांक r;

	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, शून्य, 0)) != 0) /* reserved */
		जाओ out;
	क्रम (i = 0; i < dch->nkeys; i++) {
		अगर ((r = sshkey_puts(dch->कुंजियाँ[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->कुंजी_is_ca[i] != 0)) != 0)
			जाओ out;
	}
	अगर ((r = sshbuf_put_stringb(m, b)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

अटल पूर्णांक
encode_dest_constraint(काष्ठा sshbuf *m, स्थिर काष्ठा dest_constraint *dc)
{
	काष्ठा sshbuf *b;
	पूर्णांक r;

	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, शून्य, 0)) != 0) /* reserved */
		जाओ out;
	अगर ((r = sshbuf_put_stringb(m, b)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

अटल पूर्णांक
encode_constraints(काष्ठा sshbuf *m, u_int life, u_int confirm,
    स्थिर अक्षर *provider,
    काष्ठा dest_constraint **dest_constraints, माप_प्रकार ndest_constraints,
    पूर्णांक cert_only, काष्ठा sshkey **certs, माप_प्रकार ncerts)
{
	पूर्णांक r;
	काष्ठा sshbuf *b = शून्य;
	माप_प्रकार i;

	अगर (life != 0) {
		अगर ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			जाओ out;
	}
	अगर (confirm != 0) {
		अगर ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			जाओ out;
	}
	अगर (provider != शून्य) {
		अगर ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			जाओ out;
	}
	अगर (dest_constraints != शून्य && ndest_constraints > 0) {
		अगर ((b = sshbuf_new()) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		क्रम (i = 0; i < ndest_constraints; i++) {
			अगर ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				जाओ out;
		}
		अगर ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			जाओ out;
		sshbuf_free(b);
		b = शून्य;
	}
	अगर (ncerts != 0) {
		अगर ((b = sshbuf_new()) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		क्रम (i = 0; i < ncerts; i++) {
			अगर ((r = sshkey_puts(certs[i], b)) != 0)
				जाओ out;
		}
		अगर ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			जाओ out;
		sshbuf_free(b);
		b = शून्य;
	}
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णांक
ssh_add_identity_constrained(पूर्णांक sock, काष्ठा sshkey *कुंजी,
    स्थिर अक्षर *comment, u_int life, u_int confirm,
    स्थिर अक्षर *provider, काष्ठा dest_constraint **dest_constraints,
    माप_प्रकार ndest_constraints)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	चयन (कुंजी->type) {
#अगर_घोषित WITH_OPENSSL
	हाल कुंजी_RSA:
	हाल कुंजी_RSA_CERT:
	हाल कुंजी_ECDSA:
	हाल कुंजी_ECDSA_CERT:
	हाल कुंजी_ECDSA_SK:
	हाल कुंजी_ECDSA_SK_CERT:
#पूर्ण_अगर
	हाल कुंजी_ED25519:
	हाल कुंजी_ED25519_CERT:
	हाल कुंजी_MLDSA44_ED25519:
	हाल कुंजी_MLDSA44_ED25519_CERT:
	हाल कुंजी_ED25519_SK:
	हाल कुंजी_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		अगर ((r = sshbuf_put_u8(संदेश, type)) != 0 ||
		    (r = sshkey_private_serialize(कुंजी, संदेश)) != 0 ||
		    (r = sshbuf_put_cstring(संदेश, comment)) != 0)
			जाओ out;
		अवरोध;
	शेष:
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (constrained &&
	    (r = encode_constraints(संदेश, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, शून्य, 0)) != 0)
		जाओ out;
	अगर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	वापस r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णांक
ssh_remove_identity(पूर्णांक sock, स्थिर काष्ठा sshkey *कुंजी)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;
	u_char *blob = शून्य;
	माप_प्रकार blen;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	अगर (कुंजी->type != कुंजी_UNSPEC) {
		अगर ((r = sshkey_to_blob(कुंजी, &blob, &blen)) != 0)
			जाओ out;
		अगर ((r = sshbuf_put_u8(संदेश,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(संदेश, blob, blen)) != 0)
			जाओ out;
	} अन्यथा {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	अगर (blob != शून्य)
		freezero(blob, blen);
	sshbuf_free(संदेश);
	वापस r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
पूर्णांक
ssh_update_card(पूर्णांक sock, पूर्णांक add, स्थिर अक्षर *reader_id, स्थिर अक्षर *pin,
    u_int life, u_int confirm,
    काष्ठा dest_constraint **dest_constraints, माप_प्रकार ndest_constraints,
    पूर्णांक cert_only, काष्ठा sshkey **certs, माप_प्रकार ncerts)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	अगर (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_कुंजी_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_कुंजी;
	} अन्यथा
		type = SSH_AGENTC_REMOVE_SMARTCARD_कुंजी;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u8(संदेश, type)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, pin)) != 0)
		जाओ out;
	अगर (constrained &&
	    (r = encode_constraints(संदेश, life, confirm, शून्य,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		जाओ out;
	अगर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	वापस r;
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
	काष्ठा sshbuf *संदेश;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	पूर्णांक r;

	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u8(संदेश, type)) != 0)
		जाओ out;
	अगर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	वापस r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
पूर्णांक
ssh_agent_bind_hostkey(पूर्णांक sock, स्थिर काष्ठा sshkey *कुंजी,
    स्थिर काष्ठा sshbuf *session_id, स्थिर काष्ठा sshbuf *signature,
    पूर्णांक forwarding)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;

	अगर (कुंजी == शून्य || session_id == शून्य || signature == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u8(संदेश, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(कुंजी, संदेश)) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(संदेश, signature)) != 0 ||
	    (r = sshbuf_put_u8(संदेश, forwarding ? 1 : 0)) != 0)
		जाओ out;
	अगर ((r = ssh_request_reply_decode(sock, संदेश)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(संदेश);
	वापस r;
}

/* Queries supported extension request types */
पूर्णांक
ssh_agent_query_extensions(पूर्णांक sock, अक्षर ***exts)
{
	काष्ठा sshbuf *संदेश;
	पूर्णांक r;
	u_char type;
	अक्षर *cp = शून्य, **ret = शून्य;
	माप_प्रकार i = 0;

	*exts = शून्य;
	अगर ((संदेश = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u8(संदेश, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(संदेश, "query")) != 0)
		जाओ out;
	अगर ((r = ssh_request_reply(sock, संदेश, संदेश)) != 0)
		जाओ out;
	अगर ((r = sshbuf_get_u8(संदेश, &type)) != 0)
		जाओ out;
	अगर (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		जाओ out;
	}
	/* Reply should start with "query" */
	अगर (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(संदेश, &cp, शून्य)) != 0 ||
	   म_भेद(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	ret = xcalloc(1, माप(*ret));
	जबतक (sshbuf_len(संदेश)) {
		ret = xrecallocarray(ret, i + 1, i + 2, माप(*ret));
		अगर ((r = sshbuf_get_cstring(संदेश, ret + i, शून्य)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = शून्य; /* transferred */
 out:
	मुक्त(cp);
	stringlist_free(ret);
	sshbuf_free(संदेश);
	वापस r;
}
