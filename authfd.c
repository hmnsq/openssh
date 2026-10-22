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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/un.h>
#شامل <sys/socket.h>

#شامل <fcntl.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>
#شامل <errno.h>

#شامل "ssh.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "authfd.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "atomicio.h"
#شامل "ssherr.h"
#شامل "xmalloc.h"

#define MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#define MAX_AGENT_REPLY_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#define agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
ایستا صحیح
decode_reply(u_char type)
{
	اگر (agent_failed(type))
		بازگشت SSH_ERR_AGENT_FAILURE;
	وگرنه اگر (type == SSH_AGENT_SUCCESS)
		بازگشت 0;
	وگرنه
		بازگشت SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
صحیح
ssh_get_authentication_socket_path(ثابت نویسه *authsocket, صحیح *fdp)
{
	صحیح sock, oerrno;
	ساختار sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, اندازه(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, اندازه(sunaddr.sun_path));

	اگر ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		بازگشت SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	اگر (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (ساختار sockaddr *)&sunaddr, اندازه(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}
	اگر (fdp != پوچ)
		*fdp = sock;
	وگرنه
		close(sock);
	بازگشت 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
صحیح
ssh_get_authentication_socket(صحیح *fdp)
{
	ثابت نویسه *authsocket;

	اگر (fdp != پوچ)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	اگر (authsocket == پوچ || *authsocket == '\0')
		بازگشت SSH_ERR_AGENT_NOT_PRESENT;

	بازگشت ssh_get_authentication_socket_path(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
ایستا صحیح
ssh_request_reply(صحیح sock, ساختار sshbuf *request, ساختار sshbuf *reply)
{
	صحیح r;
	size_t l, len;
	نویسه buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	اگر (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		بازگشت SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	اگر (atomicio(اقرأ, sock, buf, 4) != 4)
	    بازگشت SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	اگر (len > MAX_AGENT_REPLY_LEN)
		بازگشت SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(reply);
	وقتی (len > 0) {
		l = len;
		اگر (l > اندازه(buf))
			l = اندازه(buf);
		اگر (atomicio(اقرأ, sock, buf, l) != l)
			بازگشت SSH_ERR_AGENT_COMMUNICATION;
		اگر ((r = sshbuf_put(reply, buf, l)) != 0)
			بازگشت r;
		len -= l;
	}
	بازگشت 0;
}

/* Communicate with agent: sent request, read and decode status reply */
ایستا صحیح
ssh_request_reply_decode(صحیح sock, ساختار sshbuf *request)
{
	ساختار sshbuf *reply;
	صحیح r;
	u_char type;

	اگر ((reply = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = ssh_request_reply(sock, request, reply)) != 0 ||
	    (r = sshbuf_get_u8(reply, &type)) != 0 ||
	    (r = decode_reply(type)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(reply);
	بازگشت r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
تهی
ssh_close_authentication_socket(صحیح sock)
{
	اگر (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != پوچ)
		close(sock);
}

/* Lock/unlock agent */
صحیح
ssh_lock_agent(صحیح sock, صحیح lock, ثابت نویسه *password)
{
	صحیح r;
	u_char type = lock ? SSH_AGENTC_LOCK : SSH_AGENTC_UNLOCK;
	ساختار sshbuf *پیام;

	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیام, type)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, password)) != 0 ||
	    (r = ssh_request_reply_decode(sock, پیام)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(پیام);
	بازگشت r;
}


ایستا صحیح
deserialise_identity2(ساختار sshbuf *ids, ساختار sshkey **keyp, نویسه **commentp)
{
	صحیح r;
	نویسه *comment = پوچ;
	ثابت u_char *blob;
	size_t blen;

	اگر ((r = sshbuf_get_string_direct(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, پوچ)) != 0)
		برو out;
	اگر ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		برو out;
	اگر (commentp != پوچ) {
		*commentp = comment;
		comment = پوچ;
	}
	r = 0;
 out:
	آزاد(comment);
	بازگشت r;
}

/*
 * Fetch list of identities held by the agent.
 */
صحیح
ssh_fetch_identitylist(صحیح sock, ساختار ssh_identitylist **idlp)
{
	u_char type;
	uint32_t رقم, i;
	ساختار sshbuf *پیام;
	ساختار ssh_identitylist *idl = پوچ;
	صحیح r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیام, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		برو out;

	اگر ((r = ssh_request_reply(sock, پیام, پیام)) != 0)
		برو out;

	/* Get message type, and verify that we got a proper answer. */
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0)
		برو out;
	اگر (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		برو out;
	} وگرنه اگر (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	/* Get the number of entries in the response and check it for sanity. */
	اگر ((r = sshbuf_get_u32(پیام, &رقم)) != 0)
		برو out;
	اگر (رقم > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (رقم == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		برو out;
	}

	/* Deserialise the response into a list of keys/comments */
	اگر ((idl = calloc(1, اندازه(*idl))) == پوچ ||
	    (idl->کلیدها = calloc(رقم, اندازه(*idl->کلیدها))) == پوچ ||
	    (idl->comments = calloc(رقم, اندازه(*idl->comments))) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	برای (i = 0; i < رقم;) {
		اگر ((r = deserialise_identity2(پیام, &(idl->کلیدها[i]),
		    &(idl->comments[i]))) != 0) {
			اگر (r == SSH_ERR_کلید_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				رقم--;
				ادامه;
			} وگرنه
				برو out;
		}
		i++;
	}
	idl->nkeys = رقم;
	*idlp = idl;
	idl = پوچ;
	r = 0;
 out:
	sshbuf_free(پیام);
	اگر (idl != پوچ)
		ssh_free_identitylist(idl);
	بازگشت r;
}

تهی
ssh_free_identitylist(ساختار ssh_identitylist *idl)
{
	size_t i;

	اگر (idl == پوچ)
		بازگشت;
	برای (i = 0; i < idl->nkeys; i++) {
		اگر (idl->کلیدها != پوچ)
			sshkey_free(idl->کلیدها[i]);
		اگر (idl->comments != پوچ)
			آزاد(idl->comments[i]);
	}
	آزاد(idl->کلیدها);
	آزاد(idl->comments);
	آزاد(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
صحیح
ssh_agent_has_کلید(صحیح sock, ثابت ساختار sshkey *کلید)
{
	صحیح r, ret = SSH_ERR_کلید_NOT_FOUND;
	size_t i;
	ساختار ssh_identitylist *idlist = پوچ;

	اگر ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		بازگشت r;
	}

	برای (i = 0; i < idlist->nkeys; i++) {
		اگر (sshkey_equal_public(idlist->کلیدها[i], کلید)) {
			ret = 0;
			بشکن;
		}
	}

	ssh_free_identitylist(idlist);
	بازگشت ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
ایستا u_int
agent_encode_alg(ثابت ساختار sshkey *کلید, ثابت نویسه *alg)
{
	اگر (alg != پوچ && sshkey_type_plain(کلید->type) == کلید_RSA) {
		اگر (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			بازگشت SSH_AGENT_RSA_SHA2_256;
		اگر (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			بازگشت SSH_AGENT_RSA_SHA2_512;
	}
	بازگشت 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
صحیح
ssh_agent_sign(صحیح sock, ثابت ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen, ثابت نویسه *alg, u_int compat)
{
	ساختار sshbuf *پیام;
	u_char *sig = پوچ, type = 0;
	size_t len = 0;
	u_int flags = 0;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	*sigp = پوچ;
	*lenp = 0;

	اگر (datalen > SSH_کلید_MAX_SIGN_DATA_SIZE)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(کلید, alg);
	اگر ((r = sshbuf_put_u8(پیام, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(کلید, پیام)) != 0 ||
	    (r = sshbuf_put_string(پیام, data, datalen)) != 0 ||
	    (r = sshbuf_put_u32(پیام, flags)) != 0)
		برو out;
	اگر ((r = ssh_request_reply(sock, پیام, پیام)) != 0)
		برو out;
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0)
		برو out;
	اگر (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		برو out;
	} وگرنه اگر (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((r = sshbuf_get_string(پیام, &sig, &len)) != 0)
		برو out;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	اگر (!sshkey_is_sk(کلید) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		برو out;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = پوچ;
	len = 0;
	r = 0;
 out:
	freezero(sig, len);
	sshbuf_free(پیام);
	بازگشت r;
}

/* Encode key for a message to the agent. */

ایستا صحیح
encode_dest_constraint_hop(ساختار sshbuf *m,
    ثابت ساختار dest_constraint_hop *dch)
{
	ساختار sshbuf *b;
	u_int i;
	صحیح r;

	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, پوچ, 0)) != 0) /* reserved */
		برو out;
	برای (i = 0; i < dch->nkeys; i++) {
		اگر ((r = sshkey_puts(dch->کلیدها[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->کلید_is_ca[i] != 0)) != 0)
			برو out;
	}
	اگر ((r = sshbuf_put_stringb(m, b)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

ایستا صحیح
encode_dest_constraint(ساختار sshbuf *m, ثابت ساختار dest_constraint *dc)
{
	ساختار sshbuf *b;
	صحیح r;

	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->to)) != 0 ||
	    (r = sshbuf_put_string(b, پوچ, 0)) != 0) /* reserved */
		برو out;
	اگر ((r = sshbuf_put_stringb(m, b)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

ایستا صحیح
encode_constraints(ساختار sshbuf *m, u_int life, u_int confirm,
    ثابت نویسه *provider,
    ساختار dest_constraint **dest_constraints, size_t ndest_constraints,
    صحیح cert_only, ساختار sshkey **certs, size_t ncerts)
{
	صحیح r;
	ساختار sshbuf *b = پوچ;
	size_t i;

	اگر (life != 0) {
		اگر ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			برو out;
	}
	اگر (confirm != 0) {
		اگر ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			برو out;
	}
	اگر (provider != پوچ) {
		اگر ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			برو out;
	}
	اگر (dest_constraints != پوچ && ndest_constraints > 0) {
		اگر ((b = sshbuf_new()) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		برای (i = 0; i < ndest_constraints; i++) {
			اگر ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				برو out;
		}
		اگر ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			برو out;
		sshbuf_free(b);
		b = پوچ;
	}
	اگر (ncerts != 0) {
		اگر ((b = sshbuf_new()) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		برای (i = 0; i < ncerts; i++) {
			اگر ((r = sshkey_puts(certs[i], b)) != 0)
				برو out;
		}
		اگر ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			برو out;
		sshbuf_free(b);
		b = پوچ;
	}
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحیح
ssh_add_identity_constrained(صحیح sock, ساختار sshkey *کلید,
    ثابت نویسه *comment, u_int life, u_int confirm,
    ثابت نویسه *provider, ساختار dest_constraint **dest_constraints,
    size_t ndest_constraints)
{
	ساختار sshbuf *پیام;
	صحیح r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	انتخاب (کلید->type) {
#ifdef WITH_OPENSSL
	حالت کلید_RSA:
	حالت کلید_RSA_CERT:
	حالت کلید_ECDSA:
	حالت کلید_ECDSA_CERT:
	حالت کلید_ECDSA_SK:
	حالت کلید_ECDSA_SK_CERT:
#endif
	حالت کلید_ED25519:
	حالت کلید_ED25519_CERT:
	حالت کلید_MLDSA44_ED25519:
	حالت کلید_MLDSA44_ED25519_CERT:
	حالت کلید_ED25519_SK:
	حالت کلید_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_ADD_ID_CONSTRAINED :
		    SSH2_AGENTC_ADD_IDENTITY;
		اگر ((r = sshbuf_put_u8(پیام, type)) != 0 ||
		    (r = sshkey_private_serialize(کلید, پیام)) != 0 ||
		    (r = sshbuf_put_cstring(پیام, comment)) != 0)
			برو out;
		بشکن;
	پیشفرض:
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (constrained &&
	    (r = encode_constraints(پیام, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, پوچ, 0)) != 0)
		برو out;
	اگر ((r = ssh_request_reply_decode(sock, پیام)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(پیام);
	بازگشت r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحیح
ssh_remove_identity(صحیح sock, ثابت ساختار sshkey *کلید)
{
	ساختار sshbuf *پیام;
	صحیح r;
	u_char *blob = پوچ;
	size_t blen;

	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	اگر (کلید->type != کلید_UNSPEC) {
		اگر ((r = sshkey_to_blob(کلید, &blob, &blen)) != 0)
			برو out;
		اگر ((r = sshbuf_put_u8(پیام,
		    SSH2_AGENTC_REMOVE_IDENTITY)) != 0 ||
		    (r = sshbuf_put_string(پیام, blob, blen)) != 0)
			برو out;
	} وگرنه {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر ((r = ssh_request_reply_decode(sock, پیام)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	اگر (blob != پوچ)
		freezero(blob, blen);
	sshbuf_free(پیام);
	بازگشت r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحیح
ssh_update_card(صحیح sock, صحیح add, ثابت نویسه *reader_id, ثابت نویسه *pin,
    u_int life, u_int confirm,
    ساختار dest_constraint **dest_constraints, size_t ndest_constraints,
    صحیح cert_only, ساختار sshkey **certs, size_t ncerts)
{
	ساختار sshbuf *پیام;
	صحیح r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	اگر (add) {
		type = constrained ?
		    SSH_AGENTC_ADD_SMARTCARD_کلید_CONSTRAINED :
		    SSH_AGENTC_ADD_SMARTCARD_کلید;
	} وگرنه
		type = SSH_AGENTC_REMOVE_SMARTCARD_کلید;

	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیام, type)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, pin)) != 0)
		برو out;
	اگر (constrained &&
	    (r = encode_constraints(پیام, life, confirm, پوچ,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		برو out;
	اگر ((r = ssh_request_reply_decode(sock, پیام)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(پیام);
	بازگشت r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
صحیح
ssh_remove_all_identities(صحیح sock, صحیح version)
{
	ساختار sshbuf *پیام;
	u_char type = (version == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	صحیح r;

	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیام, type)) != 0)
		برو out;
	اگر ((r = ssh_request_reply_decode(sock, پیام)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(پیام);
	بازگشت r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
صحیح
ssh_agent_bind_hostkey(صحیح sock, ثابت ساختار sshkey *کلید,
    ثابت ساختار sshbuf *session_id, ثابت ساختار sshbuf *signature,
    صحیح forwarding)
{
	ساختار sshbuf *پیام;
	صحیح r;

	اگر (کلید == پوچ || session_id == پوچ || signature == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیام, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(کلید, پیام)) != 0 ||
	    (r = sshbuf_put_stringb(پیام, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(پیام, signature)) != 0 ||
	    (r = sshbuf_put_u8(پیام, forwarding ? 1 : 0)) != 0)
		برو out;
	اگر ((r = ssh_request_reply_decode(sock, پیام)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(پیام);
	بازگشت r;
}

/* Queries supported extension request types */
صحیح
ssh_agent_query_extensions(صحیح sock, نویسه ***exts)
{
	ساختار sshbuf *پیام;
	صحیح r;
	u_char type;
	نویسه *cp = پوچ, **ret = پوچ;
	size_t i = 0;

	*exts = پوچ;
	اگر ((پیام = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیام, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "query")) != 0)
		برو out;
	اگر ((r = ssh_request_reply(sock, پیام, پیام)) != 0)
		برو out;
	اگر ((r = sshbuf_get_u8(پیام, &type)) != 0)
		برو out;
	اگر (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		برو out;
	}
	/* Reply should start with "query" */
	اگر (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(پیام, &cp, پوچ)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	ret = xcalloc(1, اندازه(*ret));
	وقتی (sshbuf_len(پیام)) {
		ret = xrecallocarray(ret, i + 1, i + 2, اندازه(*ret));
		اگر ((r = sshbuf_get_cstring(پیام, ret + i, پوچ)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = پوچ; /* transferred */
 out:
	آزاد(cp);
	stringlist_free(ret);
	sshbuf_free(پیام);
	بازگشت r;
}
