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

#تعریف_کرو MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#تعریف_کرو MAX_AGENT_جواب_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#تعریف_کرو agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
ساکن صحیح
decode_جواب(u_char type)
{
	اگر (agent_failed(type))
		واپس SSH_ERR_AGENT_FAILURE;
	ورنہ اگر (type == SSH_AGENT_SUCCESS)
		واپس 0;
	ورنہ
		واپس SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
صحیح
ssh_get_authentication_socket_راستہ(ثابت حرف *authsocket, صحیح *fdp)
{
	صحیح sock, oerrno;
	ساخت sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_راستہ, authsocket, حجم(sunaddr.sun_راستہ));

	اگر ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		واپس SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	اگر (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (ساخت sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	}
	اگر (fdp != تہی)
		*fdp = sock;
	ورنہ
		close(sock);
	واپس 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
صحیح
ssh_get_authentication_socket(صحیح *fdp)
{
	ثابت حرف *authsocket;

	اگر (fdp != تہی)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	اگر (authsocket == تہی || *authsocket == '\0')
		واپس SSH_ERR_AGENT_NOT_PRESENT;

	واپس ssh_get_authentication_socket_راستہ(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
ساکن صحیح
ssh_request_جواب(صحیح sock, ساخت sshbuf *request, ساخت sshbuf *جواب)
{
	صحیح r;
	سائز_t l, len;
	حرف buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	اگر (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		واپس SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	اگر (atomicio(اقرأ, sock, buf, 4) != 4)
	    واپس SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	اگر (len > MAX_AGENT_جواب_LEN)
		واپس SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(جواب);
	جب (len > 0) {
		l = len;
		اگر (l > حجم(buf))
			l = حجم(buf);
		اگر (atomicio(اقرأ, sock, buf, l) != l)
			واپس SSH_ERR_AGENT_COMMUNICATION;
		اگر ((r = sshbuf_put(جواب, buf, l)) != 0)
			واپس r;
		len -= l;
	}
	واپس 0;
}

/* Communicate with agent: sent request, read and decode status reply */
ساکن صحیح
ssh_request_جواب_decode(صحیح sock, ساخت sshbuf *request)
{
	ساخت sshbuf *جواب;
	صحیح r;
	u_char type;

	اگر ((جواب = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = ssh_request_جواب(sock, request, جواب)) != 0 ||
	    (r = sshbuf_get_u8(جواب, &type)) != 0 ||
	    (r = decode_جواب(type)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(جواب);
	واپس r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
خالی
ssh_close_authentication_socket(صحیح sock)
{
	اگر (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != تہی)
		close(sock);
}

/* Lock/unlock agent */
صحیح
ssh_تالا_agent(صحیح sock, صحیح تالا, ثابت حرف *password)
{
	صحیح r;
	u_char type = تالا ? SSH_AGENTC_تالا : SSH_AGENTC_UNLOCK;
	ساخت sshbuf *پیغام;

	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیغام, type)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, password)) != 0 ||
	    (r = ssh_request_جواب_decode(sock, پیغام)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(پیغام);
	واپس r;
}


ساکن صحیح
deserialise_identity2(ساخت sshbuf *ids, ساخت sshkey **keyp, حرف **commentp)
{
	صحیح r;
	حرف *comment = تہی;
	ثابت u_char *blob;
	سائز_t blen;

	اگر ((r = sshbuf_get_string_براہ_راست(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, تہی)) != 0)
		جاؤ برآمد;
	اگر ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		جاؤ برآمد;
	اگر (commentp != تہی) {
		*commentp = comment;
		comment = تہی;
	}
	r = 0;
 برآمد:
	آزاد(comment);
	واپس r;
}

/*
 * Fetch list of identities held by the agent.
 */
صحیح
ssh_fetch_identitylist(صحیح sock, ساخت ssh_identitylist **idlp)
{
	u_char type;
	uint32_t عدد, i;
	ساخت sshbuf *پیغام;
	ساخت ssh_identitylist *idl = تہی;
	صحیح r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		جاؤ برآمد;

	اگر ((r = ssh_request_جواب(sock, پیغام, پیغام)) != 0)
		جاؤ برآمد;

	/* Get message type, and verify that we got a proper answer. */
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0)
		جاؤ برآمد;
	اگر (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		جاؤ برآمد;
	} ورنہ اگر (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* Get the number of entries in the response and check it for sanity. */
	اگر ((r = sshbuf_get_u32(پیغام, &عدد)) != 0)
		جاؤ برآمد;
	اگر (عدد > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (عدد == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		جاؤ برآمد;
	}

	/* Deserialise the response into a list of keys/comments */
	اگر ((idl = صفر_حافظہ_دو(1, حجم(*idl))) == تہی ||
	    (idl->کلیدیں = صفر_حافظہ_دو(عدد, حجم(*idl->کلیدیں))) == تہی ||
	    (idl->comments = صفر_حافظہ_دو(عدد, حجم(*idl->comments))) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	برائے (i = 0; i < عدد;) {
		اگر ((r = deserialise_identity2(پیغام, &(idl->کلیدیں[i]),
		    &(idl->comments[i]))) != 0) {
			اگر (r == SSH_ERR_کلید_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				عدد--;
				جاری;
			} ورنہ
				جاؤ برآمد;
		}
		i++;
	}
	idl->nkeys = عدد;
	*idlp = idl;
	idl = تہی;
	r = 0;
 برآمد:
	sshbuf_free(پیغام);
	اگر (idl != تہی)
		ssh_free_identitylist(idl);
	واپس r;
}

خالی
ssh_free_identitylist(ساخت ssh_identitylist *idl)
{
	سائز_t i;

	اگر (idl == تہی)
		واپس;
	برائے (i = 0; i < idl->nkeys; i++) {
		اگر (idl->کلیدیں != تہی)
			sshkey_free(idl->کلیدیں[i]);
		اگر (idl->comments != تہی)
			آزاد(idl->comments[i]);
	}
	آزاد(idl->کلیدیں);
	آزاد(idl->comments);
	آزاد(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
صحیح
ssh_agent_has_کلید(صحیح sock, ثابت ساخت sshkey *کلید)
{
	صحیح r, ret = SSH_ERR_کلید_NOT_ملا;
	سائز_t i;
	ساخت ssh_identitylist *idlist = تہی;

	اگر ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		واپس r;
	}

	برائے (i = 0; i < idlist->nkeys; i++) {
		اگر (sshkey_equal_عوامی(idlist->کلیدیں[i], کلید)) {
			ret = 0;
			توڑو;
		}
	}

	ssh_free_identitylist(idlist);
	واپس ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
ساکن u_int
agent_encode_alg(ثابت ساخت sshkey *کلید, ثابت حرف *alg)
{
	اگر (alg != تہی && sshkey_type_plain(کلید->type) == کلید_RSA) {
		اگر (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			واپس SSH_AGENT_RSA_SHA2_256;
		اگر (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			واپس SSH_AGENT_RSA_SHA2_512;
	}
	واپس 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
صحیح
ssh_agent_sign(صحیح sock, ثابت ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen, ثابت حرف *alg, u_int compat)
{
	ساخت sshbuf *پیغام;
	u_char *sig = تہی, type = 0;
	سائز_t len = 0;
	u_int flags = 0;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	*sigp = تہی;
	*lenp = 0;

	اگر (datalen > SSH_کلید_MAX_SIGN_ڈیٹا_سائز)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(کلید, alg);
	اگر ((r = sshbuf_put_u8(پیغام, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(کلید, پیغام)) != 0 ||
	    (r = sshbuf_put_string(پیغام, ڈیٹا, datalen)) != 0 ||
	    (r = sshbuf_put_u32(پیغام, flags)) != 0)
		جاؤ برآمد;
	اگر ((r = ssh_request_جواب(sock, پیغام, پیغام)) != 0)
		جاؤ برآمد;
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0)
		جاؤ برآمد;
	اگر (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		جاؤ برآمد;
	} ورنہ اگر (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_string(پیغام, &sig, &len)) != 0)
		جاؤ برآمد;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	اگر (!sshkey_is_sk(کلید) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		جاؤ برآمد;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = تہی;
	len = 0;
	r = 0;
 برآمد:
	freezero(sig, len);
	sshbuf_free(پیغام);
	واپس r;
}

/* Encode key for a message to the agent. */

ساکن صحیح
encode_dest_constraint_hop(ساخت sshbuf *m,
    ثابت ساخت dest_constraint_hop *dch)
{
	ساخت sshbuf *b;
	u_int i;
	صحیح r;

	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, تہی, 0)) != 0) /* reserved */
		جاؤ برآمد;
	برائے (i = 0; i < dch->nkeys; i++) {
		اگر ((r = sshkey_puts(dch->کلیدیں[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->کلید_is_ca[i] != 0)) != 0)
			جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_stringb(m, b)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	واپس r;
}

ساکن صحیح
encode_dest_constraint(ساخت sshbuf *m, ثابت ساخت dest_constraint *dc)
{
	ساخت sshbuf *b;
	صحیح r;

	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->مقصد)) != 0 ||
	    (r = sshbuf_put_string(b, تہی, 0)) != 0) /* reserved */
		جاؤ برآمد;
	اگر ((r = sshbuf_put_stringb(m, b)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	واپس r;
}

ساکن صحیح
encode_constraints(ساخت sshbuf *m, u_int life, u_int confirm,
    ثابت حرف *provider,
    ساخت dest_constraint **dest_constraints, سائز_t ndest_constraints,
    صحیح cert_only, ساخت sshkey **certs, سائز_t ncerts)
{
	صحیح r;
	ساخت sshbuf *b = تہی;
	سائز_t i;

	اگر (life != 0) {
		اگر ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			جاؤ برآمد;
	}
	اگر (confirm != 0) {
		اگر ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			جاؤ برآمد;
	}
	اگر (provider != تہی) {
		اگر ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			جاؤ برآمد;
	}
	اگر (dest_constraints != تہی && ndest_constraints > 0) {
		اگر ((b = sshbuf_new()) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		برائے (i = 0; i < ndest_constraints; i++) {
			اگر ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				جاؤ برآمد;
		}
		اگر ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			جاؤ برآمد;
		sshbuf_free(b);
		b = تہی;
	}
	اگر (ncerts != 0) {
		اگر ((b = sshbuf_new()) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		برائے (i = 0; i < ncerts; i++) {
			اگر ((r = sshkey_puts(certs[i], b)) != 0)
				جاؤ برآمد;
		}
		اگر ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			جاؤ برآمد;
		sshbuf_free(b);
		b = تہی;
	}
	r = 0;
 برآمد:
	sshbuf_free(b);
	واپس r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحیح
ssh_جوڑو_شناختی_عنصر_constrained(صحیح sock, ساخت sshkey *کلید,
    ثابت حرف *comment, u_int life, u_int confirm,
    ثابت حرف *provider, ساخت dest_constraint **dest_constraints,
    سائز_t ndest_constraints)
{
	ساخت sshbuf *پیغام;
	صحیح r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	انتخاب (کلید->type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت کلید_RSA:
	حالت کلید_RSA_CERT:
	حالت کلید_ECDSA:
	حالت کلید_ECDSA_CERT:
	حالت کلید_ECDSA_SK:
	حالت کلید_ECDSA_SK_CERT:
#اگر_ختم
	حالت کلید_ED25519:
	حالت کلید_ED25519_CERT:
	حالت کلید_MLDSA44_ED25519:
	حالت کلید_MLDSA44_ED25519_CERT:
	حالت کلید_ED25519_SK:
	حالت کلید_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_جوڑو_ID_CONSTRAINED :
		    SSH2_AGENTC_جوڑو_شناختی_عنصر;
		اگر ((r = sshbuf_put_u8(پیغام, type)) != 0 ||
		    (r = sshkey_نجی_serialize(کلید, پیغام)) != 0 ||
		    (r = sshbuf_put_cstring(پیغام, comment)) != 0)
			جاؤ برآمد;
		توڑو;
	طےشدہ:
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (constrained &&
	    (r = encode_constraints(پیغام, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, تہی, 0)) != 0)
		جاؤ برآمد;
	اگر ((r = ssh_request_جواب_decode(sock, پیغام)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(پیغام);
	واپس r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحیح
ssh_remove_شناختی_عنصر(صحیح sock, ثابت ساخت sshkey *کلید)
{
	ساخت sshbuf *پیغام;
	صحیح r;
	u_char *blob = تہی;
	سائز_t blen;

	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	اگر (کلید->type != کلید_UNSPEC) {
		اگر ((r = sshkey_مقصد_blob(کلید, &blob, &blen)) != 0)
			جاؤ برآمد;
		اگر ((r = sshbuf_put_u8(پیغام,
		    SSH2_AGENTC_REMOVE_شناختی_عنصر)) != 0 ||
		    (r = sshbuf_put_string(پیغام, blob, blen)) != 0)
			جاؤ برآمد;
	} ورنہ {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر ((r = ssh_request_جواب_decode(sock, پیغام)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	اگر (blob != تہی)
		freezero(blob, blen);
	sshbuf_free(پیغام);
	واپس r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحیح
ssh_update_card(صحیح sock, صحیح جوڑو, ثابت حرف *reader_id, ثابت حرف *pin,
    u_int life, u_int confirm,
    ساخت dest_constraint **dest_constraints, سائز_t ndest_constraints,
    صحیح cert_only, ساخت sshkey **certs, سائز_t ncerts)
{
	ساخت sshbuf *پیغام;
	صحیح r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	اگر (جوڑو) {
		type = constrained ?
		    SSH_AGENTC_جوڑو_SMARTCARD_کلید_CONSTRAINED :
		    SSH_AGENTC_جوڑو_SMARTCARD_کلید;
	} ورنہ
		type = SSH_AGENTC_REMOVE_SMARTCARD_کلید;

	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیغام, type)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, pin)) != 0)
		جاؤ برآمد;
	اگر (constrained &&
	    (r = encode_constraints(پیغام, life, confirm, تہی,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		جاؤ برآمد;
	اگر ((r = ssh_request_جواب_decode(sock, پیغام)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(پیغام);
	واپس r;
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
ssh_remove_all_identities(صحیح sock, صحیح نسخہ)
{
	ساخت sshbuf *پیغام;
	u_char type = (نسخہ == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	صحیح r;

	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیغام, type)) != 0)
		جاؤ برآمد;
	اگر ((r = ssh_request_جواب_decode(sock, پیغام)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(پیغام);
	واپس r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
صحیح
ssh_agent_bind_hostkey(صحیح sock, ثابت ساخت sshkey *کلید,
    ثابت ساخت sshbuf *session_id, ثابت ساخت sshbuf *signature,
    صحیح forwarding)
{
	ساخت sshbuf *پیغام;
	صحیح r;

	اگر (کلید == تہی || session_id == تہی || signature == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیغام, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(کلید, پیغام)) != 0 ||
	    (r = sshbuf_put_stringb(پیغام, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(پیغام, signature)) != 0 ||
	    (r = sshbuf_put_u8(پیغام, forwarding ? 1 : 0)) != 0)
		جاؤ برآمد;
	اگر ((r = ssh_request_جواب_decode(sock, پیغام)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(پیغام);
	واپس r;
}

/* Queries supported extension request types */
صحیح
ssh_agent_query_extensions(صحیح sock, حرف ***exts)
{
	ساخت sshbuf *پیغام;
	صحیح r;
	u_char type;
	حرف *cp = تہی, **ret = تہی;
	سائز_t i = 0;

	*exts = تہی;
	اگر ((پیغام = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u8(پیغام, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(پیغام, "query")) != 0)
		جاؤ برآمد;
	اگر ((r = ssh_request_جواب(sock, پیغام, پیغام)) != 0)
		جاؤ برآمد;
	اگر ((r = sshbuf_get_u8(پیغام, &type)) != 0)
		جاؤ برآمد;
	اگر (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		جاؤ برآمد;
	}
	/* Reply should start with "query" */
	اگر (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(پیغام, &cp, تہی)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	ret = xcalloc(1, حجم(*ret));
	جب (sshbuf_len(پیغام)) {
		ret = xrecallocarray(ret, i + 1, i + 2, حجم(*ret));
		اگر ((r = sshbuf_get_cstring(پیغام, ret + i, تہی)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = تہی; /* transferred */
 برآمد:
	آزاد(cp);
	stringlist_free(ret);
	sshbuf_free(پیغام);
	واپس r;
}
