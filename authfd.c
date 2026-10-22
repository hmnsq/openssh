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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/un.h>
#ضمن <sys/socket.h>

#ضمن <fcntl.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>
#ضمن <errno.h>

#ضمن "ssh.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "authfd.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "atomicio.h"
#ضمن "ssherr.h"
#ضمن "xmalloc.h"

#تعریف_کن MAX_AGENT_IDENTITIES	2048		/* Max keys in agent reply */
#تعریف_کن MAX_AGENT_پاسخ_LEN	(256 * 1024)	/* Max bytes in agent reply */

/* macro to check for "agent failure" message */
#تعریف_کن agent_failed(x) \
    ((x == SSH_AGENT_FAILURE) || \
    (x == SSH_AGENT_EXTENSION_FAILURE) || \
    (x == SSH_COM_AGENT2_FAILURE) || \
    (x == SSH2_AGENT_FAILURE))

/* Convert success/failure response from agent to a err.h status */
ساكن صحيح
decode_پاسخ(u_char type)
{
	إذا (agent_failed(type))
		أرجع SSH_ERR_AGENT_FAILURE;
	وإلا إذا (type == SSH_AGENT_SUCCESS)
		أرجع 0;
	وإلا
		أرجع SSH_ERR_INVALID_FORMAT;
}

/*
 * Opens an authentication socket at the provided path and stores the file
 * descriptor in fdp. Returns 0 on success and an error on failure.
 */
صحيح
ssh_get_authentication_socket_مسیر(ثابت حرف *authsocket, صحيح *fdp)
{
	صحيح sock, oerrno;
	بنية sockaddr_un sunaddr;

	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, حجم(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_مسیر, authsocket, حجم(sunaddr.sun_مسیر));

	إذا ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		أرجع SSH_ERR_SYSTEM_ERROR;

	/* close on exec */
	إذا (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (بنية sockaddr *)&sunaddr, حجم(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	إذا (fdp != عدم)
		*fdp = sock;
	وإلا
		close(sock);
	أرجع 0;
}

/*
 * Opens the default authentication socket and stores the file descriptor in
 * fdp. Returns 0 on success and an error on failure.
 */
صحيح
ssh_get_authentication_socket(صحيح *fdp)
{
	ثابت حرف *authsocket;

	إذا (fdp != عدم)
		*fdp = -1;

	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	إذا (authsocket == عدم || *authsocket == '\0')
		أرجع SSH_ERR_AGENT_NOT_PRESENT;

	أرجع ssh_get_authentication_socket_مسیر(authsocket, fdp);
}

/* Communicate with agent: send request and read reply */
ساكن صحيح
ssh_request_پاسخ(صحيح sock, بنية sshbuf *request, بنية sshbuf *پاسخ)
{
	صحيح r;
	اندازه_t l, len;
	حرف buf[1024];

	/* Get the length of the message, and format it in the buffer. */
	len = sshbuf_len(request);
	POKE_U32(buf, len);

	/* Send the length and then the packet to the agent. */
	إذا (atomicio(vwrite, sock, buf, 4) != 4 ||
	    atomicio(vwrite, sock, sshbuf_mutable_ptr(request),
	    sshbuf_len(request)) != sshbuf_len(request))
		أرجع SSH_ERR_AGENT_COMMUNICATION;
	/*
	 * Wait for response from the agent.  First read the length of the
	 * response packet.
	 */
	إذا (atomicio(اقرأ, sock, buf, 4) != 4)
	    أرجع SSH_ERR_AGENT_COMMUNICATION;

	/* Extract the length, and check it for sanity. */
	len = PEEK_U32(buf);
	إذا (len > MAX_AGENT_پاسخ_LEN)
		أرجع SSH_ERR_INVALID_FORMAT;

	/* Read the rest of the response in to the buffer. */
	sshbuf_reset(پاسخ);
	طالما (len > 0) {
		l = len;
		إذا (l > حجم(buf))
			l = حجم(buf);
		إذا (atomicio(اقرأ, sock, buf, l) != l)
			أرجع SSH_ERR_AGENT_COMMUNICATION;
		إذا ((r = sshbuf_put(پاسخ, buf, l)) != 0)
			أرجع r;
		len -= l;
	}
	أرجع 0;
}

/* Communicate with agent: sent request, read and decode status reply */
ساكن صحيح
ssh_request_پاسخ_decode(صحيح sock, بنية sshbuf *request)
{
	بنية sshbuf *پاسخ;
	صحيح r;
	u_char type;

	إذا ((پاسخ = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = ssh_request_پاسخ(sock, request, پاسخ)) != 0 ||
	    (r = sshbuf_get_u8(پاسخ, &type)) != 0 ||
	    (r = decode_پاسخ(type)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(پاسخ);
	أرجع r;
}

/*
 * Closes the agent socket if it should be closed (depends on how it was
 * obtained).  The argument must have been returned by
 * ssh_get_authentication_socket().
 */
فراغ
ssh_close_authentication_socket(صحيح sock)
{
	إذا (sock != -1 && getenv(SSH_AUTHSOCKET_ENV_NAME) != عدم)
		close(sock);
}

/* Lock/unlock agent */
صحيح
ssh_قفل_agent(صحيح sock, صحيح قفل, ثابت حرف *password)
{
	صحيح r;
	u_char type = قفل ? SSH_AGENTC_قفل : SSH_AGENTC_UNLOCK;
	بنية sshbuf *پیام;

	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(پیام, type)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, password)) != 0 ||
	    (r = ssh_request_پاسخ_decode(sock, پیام)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(پیام);
	أرجع r;
}


ساكن صحيح
deserialise_identity2(بنية sshbuf *ids, بنية sshkey **keyp, حرف **commentp)
{
	صحيح r;
	حرف *comment = عدم;
	ثابت u_char *blob;
	اندازه_t blen;

	إذا ((r = sshbuf_get_string_مستقیم(ids, &blob, &blen)) != 0 ||
	    (r = sshbuf_get_cstring(ids, &comment, عدم)) != 0)
		اذهب بیرون;
	إذا ((r = sshkey_from_blob(blob, blen, keyp)) != 0)
		اذهب بیرون;
	إذا (commentp != عدم) {
		*commentp = comment;
		comment = عدم;
	}
	r = 0;
 بیرون:
	حرر(comment);
	أرجع r;
}

/*
 * Fetch list of identities held by the agent.
 */
صحيح
ssh_fetch_identitylist(صحيح sock, بنية ssh_identitylist **idlp)
{
	u_char type;
	uint32_t رقم, i;
	بنية sshbuf *پیام;
	بنية ssh_identitylist *idl = عدم;
	صحيح r;

	/*
	 * Send a message to the agent requesting for a list of the
	 * identities it can represent.
	 */
	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(پیام, SSH2_AGENTC_REQUEST_IDENTITIES)) != 0)
		اذهب بیرون;

	إذا ((r = ssh_request_پاسخ(sock, پیام, پیام)) != 0)
		اذهب بیرون;

	/* Get message type, and verify that we got a proper answer. */
	إذا ((r = sshbuf_get_u8(پیام, &type)) != 0)
		اذهب بیرون;
	إذا (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		اذهب بیرون;
	} وإلا إذا (type != SSH2_AGENT_IDENTITIES_ANSWER) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}

	/* Get the number of entries in the response and check it for sanity. */
	إذا ((r = sshbuf_get_u32(پیام, &رقم)) != 0)
		اذهب بیرون;
	إذا (رقم > MAX_AGENT_IDENTITIES) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	إذا (رقم == 0) {
		r = SSH_ERR_AGENT_NO_IDENTITIES;
		اذهب بیرون;
	}

	/* Deserialise the response into a list of keys/comments */
	إذا ((idl = حافظه_صفر_بده(1, حجم(*idl))) == عدم ||
	    (idl->کلیدها = حافظه_صفر_بده(رقم, حجم(*idl->کلیدها))) == عدم ||
	    (idl->comments = حافظه_صفر_بده(رقم, حجم(*idl->comments))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	لكل (i = 0; i < رقم;) {
		إذا ((r = deserialise_identity2(پیام, &(idl->کلیدها[i]),
		    &(idl->comments[i]))) != 0) {
			إذا (r == SSH_ERR_کلید_TYPE_UNKNOWN) {
				/* Gracefully skip unknown key types */
				رقم--;
				استمر;
			} وإلا
				اذهب بیرون;
		}
		i++;
	}
	idl->nkeys = رقم;
	*idlp = idl;
	idl = عدم;
	r = 0;
 بیرون:
	sshbuf_free(پیام);
	إذا (idl != عدم)
		ssh_free_identitylist(idl);
	أرجع r;
}

فراغ
ssh_free_identitylist(بنية ssh_identitylist *idl)
{
	اندازه_t i;

	إذا (idl == عدم)
		أرجع;
	لكل (i = 0; i < idl->nkeys; i++) {
		إذا (idl->کلیدها != عدم)
			sshkey_free(idl->کلیدها[i]);
		إذا (idl->comments != عدم)
			حرر(idl->comments[i]);
	}
	حرر(idl->کلیدها);
	حرر(idl->comments);
	حرر(idl);
}

/*
 * Check if the ssh agent has a given key.
 * Returns 0 if found, or a negative SSH_ERR_* error code on failure.
 */
صحيح
ssh_agent_has_کلید(صحيح sock, ثابت بنية sshkey *کلید)
{
	صحيح r, ret = SSH_ERR_کلید_NOT_یافت;
	اندازه_t i;
	بنية ssh_identitylist *idlist = عدم;

	إذا ((r = ssh_fetch_identitylist(sock, &idlist)) != 0) {
		أرجع r;
	}

	لكل (i = 0; i < idlist->nkeys; i++) {
		إذا (sshkey_equal_عمومی(idlist->کلیدها[i], کلید)) {
			ret = 0;
			اكسر;
		}
	}

	ssh_free_identitylist(idlist);
	أرجع ret;
}

/*
 * Sends a challenge (typically from a server via ssh(1)) to the agent,
 * and waits for a response from the agent.
 * Returns true (non-zero) if the agent gave the correct answer, zero
 * otherwise.
 */


/* encode signature algorithm in flag bits, so we can keep the msg format */
ساكن u_int
agent_encode_alg(ثابت بنية sshkey *کلید, ثابت حرف *alg)
{
	إذا (alg != عدم && sshkey_type_plain(کلید->type) == کلید_RSA) {
		إذا (strcmp(alg, "rsa-sha2-256") == 0 ||
		    strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
			أرجع SSH_AGENT_RSA_SHA2_256;
		إذا (strcmp(alg, "rsa-sha2-512") == 0 ||
		    strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
			أرجع SSH_AGENT_RSA_SHA2_512;
	}
	أرجع 0;
}

/* ask agent to sign data, returns err.h code on error, 0 on success */
صحيح
ssh_agent_sign(صحيح sock, ثابت بنية sshkey *کلید,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *داده, اندازه_t datalen, ثابت حرف *alg, u_int compat)
{
	بنية sshbuf *پیام;
	u_char *sig = عدم, type = 0;
	اندازه_t len = 0;
	u_int flags = 0;
	صحيح r = SSH_ERR_داخلی_ERROR;

	*sigp = عدم;
	*lenp = 0;

	إذا (datalen > SSH_کلید_MAX_SIGN_داده_اندازه)
		أرجع SSH_ERR_INVALID_آرگومان;
	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	flags |= agent_encode_alg(کلید, alg);
	إذا ((r = sshbuf_put_u8(پیام, SSH2_AGENTC_SIGN_REQUEST)) != 0 ||
	    (r = sshkey_puts(کلید, پیام)) != 0 ||
	    (r = sshbuf_put_string(پیام, داده, datalen)) != 0 ||
	    (r = sshbuf_put_u32(پیام, flags)) != 0)
		اذهب بیرون;
	إذا ((r = ssh_request_پاسخ(sock, پیام, پیام)) != 0)
		اذهب بیرون;
	إذا ((r = sshbuf_get_u8(پیام, &type)) != 0)
		اذهب بیرون;
	إذا (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		اذهب بیرون;
	} وإلا إذا (type != SSH2_AGENT_SIGN_RESPONSE) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_get_string(پیام, &sig, &len)) != 0)
		اذهب بیرون;
	/*
	 * Check what we actually got back from the agent, in case it returned
	 * an incorrect RSA signature algorithm (e.g. "ssh-rsa" (RSA/SHA1) vs.
	 * "rsa-sha2-256").
	 * We don't do this for FIDO signatures as webauthn vs plain are just
	 * different signature formats and not entirely different algorithms.
	 */
	إذا (!sshkey_is_sk(کلید) &&
	    (r = sshkey_check_sigtype(sig, len, alg)) != 0)
		اذهب بیرون;
	/* success */
	*sigp = sig;
	*lenp = len;
	sig = عدم;
	len = 0;
	r = 0;
 بیرون:
	freezero(sig, len);
	sshbuf_free(پیام);
	أرجع r;
}

/* Encode key for a message to the agent. */

ساكن صحيح
encode_dest_constraint_hop(بنية sshbuf *m,
    ثابت بنية dest_constraint_hop *dch)
{
	بنية sshbuf *b;
	u_int i;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_cstring(b, dch->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, dch->hostname)) != 0 ||
	    (r = sshbuf_put_string(b, عدم, 0)) != 0) /* reserved */
		اذهب بیرون;
	لكل (i = 0; i < dch->nkeys; i++) {
		إذا ((r = sshkey_puts(dch->کلیدها[i], b)) != 0 ||
		    (r = sshbuf_put_u8(b, dch->کلید_is_ca[i] != 0)) != 0)
			اذهب بیرون;
	}
	إذا ((r = sshbuf_put_stringb(m, b)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
encode_dest_constraint(بنية sshbuf *m, ثابت بنية dest_constraint *dc)
{
	بنية sshbuf *b;
	صحيح r;

	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = encode_dest_constraint_hop(b, &dc->from)) != 0 ||
	    (r = encode_dest_constraint_hop(b, &dc->مقصد)) != 0 ||
	    (r = sshbuf_put_string(b, عدم, 0)) != 0) /* reserved */
		اذهب بیرون;
	إذا ((r = sshbuf_put_stringb(m, b)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
encode_constraints(بنية sshbuf *m, u_int life, u_int confirm,
    ثابت حرف *provider,
    بنية dest_constraint **dest_constraints, اندازه_t ndest_constraints,
    صحيح cert_only, بنية sshkey **certs, اندازه_t ncerts)
{
	صحيح r;
	بنية sshbuf *b = عدم;
	اندازه_t i;

	إذا (life != 0) {
		إذا ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_LIFETIME)) != 0 ||
		    (r = sshbuf_put_u32(m, life)) != 0)
			اذهب بیرون;
	}
	إذا (confirm != 0) {
		إذا ((r = sshbuf_put_u8(m, SSH_AGENT_CONSTRAIN_CONFIRM)) != 0)
			اذهب بیرون;
	}
	إذا (provider != عدم) {
		إذا ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "sk-provider@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(m, provider)) != 0)
			اذهب بیرون;
	}
	إذا (dest_constraints != عدم && ndest_constraints > 0) {
		إذا ((b = sshbuf_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بیرون;
		}
		لكل (i = 0; i < ndest_constraints; i++) {
			إذا ((r = encode_dest_constraint(b,
			    dest_constraints[i])) != 0)
				اذهب بیرون;
		}
		إذا ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "restrict-destination-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			اذهب بیرون;
		sshbuf_free(b);
		b = عدم;
	}
	إذا (ncerts != 0) {
		إذا ((b = sshbuf_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بیرون;
		}
		لكل (i = 0; i < ncerts; i++) {
			إذا ((r = sshkey_puts(certs[i], b)) != 0)
				اذهب بیرون;
		}
		إذا ((r = sshbuf_put_u8(m,
		    SSH_AGENT_CONSTRAIN_EXTENSION)) != 0 ||
		    (r = sshbuf_put_cstring(m,
		    "associated-certs-v00@openssh.com")) != 0 ||
		    (r = sshbuf_put_u8(m, cert_only != 0)) != 0 ||
		    (r = sshbuf_put_stringb(m, b)) != 0)
			اذهب بیرون;
		sshbuf_free(b);
		b = عدم;
	}
	r = 0;
 بیرون:
	sshbuf_free(b);
	أرجع r;
}

/*
 * Adds an identity to the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحيح
ssh_جمع_کن_عنصر_خنثی_constrained(صحيح sock, بنية sshkey *کلید,
    ثابت حرف *comment, u_int life, u_int confirm,
    ثابت حرف *provider, بنية dest_constraint **dest_constraints,
    اندازه_t ndest_constraints)
{
	بنية sshbuf *پیام;
	صحيح r, constrained = (life || confirm || provider || dest_constraints);
	u_char type;

	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	بدل (کلید->type) {
#اگر_تعریف_شده WITH_OPENSSL
	حالة کلید_RSA:
	حالة کلید_RSA_CERT:
	حالة کلید_ECDSA:
	حالة کلید_ECDSA_CERT:
	حالة کلید_ECDSA_SK:
	حالة کلید_ECDSA_SK_CERT:
#پایان_اگر
	حالة کلید_ED25519:
	حالة کلید_ED25519_CERT:
	حالة کلید_MLDSA44_ED25519:
	حالة کلید_MLDSA44_ED25519_CERT:
	حالة کلید_ED25519_SK:
	حالة کلید_ED25519_SK_CERT:
		type = constrained ?
		    SSH2_AGENTC_جمع_کن_ID_CONSTRAINED :
		    SSH2_AGENTC_جمع_کن_عنصر_خنثی;
		إذا ((r = sshbuf_put_u8(پیام, type)) != 0 ||
		    (r = sshkey_خصوصی_serialize(کلید, پیام)) != 0 ||
		    (r = sshbuf_put_cstring(پیام, comment)) != 0)
			اذهب بیرون;
		اكسر;
	افتراضي:
		r = SSH_ERR_INVALID_آرگومان;
		اذهب بیرون;
	}
	إذا (constrained &&
	    (r = encode_constraints(پیام, life, confirm, provider,
	    dest_constraints, ndest_constraints, 0, عدم, 0)) != 0)
		اذهب بیرون;
	إذا ((r = ssh_request_پاسخ_decode(sock, پیام)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(پیام);
	أرجع r;
}

/*
 * Removes an identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحيح
ssh_remove_عنصر_خنثی(صحيح sock, ثابت بنية sshkey *کلید)
{
	بنية sshbuf *پیام;
	صحيح r;
	u_char *blob = عدم;
	اندازه_t blen;

	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	إذا (کلید->type != کلید_UNSPEC) {
		إذا ((r = sshkey_مقصد_blob(کلید, &blob, &blen)) != 0)
			اذهب بیرون;
		إذا ((r = sshbuf_put_u8(پیام,
		    SSH2_AGENTC_REMOVE_عنصر_خنثی)) != 0 ||
		    (r = sshbuf_put_string(پیام, blob, blen)) != 0)
			اذهب بیرون;
	} وإلا {
		r = SSH_ERR_INVALID_آرگومان;
		اذهب بیرون;
	}
	إذا ((r = ssh_request_پاسخ_decode(sock, پیام)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	إذا (blob != عدم)
		freezero(blob, blen);
	sshbuf_free(پیام);
	أرجع r;
}

/*
 * Add/remove an token-based identity from the authentication server.
 * This call is intended only for use by ssh-add(1) and like applications.
 */
صحيح
ssh_update_card(صحيح sock, صحيح جمع_کن, ثابت حرف *reader_id, ثابت حرف *pin,
    u_int life, u_int confirm,
    بنية dest_constraint **dest_constraints, اندازه_t ndest_constraints,
    صحيح cert_only, بنية sshkey **certs, اندازه_t ncerts)
{
	بنية sshbuf *پیام;
	صحيح r, constrained = (life || confirm || dest_constraints || certs);
	u_char type;

	إذا (جمع_کن) {
		type = constrained ?
		    SSH_AGENTC_جمع_کن_SMARTCARD_کلید_CONSTRAINED :
		    SSH_AGENTC_جمع_کن_SMARTCARD_کلید;
	} وإلا
		type = SSH_AGENTC_REMOVE_SMARTCARD_کلید;

	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(پیام, type)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, reader_id)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, pin)) != 0)
		اذهب بیرون;
	إذا (constrained &&
	    (r = encode_constraints(پیام, life, confirm, عدم,
	    dest_constraints, ndest_constraints,
	    cert_only, certs, ncerts)) != 0)
		اذهب بیرون;
	إذا ((r = ssh_request_پاسخ_decode(sock, پیام)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(پیام);
	أرجع r;
}

/*
 * Removes all identities from the agent.
 * This call is intended only for use by ssh-add(1) and like applications.
 *
 * This supports the SSH protocol 1 message to because, when clearing all
 * keys from an agent, we generally want to clear both protocol v1 and v2
 * keys.
 */
صحيح
ssh_remove_all_identities(صحيح sock, صحيح نسخه)
{
	بنية sshbuf *پیام;
	u_char type = (نسخه == 1) ?
	    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES :
	    SSH2_AGENTC_REMOVE_ALL_IDENTITIES;
	صحيح r;

	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(پیام, type)) != 0)
		اذهب بیرون;
	إذا ((r = ssh_request_پاسخ_decode(sock, پیام)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(پیام);
	أرجع r;
}

/* Binds a session ID to a hostkey via the initial KEX signature. */
صحيح
ssh_agent_bind_hostkey(صحيح sock, ثابت بنية sshkey *کلید,
    ثابت بنية sshbuf *session_id, ثابت بنية sshbuf *signature,
    صحيح forwarding)
{
	بنية sshbuf *پیام;
	صحيح r;

	إذا (کلید == عدم || session_id == عدم || signature == عدم)
		أرجع SSH_ERR_INVALID_آرگومان;
	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(پیام, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "session-bind@openssh.com")) != 0 ||
	    (r = sshkey_puts(کلید, پیام)) != 0 ||
	    (r = sshbuf_put_stringb(پیام, session_id)) != 0 ||
	    (r = sshbuf_put_stringb(پیام, signature)) != 0 ||
	    (r = sshbuf_put_u8(پیام, forwarding ? 1 : 0)) != 0)
		اذهب بیرون;
	إذا ((r = ssh_request_پاسخ_decode(sock, پیام)) != 0)
		اذهب بیرون;
	/* success */
	r = 0;
 بیرون:
	sshbuf_free(پیام);
	أرجع r;
}

/* Queries supported extension request types */
صحيح
ssh_agent_query_extensions(صحيح sock, حرف ***exts)
{
	بنية sshbuf *پیام;
	صحيح r;
	u_char type;
	حرف *cp = عدم, **ret = عدم;
	اندازه_t i = 0;

	*exts = عدم;
	إذا ((پیام = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u8(پیام, SSH_AGENTC_EXTENSION)) != 0 ||
	    (r = sshbuf_put_cstring(پیام, "query")) != 0)
		اذهب بیرون;
	إذا ((r = ssh_request_پاسخ(sock, پیام, پیام)) != 0)
		اذهب بیرون;
	إذا ((r = sshbuf_get_u8(پیام, &type)) != 0)
		اذهب بیرون;
	إذا (agent_failed(type)) {
		r = SSH_ERR_AGENT_FAILURE;
		اذهب بیرون;
	}
	/* Reply should start with "query" */
	إذا (type != SSH_AGENT_EXTENSION_RESPONSE ||
	   (r = sshbuf_get_cstring(پیام, &cp, عدم)) != 0 ||
	   strcmp(cp, "query") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	ret = xcalloc(1, حجم(*ret));
	طالما (sshbuf_len(پیام)) {
		ret = xrecallocarray(ret, i + 1, i + 2, حجم(*ret));
		إذا ((r = sshbuf_get_cstring(پیام, ret + i, عدم)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بیرون;
		}
		i++;
	}
	/* success */
	r = 0;
	*exts = ret;
	ret = عدم; /* transferred */
 بیرون:
	حرر(cp);
	stringlist_free(ret);
	sshbuf_free(پیام);
	أرجع r;
}
