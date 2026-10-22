/* $OpenBSD: authfd.h,v 1.55 2026/03/05 05:44:15 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions to interface with the SSH_AUTHENTICATION_FD socket.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef AUTHFD_H
#define AUTHFD_H

ساختار sshbuf;
ساختار sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
ساختار ssh_identitylist {
	size_t nkeys;
	ساختار sshkey **کلیدها;
	نویسه **comments;
};

/* Key destination restrictions */
ساختار dest_constraint_hop {
	نویسه *user;	/* wildcards allowed */
	نویسه *hostname; /* used to matching cert principals and for display */
	صحیح is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	ساختار sshkey **کلیدها;
	صحیح *کلید_is_ca;
};
ساختار dest_constraint {
	ساختار dest_constraint_hop from;
	ساختار dest_constraint_hop to;
};

صحیح	ssh_get_authentication_socket(صحیح *fdp);
صحیح	ssh_get_authentication_socket_path(ثابت نویسه *authsocket, صحیح *fdp);
تهی	ssh_close_authentication_socket(صحیح sock);

صحیح	ssh_lock_agent(صحیح sock, صحیح lock, ثابت نویسه *password);
صحیح	ssh_fetch_identitylist(صحیح sock, ساختار ssh_identitylist **idlp);
تهی	ssh_free_identitylist(ساختار ssh_identitylist *idl);
صحیح	ssh_add_identity_constrained(صحیح sock, ساختار sshkey *کلید,
    ثابت نویسه *comment, u_int life, u_int confirm, ثابت نویسه *provider,
    ساختار dest_constraint **dest_constraints, size_t ndest_constraints);
صحیح	ssh_agent_has_کلید(صحیح sock, ثابت ساختار sshkey *کلید);
صحیح	ssh_remove_identity(صحیح sock, ثابت ساختار sshkey *کلید);
صحیح	ssh_update_card(صحیح sock, صحیح add, ثابت نویسه *reader_id,
	    ثابت نویسه *pin, u_int life, u_int confirm,
	    ساختار dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    صحیح cert_only, ساختار sshkey **certs, size_t ncerts);
صحیح	ssh_remove_all_identities(صحیح sock, صحیح version);

صحیح	ssh_agent_sign(صحیح sock, ثابت ساختار sshkey *کلید,
	    u_char **sigp, size_t *lenp,
	    ثابت u_char *data, size_t datalen, ثابت نویسه *alg, u_int compat);

صحیح	ssh_agent_bind_hostkey(صحیح sock, ثابت ساختار sshkey *کلید,
    ثابت ساختار sshbuf *session_id, ثابت ساختار sshbuf *signature,
    صحیح forwarding);

صحیح	ssh_agent_query_extensions(صحیح sock, نویسه ***exts);

/* Messages for the authentication agent connection. */
#define SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#define SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#define SSH_AGENTC_RSA_CHALLENGE		3
#define SSH_AGENT_RSA_RESPONSE			4
#define SSH_AGENT_FAILURE			5
#define SSH_AGENT_SUCCESS			6
#define SSH_AGENTC_ADD_RSA_IDENTITY		7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY		8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#define SSH2_AGENTC_REQUEST_IDENTITIES		11
#define SSH2_AGENT_IDENTITIES_ANSWER		12
#define SSH2_AGENTC_SIGN_REQUEST		13
#define SSH2_AGENT_SIGN_RESPONSE		14
#define SSH2_AGENTC_ADD_IDENTITY		17
#define SSH2_AGENTC_REMOVE_IDENTITY		18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#define SSH_AGENTC_ADD_SMARTCARD_کلید		20
#define SSH_AGENTC_REMOVE_SMARTCARD_کلید		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_کلید_CONSTRAINED 26

/* generic extension mechanism */
#define SSH_AGENTC_EXTENSION			27
#define SSH_AGENT_EXTENSION_FAILURE		28
#define SSH_AGENT_EXTENSION_RESPONSE		29

#define	SSH_AGENT_CONSTRAIN_LIFETIME		1
#define	SSH_AGENT_CONSTRAIN_CONFIRM		2
#define	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#define SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#define SSH_COM_AGENT2_FAILURE			102

#define	SSH_AGENT_OLD_SIGNATURE			0x01
#define	SSH_AGENT_RSA_SHA2_256			0x02
#define	SSH_AGENT_RSA_SHA2_512			0x04

#endif				/* AUTHFD_H */
