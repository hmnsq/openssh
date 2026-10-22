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

கட்டமைப்பு sshbuf;
கட்டமைப்பு sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
கட்டமைப்பு ssh_identitylist {
	size_t nkeys;
	கட்டமைப்பு sshkey **சாவிகள்;
	எழுத்து **comments;
};

/* Key destination restrictions */
கட்டமைப்பு dest_constraint_hop {
	எழுத்து *user;	/* wildcards allowed */
	எழுத்து *hostname; /* used to matching cert principals and for display */
	முழு is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	கட்டமைப்பு sshkey **சாவிகள்;
	முழு *சாவி_is_ca;
};
கட்டமைப்பு dest_constraint {
	கட்டமைப்பு dest_constraint_hop from;
	கட்டமைப்பு dest_constraint_hop to;
};

முழு	ssh_get_authentication_socket(முழு *fdp);
முழு	ssh_get_authentication_socket_path(மாறிலி எழுத்து *authsocket, முழு *fdp);
வெறுமை	ssh_close_authentication_socket(முழு sock);

முழு	ssh_lock_agent(முழு sock, முழு lock, மாறிலி எழுத்து *password);
முழு	ssh_fetch_identitylist(முழு sock, கட்டமைப்பு ssh_identitylist **idlp);
வெறுமை	ssh_free_identitylist(கட்டமைப்பு ssh_identitylist *idl);
முழு	ssh_add_identity_constrained(முழு sock, கட்டமைப்பு sshkey *சாவி,
    மாறிலி எழுத்து *comment, u_int life, u_int confirm, மாறிலி எழுத்து *provider,
    கட்டமைப்பு dest_constraint **dest_constraints, size_t ndest_constraints);
முழு	ssh_agent_has_சாவி(முழு sock, மாறிலி கட்டமைப்பு sshkey *சாவி);
முழு	ssh_remove_identity(முழு sock, மாறிலி கட்டமைப்பு sshkey *சாவி);
முழு	ssh_update_card(முழு sock, முழு add, மாறிலி எழுத்து *reader_id,
	    மாறிலி எழுத்து *pin, u_int life, u_int confirm,
	    கட்டமைப்பு dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    முழு cert_only, கட்டமைப்பு sshkey **certs, size_t ncerts);
முழு	ssh_remove_all_identities(முழு sock, முழு version);

முழு	ssh_agent_sign(முழு sock, மாறிலி கட்டமைப்பு sshkey *சாவி,
	    u_char **sigp, size_t *lenp,
	    மாறிலி u_char *data, size_t datalen, மாறிலி எழுத்து *alg, u_int compat);

முழு	ssh_agent_bind_hostkey(முழு sock, மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி கட்டமைப்பு sshbuf *session_id, மாறிலி கட்டமைப்பு sshbuf *signature,
    முழு forwarding);

முழு	ssh_agent_query_extensions(முழு sock, எழுத்து ***exts);

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
#define SSH_AGENTC_ADD_SMARTCARD_சாவி		20
#define SSH_AGENTC_REMOVE_SMARTCARD_சாவி		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_சாவி_CONSTRAINED 26

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
