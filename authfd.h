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

সংরচনা sshbuf;
সংরচনা sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
সংরচনা ssh_identitylist {
	size_t nkeys;
	সংরচনা sshkey **চাবিগুলি;
	ৱর্ণ **comments;
};

/* Key destination restrictions */
সংরচনা dest_constraint_hop {
	ৱর্ণ *user;	/* wildcards allowed */
	ৱর্ণ *hostname; /* used to matching cert principals and for display */
	পূর্ণাঙ্ক is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	সংরচনা sshkey **চাবিগুলি;
	পূর্ণাঙ্ক *চাবি_is_ca;
};
সংরচনা dest_constraint {
	সংরচনা dest_constraint_hop from;
	সংরচনা dest_constraint_hop to;
};

পূর্ণাঙ্ক	ssh_get_authentication_socket(পূর্ণাঙ্ক *fdp);
পূর্ণাঙ্ক	ssh_get_authentication_socket_path(ধ্রুৱ ৱর্ণ *authsocket, পূর্ণাঙ্ক *fdp);
শূন্য	ssh_close_authentication_socket(পূর্ণাঙ্ক sock);

পূর্ণাঙ্ক	ssh_lock_agent(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক lock, ধ্রুৱ ৱর্ণ *password);
পূর্ণাঙ্ক	ssh_fetch_identitylist(পূর্ণাঙ্ক sock, সংরচনা ssh_identitylist **idlp);
শূন্য	ssh_free_identitylist(সংরচনা ssh_identitylist *idl);
পূর্ণাঙ্ক	ssh_add_identity_constrained(পূর্ণাঙ্ক sock, সংরচনা sshkey *চাবি,
    ধ্রুৱ ৱর্ণ *comment, u_int life, u_int confirm, ধ্রুৱ ৱর্ণ *provider,
    সংরচনা dest_constraint **dest_constraints, size_t ndest_constraints);
পূর্ণাঙ্ক	ssh_agent_has_চাবি(পূর্ণাঙ্ক sock, ধ্রুৱ সংরচনা sshkey *চাবি);
পূর্ণাঙ্ক	ssh_remove_identity(পূর্ণাঙ্ক sock, ধ্রুৱ সংরচনা sshkey *চাবি);
পূর্ণাঙ্ক	ssh_update_card(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক add, ধ্রুৱ ৱর্ণ *reader_id,
	    ধ্রুৱ ৱর্ণ *pin, u_int life, u_int confirm,
	    সংরচনা dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    পূর্ণাঙ্ক cert_only, সংরচনা sshkey **certs, size_t ncerts);
পূর্ণাঙ্ক	ssh_remove_all_identities(পূর্ণাঙ্ক sock, পূর্ণাঙ্ক version);

পূর্ণাঙ্ক	ssh_agent_sign(পূর্ণাঙ্ক sock, ধ্রুৱ সংরচনা sshkey *চাবি,
	    u_char **sigp, size_t *lenp,
	    ধ্রুৱ u_char *data, size_t datalen, ধ্রুৱ ৱর্ণ *alg, u_int compat);

পূর্ণাঙ্ক	ssh_agent_bind_hostkey(পূর্ণাঙ্ক sock, ধ্রুৱ সংরচনা sshkey *চাবি,
    ধ্রুৱ সংরচনা sshbuf *session_id, ধ্রুৱ সংরচনা sshbuf *signature,
    পূর্ণাঙ্ক forwarding);

পূর্ণাঙ্ক	ssh_agent_query_extensions(পূর্ণাঙ্ক sock, ৱর্ণ ***exts);

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
#define SSH_AGENTC_ADD_SMARTCARD_চাবি		20
#define SSH_AGENTC_REMOVE_SMARTCARD_চাবি		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_চাবি_CONSTRAINED 26

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
