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

কাঠামো sshbuf;
কাঠামো sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
কাঠামো ssh_identitylist {
	আকার_t nkeys;
	কাঠামো sshkey **চাবিগুলি;
	অক্ষর **comments;
};

/* Key destination restrictions */
কাঠামো dest_constraint_hop {
	অক্ষর *user;	/* wildcards allowed */
	অক্ষর *hostname; /* used to matching cert principals and for display */
	পূর্ণসংখ্যা is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	কাঠামো sshkey **চাবিগুলি;
	পূর্ণসংখ্যা *চাবি_is_ca;
};
কাঠামো dest_constraint {
	কাঠামো dest_constraint_hop from;
	কাঠামো dest_constraint_hop to;
};

পূর্ণসংখ্যা	ssh_get_authentication_socket(পূর্ণসংখ্যা *fdp);
পূর্ণসংখ্যা	ssh_get_authentication_socket_path(ধ্রুবক অক্ষর *authsocket, পূর্ণসংখ্যা *fdp);
শূন্য	ssh_close_authentication_socket(পূর্ণসংখ্যা sock);

পূর্ণসংখ্যা	ssh_lock_agent(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা lock, ধ্রুবক অক্ষর *password);
পূর্ণসংখ্যা	ssh_fetch_identitylist(পূর্ণসংখ্যা sock, কাঠামো ssh_identitylist **idlp);
শূন্য	ssh_free_identitylist(কাঠামো ssh_identitylist *idl);
পূর্ণসংখ্যা	ssh_add_identity_constrained(পূর্ণসংখ্যা sock, কাঠামো sshkey *চাবি,
    ধ্রুবক অক্ষর *comment, u_int life, u_int confirm, ধ্রুবক অক্ষর *provider,
    কাঠামো dest_constraint **dest_constraints, আকার_t ndest_constraints);
পূর্ণসংখ্যা	ssh_agent_has_চাবি(পূর্ণসংখ্যা sock, ধ্রুবক কাঠামো sshkey *চাবি);
পূর্ণসংখ্যা	ssh_remove_identity(পূর্ণসংখ্যা sock, ধ্রুবক কাঠামো sshkey *চাবি);
পূর্ণসংখ্যা	ssh_update_card(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা add, ধ্রুবক অক্ষর *reader_id,
	    ধ্রুবক অক্ষর *pin, u_int life, u_int confirm,
	    কাঠামো dest_constraint **dest_constraints,
	    আকার_t ndest_constraints,
	    পূর্ণসংখ্যা cert_only, কাঠামো sshkey **certs, আকার_t ncerts);
পূর্ণসংখ্যা	ssh_remove_all_identities(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা version);

পূর্ণসংখ্যা	ssh_agent_sign(পূর্ণসংখ্যা sock, ধ্রুবক কাঠামো sshkey *চাবি,
	    u_char **sigp, আকার_t *lenp,
	    ধ্রুবক u_char *তথ্য, আকার_t datalen, ধ্রুবক অক্ষর *alg, u_int compat);

পূর্ণসংখ্যা	ssh_agent_bind_hostkey(পূর্ণসংখ্যা sock, ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক কাঠামো sshbuf *session_id, ধ্রুবক কাঠামো sshbuf *signature,
    পূর্ণসংখ্যা forwarding);

পূর্ণসংখ্যা	ssh_agent_query_extensions(পূর্ণসংখ্যা sock, অক্ষর ***exts);

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
