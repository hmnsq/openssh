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

ସଂରଚନା sshbuf;
ସଂରଚନା sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
ସଂରଚନା ssh_identitylist {
	size_t nkeys;
	ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ;
	ଅକ୍ଷର **comments;
};

/* Key destination restrictions */
ସଂରଚନା dest_constraint_hop {
	ଅକ୍ଷର *user;	/* wildcards allowed */
	ଅକ୍ଷର *hostname; /* used to matching cert principals and for display */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ଚାବି_is_ca;
};
ସଂରଚନା dest_constraint {
	ସଂରଚନା dest_constraint_hop from;
	ସଂରଚନା dest_constraint_hop to;
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_get_authentication_socket(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fdp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_get_authentication_socket_path(ଅଚଳ ଅକ୍ଷର *authsocket, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fdp);
ଶୂନ୍ୟ	ssh_close_authentication_socket(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_lock_agent(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lock, ଅଚଳ ଅକ୍ଷର *password);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_fetch_identitylist(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା ssh_identitylist **idlp);
ଶୂନ୍ୟ	ssh_free_identitylist(ସଂରଚନା ssh_identitylist *idl);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_add_identity_constrained(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ଅକ୍ଷର *comment, u_int life, u_int confirm, ଅଚଳ ଅକ୍ଷର *provider,
    ସଂରଚନା dest_constraint **dest_constraints, size_t ndest_constraints);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_agent_has_ଚାବି(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ସଂରଚନା sshkey *ଚାବି);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_remove_identity(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ସଂରଚନା sshkey *ଚାବି);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_update_card(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା add, ଅଚଳ ଅକ୍ଷର *reader_id,
	    ଅଚଳ ଅକ୍ଷର *pin, u_int life, u_int confirm,
	    ସଂରଚନା dest_constraint **dest_constraints,
	    size_t ndest_constraints,
	    ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert_only, ସଂରଚନା sshkey **certs, size_t ncerts);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_remove_all_identities(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା version);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_agent_sign(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
	    u_char **sigp, size_t *lenp,
	    ଅଚଳ u_char *data, size_t datalen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_agent_bind_hostkey(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ ସଂରଚନା sshbuf *session_id, ଅଚଳ ସଂରଚନା sshbuf *signature,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା forwarding);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_agent_query_extensions(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅକ୍ଷର ***exts);

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
#define SSH_AGENTC_ADD_SMARTCARD_ଚାବି		20
#define SSH_AGENTC_REMOVE_SMARTCARD_ଚାବି		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_ଚାବି_CONSTRAINED 26

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
