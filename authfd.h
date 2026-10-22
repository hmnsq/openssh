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

#यदि_अपरिभाषितम् AUTHFD_H
#परिभाषय AUTHFD_H

संरचना sshbuf;
संरचना sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
संरचना ssh_identitylist {
	आकार_t nkeys;
	संरचना sshkey **कुञ्चिकाः;
	वर्ण **comments;
};

/* Key destination restrictions */
संरचना dest_constraint_hop {
	वर्ण *user;	/* wildcards allowed */
	वर्ण *hostname; /* used to matching cert principals and for display */
	पूर्णाङ्क is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	संरचना sshkey **कुञ्चिकाः;
	पूर्णाङ्क *कुञ्चिका_is_ca;
};
संरचना dest_constraint {
	संरचना dest_constraint_hop from;
	संरचना dest_constraint_hop गन्तव्यम्;
};

पूर्णाङ्क	ssh_get_authentication_socket(पूर्णाङ्क *fdp);
पूर्णाङ्क	ssh_get_authentication_socket_मार्गः(ध्रुव वर्ण *authsocket, पूर्णाङ्क *fdp);
शून्य	ssh_close_authentication_socket(पूर्णाङ्क sock);

पूर्णाङ्क	ssh_तालकम्_agent(पूर्णाङ्क sock, पूर्णाङ्क तालकम्, ध्रुव वर्ण *password);
पूर्णाङ्क	ssh_fetch_identitylist(पूर्णाङ्क sock, संरचना ssh_identitylist **idlp);
शून्य	ssh_free_identitylist(संरचना ssh_identitylist *idl);
पूर्णाङ्क	ssh_सङ्कलय_तटस्थः_constrained(पूर्णाङ्क sock, संरचना sshkey *कुञ्चिका,
    ध्रुव वर्ण *comment, u_int life, u_int confirm, ध्रुव वर्ण *provider,
    संरचना dest_constraint **dest_constraints, आकार_t ndest_constraints);
पूर्णाङ्क	ssh_agent_has_कुञ्चिका(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका);
पूर्णाङ्क	ssh_remove_तटस्थः(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका);
पूर्णाङ्क	ssh_update_card(पूर्णाङ्क sock, पूर्णाङ्क सङ्कलय, ध्रुव वर्ण *reader_id,
	    ध्रुव वर्ण *pin, u_int life, u_int confirm,
	    संरचना dest_constraint **dest_constraints,
	    आकार_t ndest_constraints,
	    पूर्णाङ्क cert_only, संरचना sshkey **certs, आकार_t ncerts);
पूर्णाङ्क	ssh_remove_all_identities(पूर्णाङ्क sock, पूर्णाङ्क संस्करणम्);

पूर्णाङ्क	ssh_agent_sign(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका,
	    u_char **sigp, आकार_t *lenp,
	    ध्रुव u_char *दत्त, आकार_t datalen, ध्रुव वर्ण *alg, u_int compat);

पूर्णाङ्क	ssh_agent_bind_hostkey(पूर्णाङ्क sock, ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव संरचना sshbuf *session_id, ध्रुव संरचना sshbuf *signature,
    पूर्णाङ्क forwarding);

पूर्णाङ्क	ssh_agent_query_extensions(पूर्णाङ्क sock, वर्ण ***exts);

/* Messages for the authentication agent connection. */
#परिभाषय SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#परिभाषय SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#परिभाषय SSH_AGENTC_RSA_CHALLENGE		3
#परिभाषय SSH_AGENT_RSA_RESPONSE			4
#परिभाषय SSH_AGENT_FAILURE			5
#परिभाषय SSH_AGENT_SUCCESS			6
#परिभाषय SSH_AGENTC_सङ्कलय_RSA_तटस्थः		7
#परिभाषय SSH_AGENTC_REMOVE_RSA_तटस्थः		8
#परिभाषय SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#परिभाषय SSH2_AGENTC_REQUEST_IDENTITIES		11
#परिभाषय SSH2_AGENT_IDENTITIES_ANSWER		12
#परिभाषय SSH2_AGENTC_SIGN_REQUEST		13
#परिभाषय SSH2_AGENT_SIGN_RESPONSE		14
#परिभाषय SSH2_AGENTC_सङ्कलय_तटस्थः		17
#परिभाषय SSH2_AGENTC_REMOVE_तटस्थः		18
#परिभाषय SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#परिभाषय SSH_AGENTC_सङ्कलय_SMARTCARD_कुञ्चिका		20
#परिभाषय SSH_AGENTC_REMOVE_SMARTCARD_कुञ्चिका		21

/* lock/unlock the agent */
#परिभाषय SSH_AGENTC_तालकम्				22
#परिभाषय SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#परिभाषय SSH_AGENTC_सङ्कलय_RSA_ID_CONSTRAINED	24
#परिभाषय SSH2_AGENTC_सङ्कलय_ID_CONSTRAINED		25
#परिभाषय SSH_AGENTC_सङ्कलय_SMARTCARD_कुञ्चिका_CONSTRAINED 26

/* generic extension mechanism */
#परिभाषय SSH_AGENTC_EXTENSION			27
#परिभाषय SSH_AGENT_EXTENSION_FAILURE		28
#परिभाषय SSH_AGENT_EXTENSION_RESPONSE		29

#परिभाषय	SSH_AGENT_CONSTRAIN_LIFETIME		1
#परिभाषय	SSH_AGENT_CONSTRAIN_CONFIRM		2
#परिभाषय	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#परिभाषय SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#परिभाषय SSH_COM_AGENT2_FAILURE			102

#परिभाषय	SSH_AGENT_OLD_SIGNATURE			0x01
#परिभाषय	SSH_AGENT_RSA_SHA2_256			0x02
#परिभाषय	SSH_AGENT_RSA_SHA2_512			0x04

#यदि_अन्तः				/* AUTHFD_H */
