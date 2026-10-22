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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ AUTHFD_H
#ವ್ಯಾಖ್ಯಾನಿಸು AUTHFD_H

ರಚನೆ sshbuf;
ರಚನೆ sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
ರಚನೆ ssh_identitylist {
	ಗಾತ್ರ_t nkeys;
	ರಚನೆ sshkey **ಕೀಲಿಗಳು;
	ಅಕ್ಷರ **comments;
};

/* Key destination restrictions */
ರಚನೆ dest_constraint_hop {
	ಅಕ್ಷರ *user;	/* wildcards allowed */
	ಅಕ್ಷರ *hostname; /* used to matching cert principals and for display */
	ಪೂರ್ಣಾಂಕ is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	ರಚನೆ sshkey **ಕೀಲಿಗಳು;
	ಪೂರ್ಣಾಂಕ *ಕೀಲಿ_is_ca;
};
ರಚನೆ dest_constraint {
	ರಚನೆ dest_constraint_hop from;
	ರಚನೆ dest_constraint_hop ಗಮ್ಯ;
};

ಪೂರ್ಣಾಂಕ	ssh_get_authentication_socket(ಪೂರ್ಣಾಂಕ *fdp);
ಪೂರ್ಣಾಂಕ	ssh_get_authentication_socket_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *authsocket, ಪೂರ್ಣಾಂಕ *fdp);
ಶೂನ್ಯ	ssh_close_authentication_socket(ಪೂರ್ಣಾಂಕ sock);

ಪೂರ್ಣಾಂಕ	ssh_ಬೀಗ_agent(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ ಬೀಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password);
ಪೂರ್ಣಾಂಕ	ssh_fetch_identitylist(ಪೂರ್ಣಾಂಕ sock, ರಚನೆ ssh_identitylist **idlp);
ಶೂನ್ಯ	ssh_free_identitylist(ರಚನೆ ssh_identitylist *idl);
ಪೂರ್ಣಾಂಕ	ssh_ಕೂಡಿಸು_ತಟಸ್ಥ_constrained(ಪೂರ್ಣಾಂಕ sock, ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment, u_int life, u_int confirm, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider,
    ರಚನೆ dest_constraint **dest_constraints, ಗಾತ್ರ_t ndest_constraints);
ಪೂರ್ಣಾಂಕ	ssh_agent_has_ಕೀಲಿ(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಂಕ	ssh_remove_ತಟಸ್ಥ(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಂಕ	ssh_update_card(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ ಕೂಡಿಸು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reader_id,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, u_int life, u_int confirm,
	    ರಚನೆ dest_constraint **dest_constraints,
	    ಗಾತ್ರ_t ndest_constraints,
	    ಪೂರ್ಣಾಂಕ cert_only, ರಚನೆ sshkey **certs, ಗಾತ್ರ_t ncerts);
ಪೂರ್ಣಾಂಕ	ssh_remove_all_identities(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ ಆವೃತ್ತಿ);

ಪೂರ್ಣಾಂಕ	ssh_agent_sign(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
	    u_char **sigp, ಗಾತ್ರ_t *lenp,
	    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat);

ಪೂರ್ಣಾಂಕ	ssh_agent_bind_hostkey(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *session_id, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *signature,
    ಪೂರ್ಣಾಂಕ forwarding);

ಪೂರ್ಣಾಂಕ	ssh_agent_query_extensions(ಪೂರ್ಣಾಂಕ sock, ಅಕ್ಷರ ***exts);

/* Messages for the authentication agent connection. */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_RSA_CHALLENGE		3
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENT_RSA_RESPONSE			4
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENT_FAILURE			5
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENT_SUCCESS			6
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_ಕೂಡಿಸು_RSA_ತಟಸ್ಥ		7
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_REMOVE_RSA_ತಟಸ್ಥ		8
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENTC_REQUEST_IDENTITIES		11
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENT_IDENTITIES_ANSWER		12
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENTC_SIGN_REQUEST		13
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENT_SIGN_RESPONSE		14
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENTC_ಕೂಡಿಸು_ತಟಸ್ಥ		17
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENTC_REMOVE_ತಟಸ್ಥ		18
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_ಕೂಡಿಸು_SMARTCARD_ಕೀಲಿ		20
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_REMOVE_SMARTCARD_ಕೀಲಿ		21

/* lock/unlock the agent */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_ಬೀಗ				22
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_ಕೂಡಿಸು_RSA_ID_CONSTRAINED	24
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENTC_ಕೂಡಿಸು_ID_CONSTRAINED		25
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_ಕೂಡಿಸು_SMARTCARD_ಕೀಲಿ_CONSTRAINED 26

/* generic extension mechanism */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTC_EXTENSION			27
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENT_EXTENSION_FAILURE		28
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENT_EXTENSION_RESPONSE		29

#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_AGENT_CONSTRAIN_LIFETIME		1
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_AGENT_CONSTRAIN_CONFIRM		2
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_COM_AGENT2_FAILURE			102

#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_AGENT_OLD_SIGNATURE			0x01
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_AGENT_RSA_SHA2_256			0x02
#ವ್ಯಾಖ್ಯಾನಿಸು	SSH_AGENT_RSA_SHA2_512			0x04

#ಆದರೆ_ಅಂತ್ಯ				/* AUTHFD_H */
