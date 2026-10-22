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

#నిర్వచితం_కాకపోతే AUTHFD_H
#నిర్వచించు AUTHFD_H

నిర్మాణం sshbuf;
నిర్మాణం sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
నిర్మాణం ssh_identitylist {
	కొలత_t nkeys;
	నిర్మాణం sshkey **కీలకాలు;
	అక్షరం **comments;
};

/* Key destination restrictions */
నిర్మాణం dest_constraint_hop {
	అక్షరం *user;	/* wildcards allowed */
	అక్షరం *hostname; /* used to matching cert principals and for display */
	పూర్ణాంకం is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	నిర్మాణం sshkey **కీలకాలు;
	పూర్ణాంకం *కీలకం_is_ca;
};
నిర్మాణం dest_constraint {
	నిర్మాణం dest_constraint_hop from;
	నిర్మాణం dest_constraint_hop గమ్యం;
};

పూర్ణాంకం	ssh_get_authentication_socket(పూర్ణాంకం *fdp);
పూర్ణాంకం	ssh_get_authentication_socket_మార్గం(స్థిరరాశి అక్షరం *authsocket, పూర్ణాంకం *fdp);
శూన్య	ssh_close_authentication_socket(పూర్ణాంకం sock);

పూర్ణాంకం	ssh_తాళం_agent(పూర్ణాంకం sock, పూర్ణాంకం తాళం, స్థిరరాశి అక్షరం *password);
పూర్ణాంకం	ssh_fetch_identitylist(పూర్ణాంకం sock, నిర్మాణం ssh_identitylist **idlp);
శూన్య	ssh_free_identitylist(నిర్మాణం ssh_identitylist *idl);
పూర్ణాంకం	ssh_కూడు_తటస్థం_constrained(పూర్ణాంకం sock, నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి అక్షరం *comment, u_int life, u_int confirm, స్థిరరాశి అక్షరం *provider,
    నిర్మాణం dest_constraint **dest_constraints, కొలత_t ndest_constraints);
పూర్ణాంకం	ssh_agent_has_కీలకం(పూర్ణాంకం sock, స్థిరరాశి నిర్మాణం sshkey *కీలకం);
పూర్ణాంకం	ssh_remove_తటస్థం(పూర్ణాంకం sock, స్థిరరాశి నిర్మాణం sshkey *కీలకం);
పూర్ణాంకం	ssh_update_card(పూర్ణాంకం sock, పూర్ణాంకం కూడు, స్థిరరాశి అక్షరం *reader_id,
	    స్థిరరాశి అక్షరం *pin, u_int life, u_int confirm,
	    నిర్మాణం dest_constraint **dest_constraints,
	    కొలత_t ndest_constraints,
	    పూర్ణాంకం cert_only, నిర్మాణం sshkey **certs, కొలత_t ncerts);
పూర్ణాంకం	ssh_remove_all_identities(పూర్ణాంకం sock, పూర్ణాంకం సంస్కరణ);

పూర్ణాంకం	ssh_agent_sign(పూర్ణాంకం sock, స్థిరరాశి నిర్మాణం sshkey *కీలకం,
	    u_char **sigp, కొలత_t *lenp,
	    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen, స్థిరరాశి అక్షరం *alg, u_int compat);

పూర్ణాంకం	ssh_agent_bind_hostkey(పూర్ణాంకం sock, స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి నిర్మాణం sshbuf *session_id, స్థిరరాశి నిర్మాణం sshbuf *signature,
    పూర్ణాంకం forwarding);

పూర్ణాంకం	ssh_agent_query_extensions(పూర్ణాంకం sock, అక్షరం ***exts);

/* Messages for the authentication agent connection. */
#నిర్వచించు SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#నిర్వచించు SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#నిర్వచించు SSH_AGENTC_RSA_CHALLENGE		3
#నిర్వచించు SSH_AGENT_RSA_RESPONSE			4
#నిర్వచించు SSH_AGENT_FAILURE			5
#నిర్వచించు SSH_AGENT_SUCCESS			6
#నిర్వచించు SSH_AGENTC_కూడు_RSA_తటస్థం		7
#నిర్వచించు SSH_AGENTC_REMOVE_RSA_తటస్థం		8
#నిర్వచించు SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#నిర్వచించు SSH2_AGENTC_REQUEST_IDENTITIES		11
#నిర్వచించు SSH2_AGENT_IDENTITIES_ANSWER		12
#నిర్వచించు SSH2_AGENTC_SIGN_REQUEST		13
#నిర్వచించు SSH2_AGENT_SIGN_RESPONSE		14
#నిర్వచించు SSH2_AGENTC_కూడు_తటస్థం		17
#నిర్వచించు SSH2_AGENTC_REMOVE_తటస్థం		18
#నిర్వచించు SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#నిర్వచించు SSH_AGENTC_కూడు_SMARTCARD_కీలకం		20
#నిర్వచించు SSH_AGENTC_REMOVE_SMARTCARD_కీలకం		21

/* lock/unlock the agent */
#నిర్వచించు SSH_AGENTC_తాళం				22
#నిర్వచించు SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#నిర్వచించు SSH_AGENTC_కూడు_RSA_ID_CONSTRAINED	24
#నిర్వచించు SSH2_AGENTC_కూడు_ID_CONSTRAINED		25
#నిర్వచించు SSH_AGENTC_కూడు_SMARTCARD_కీలకం_CONSTRAINED 26

/* generic extension mechanism */
#నిర్వచించు SSH_AGENTC_EXTENSION			27
#నిర్వచించు SSH_AGENT_EXTENSION_FAILURE		28
#నిర్వచించు SSH_AGENT_EXTENSION_RESPONSE		29

#నిర్వచించు	SSH_AGENT_CONSTRAIN_LIFETIME		1
#నిర్వచించు	SSH_AGENT_CONSTRAIN_CONFIRM		2
#నిర్వచించు	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#నిర్వచించు SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#నిర్వచించు SSH_COM_AGENT2_FAILURE			102

#నిర్వచించు	SSH_AGENT_OLD_SIGNATURE			0x01
#నిర్వచించు	SSH_AGENT_RSA_SHA2_256			0x02
#నిర్వచించు	SSH_AGENT_RSA_SHA2_512			0x04

#అయితే_ముగింపు				/* AUTHFD_H */
