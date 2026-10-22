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

#اگر_غیر_تعریف_شدہ AUTHFD_H
#تعریف_کرو AUTHFD_H

ساخت sshbuf;
ساخت sshkey;

/* List of identities returned by ssh_fetch_identitylist() */
ساخت ssh_identitylist {
	سائز_t nkeys;
	ساخت sshkey **کلیدیں;
	حرف **comments;
};

/* Key destination restrictions */
ساخت dest_constraint_hop {
	حرف *user;	/* wildcards allowed */
	حرف *hostname; /* used to matching cert principals and for display */
	صحیح is_ca;
	u_int nkeys;	/* number of entries in *both* 'keys' and 'key_is_ca' */
	ساخت sshkey **کلیدیں;
	صحیح *کلید_is_ca;
};
ساخت dest_constraint {
	ساخت dest_constraint_hop from;
	ساخت dest_constraint_hop مقصد;
};

صحیح	ssh_get_authentication_socket(صحیح *fdp);
صحیح	ssh_get_authentication_socket_راستہ(ثابت حرف *authsocket, صحیح *fdp);
خالی	ssh_close_authentication_socket(صحیح sock);

صحیح	ssh_تالا_agent(صحیح sock, صحیح تالا, ثابت حرف *password);
صحیح	ssh_fetch_identitylist(صحیح sock, ساخت ssh_identitylist **idlp);
خالی	ssh_free_identitylist(ساخت ssh_identitylist *idl);
صحیح	ssh_جوڑو_شناختی_عنصر_constrained(صحیح sock, ساخت sshkey *کلید,
    ثابت حرف *comment, u_int life, u_int confirm, ثابت حرف *provider,
    ساخت dest_constraint **dest_constraints, سائز_t ndest_constraints);
صحیح	ssh_agent_has_کلید(صحیح sock, ثابت ساخت sshkey *کلید);
صحیح	ssh_remove_شناختی_عنصر(صحیح sock, ثابت ساخت sshkey *کلید);
صحیح	ssh_update_card(صحیح sock, صحیح جوڑو, ثابت حرف *reader_id,
	    ثابت حرف *pin, u_int life, u_int confirm,
	    ساخت dest_constraint **dest_constraints,
	    سائز_t ndest_constraints,
	    صحیح cert_only, ساخت sshkey **certs, سائز_t ncerts);
صحیح	ssh_remove_all_identities(صحیح sock, صحیح نسخہ);

صحیح	ssh_agent_sign(صحیح sock, ثابت ساخت sshkey *کلید,
	    u_char **sigp, سائز_t *lenp,
	    ثابت u_char *ڈیٹا, سائز_t datalen, ثابت حرف *alg, u_int compat);

صحیح	ssh_agent_bind_hostkey(صحیح sock, ثابت ساخت sshkey *کلید,
    ثابت ساخت sshbuf *session_id, ثابت ساخت sshbuf *signature,
    صحیح forwarding);

صحیح	ssh_agent_query_extensions(صحیح sock, حرف ***exts);

/* Messages for the authentication agent connection. */
#تعریف_کرو SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#تعریف_کرو SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#تعریف_کرو SSH_AGENTC_RSA_CHALLENGE		3
#تعریف_کرو SSH_AGENT_RSA_RESPONSE			4
#تعریف_کرو SSH_AGENT_FAILURE			5
#تعریف_کرو SSH_AGENT_SUCCESS			6
#تعریف_کرو SSH_AGENTC_جوڑو_RSA_شناختی_عنصر		7
#تعریف_کرو SSH_AGENTC_REMOVE_RSA_شناختی_عنصر		8
#تعریف_کرو SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#تعریف_کرو SSH2_AGENTC_REQUEST_IDENTITIES		11
#تعریف_کرو SSH2_AGENT_IDENTITIES_ANSWER		12
#تعریف_کرو SSH2_AGENTC_SIGN_REQUEST		13
#تعریف_کرو SSH2_AGENT_SIGN_RESPONSE		14
#تعریف_کرو SSH2_AGENTC_جوڑو_شناختی_عنصر		17
#تعریف_کرو SSH2_AGENTC_REMOVE_شناختی_عنصر		18
#تعریف_کرو SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#تعریف_کرو SSH_AGENTC_جوڑو_SMARTCARD_کلید		20
#تعریف_کرو SSH_AGENTC_REMOVE_SMARTCARD_کلید		21

/* lock/unlock the agent */
#تعریف_کرو SSH_AGENTC_تالا				22
#تعریف_کرو SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#تعریف_کرو SSH_AGENTC_جوڑو_RSA_ID_CONSTRAINED	24
#تعریف_کرو SSH2_AGENTC_جوڑو_ID_CONSTRAINED		25
#تعریف_کرو SSH_AGENTC_جوڑو_SMARTCARD_کلید_CONSTRAINED 26

/* generic extension mechanism */
#تعریف_کرو SSH_AGENTC_EXTENSION			27
#تعریف_کرو SSH_AGENT_EXTENSION_FAILURE		28
#تعریف_کرو SSH_AGENT_EXTENSION_RESPONSE		29

#تعریف_کرو	SSH_AGENT_CONSTRAIN_LIFETIME		1
#تعریف_کرو	SSH_AGENT_CONSTRAIN_CONFIRM		2
#تعریف_کرو	SSH_AGENT_CONSTRAIN_EXTENSION		255

/* extended failure messages */
#تعریف_کرو SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#تعریف_کرو SSH_COM_AGENT2_FAILURE			102

#تعریف_کرو	SSH_AGENT_OLD_SIGNATURE			0x01
#تعریف_کرو	SSH_AGENT_RSA_SHA2_256			0x02
#تعریف_کرو	SSH_AGENT_RSA_SHA2_512			0x04

#اگر_ختم				/* AUTHFD_H */
