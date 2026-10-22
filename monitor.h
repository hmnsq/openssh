/* $OpenBSD: monitor.h,v 1.28 2026/03/02 02:40:15 djm Exp $ */

/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
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

#ifndef _MONITOR_H_
#define _MONITOR_H_

/* Please keep *_REQ_* values on even numbers and *_ANS_* on odd numbers */
ગણના monitor_reqtype {
	MONITOR_REQ_MODULI = 0, MONITOR_ANS_MODULI = 1,
	MONITOR_REQ_FREE = 2,
	MONITOR_REQ_AUTHSERV = 4,
	MONITOR_REQ_SIGN = 6, MONITOR_ANS_SIGN = 7,
	MONITOR_REQ_PWNAM = 8, MONITOR_ANS_PWNAM = 9,
	MONITOR_REQ_AUTH2_READ_BANNER = 10, MONITOR_ANS_AUTH2_READ_BANNER = 11,
	MONITOR_REQ_AUTHPASSWORD = 12, MONITOR_ANS_AUTHPASSWORD = 13,
	MONITOR_REQ_BSDAUTHQUERY = 14, MONITOR_ANS_BSDAUTHQUERY = 15,
	MONITOR_REQ_BSDAUTHRESPOND = 16, MONITOR_ANS_BSDAUTHRESPOND = 17,
	MONITOR_REQ_SETCOMPAT = 18,
	MONITOR_REQ_KEYALLOWED = 22, MONITOR_ANS_KEYALLOWED = 23,
	MONITOR_REQ_KEYVERIFY = 24, MONITOR_ANS_KEYVERIFY = 25,
	MONITOR_REQ_KEYEXPORT = 26,
	MONITOR_REQ_PTY = 28, MONITOR_ANS_PTY = 29,
	MONITOR_REQ_PTYCLEANUP = 30,
	MONITOR_REQ_SESSKEY = 32, MONITOR_ANS_SESSKEY = 33,
	MONITOR_REQ_SESSID = 34,
	MONITOR_REQ_RSAKEYALLOWED = 36, MONITOR_ANS_RSAKEYALLOWED = 37,
	MONITOR_REQ_RSACHALLENGE = 38, MONITOR_ANS_RSACHALLENGE = 39,
	MONITOR_REQ_RSARESPONSE = 40, MONITOR_ANS_RSARESPONSE = 41,
	MONITOR_REQ_GSSSETUP = 42, MONITOR_ANS_GSSSETUP = 43,
	MONITOR_REQ_GSSSTEP = 44, MONITOR_ANS_GSSSTEP = 45,
	MONITOR_REQ_GSSUSEROK = 46, MONITOR_ANS_GSSUSEROK = 47,
	MONITOR_REQ_GSSCHECKMIC = 48, MONITOR_ANS_GSSCHECKMIC = 49,
	MONITOR_REQ_TERM = 50,
	MONITOR_REQ_STATE = 51, MONITOR_ANS_STATE = 52,

	MONITOR_REQ_PAM_START = 100,
	MONITOR_REQ_PAM_ACCOUNT = 102, MONITOR_ANS_PAM_ACCOUNT = 103,
	MONITOR_REQ_PAM_INIT_CTX = 104, MONITOR_ANS_PAM_INIT_CTX = 105,
	MONITOR_REQ_PAM_QUERY = 106, MONITOR_ANS_PAM_QUERY = 107,
	MONITOR_REQ_PAM_RESPOND = 108, MONITOR_ANS_PAM_RESPOND = 109,
	MONITOR_REQ_PAM_FREE_CTX = 110, MONITOR_ANS_PAM_FREE_CTX = 111,
	MONITOR_REQ_AUDIT_EVENT = 112, MONITOR_REQ_AUDIT_COMMAND = 113,

};

સંરચના ssh;
સંરચના sshbuf;

સંરચના monitor {
	પૂર્ણાંક			 m_recvfd;
	પૂર્ણાંક			 m_sendfd;
	પૂર્ણાંક			 m_log_recvfd;
	પૂર્ણાંક			 m_log_sendfd;
	સંરચના kex		**m_pkex;
	pid_t			 m_pid;
};

સંરચના monitor *monitor_init(શૂન્ય);
શૂન્ય monitor_reinit(સંરચના monitor *);

સંરચના Authctxt;
શૂન્ય monitor_child_preauth(સંરચના ssh *, સંરચના monitor *);
શૂન્ય monitor_child_postauth(સંરચના ssh *, સંરચના monitor *);

શૂન્ય monitor_clear_keystate(સંરચના ssh *, સંરચના monitor *);
શૂન્ય monitor_apply_keystate(સંરચના ssh *, સંરચના monitor *);

પૂર્ણાંક  monitor_auth_attempted(શૂન્ય);
પૂર્ણાંક  monitor_invalid_user(શૂન્ય);

/* Prototypes for request sending and receiving */
શૂન્ય mm_request_send(પૂર્ણાંક, ગણના monitor_reqtype, સંરચના sshbuf *);
શૂન્ય mm_request_receive(પૂર્ણાંક, સંરચના sshbuf *);
શૂન્ય mm_request_receive_expect(પૂર્ણાંક, ગણના monitor_reqtype, સંરચના sshbuf *);
શૂન્ય mm_get_keystate(સંરચના ssh *, સંરચના monitor *);

/* XXX: should be returned via a monitor call rather than config_fd */
શૂન્ય mm_encode_server_options(સંરચના sshbuf *);

સંરચના sshbuf *pack_hostkeys(શૂન્ય);

#endif /* _MONITOR_H_ */
