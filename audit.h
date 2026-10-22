/*
 * Copyright (c) 2004, 2005 Darren Tucker.  All rights reserved.
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

#اگر_تعریف_نشده _SSH_AUDIT_H
# define _SSH_AUDIT_H

#ضمن "loginrec.h"

بنية ssh;

تعداد ssh_audit_event_type {
	SSH_LOGIN_EXCEED_MAXTRIES,
	SSH_LOGIN_ریشه_DENIED,
	SSH_AUTH_SUCCESS,
	SSH_AUTH_FAIL_NONE,
	SSH_AUTH_FAIL_PASSWD,
	SSH_AUTH_FAIL_KBDINT,	/* keyboard-interactive or challenge-response */
	SSH_AUTH_FAIL_PUBKEY,	/* ssh2 pubkey or ssh1 rsa */
	SSH_AUTH_FAIL_HOSTBASED,	/* ssh2 hostbased or ssh1 rhostsrsa */
	SSH_AUTH_FAIL_GSSAPI,
	SSH_INVALID_USER,
	SSH_NOLOGIN,		/* denied by /etc/nologin, not implemented */
	SSH_CONNECTION_CLOSE,	/* closed after attempting auth or session */
	SSH_CONNECTION_ABANDON,	/* closed without completing auth */
	SSH_AUDIT_UNKNOWN
};
تعريفنوع تعداد ssh_audit_event_type ssh_audit_event_t;

فراغ	audit_connection_from(ثابت حرف *, صحيح);
فراغ	audit_event(بنية ssh *, ssh_audit_event_t);
فراغ	audit_session_open(بنية logininfo *);
فراغ	audit_session_close(بنية logininfo *);
فراغ	audit_پیاپی_command(ثابت حرف *);
ssh_audit_event_t audit_classify_auth(ثابت حرف *);

#پایان_اگر /* _SSH_AUDIT_H */
