/* $OpenBSD: monitor_wrap.h,v 1.55 2026/05/31 11:30:50 djm Exp $ */

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

#ifndef _MM_WRAP_H_
#define _MM_WRAP_H_

#define MONITOR_MAX_MSGLEN		(4 * 1024 * 1024)
/* The configuration has to fit in a monitor message along with other state */
#define MONITOR_MAX_CFGLEN		(MONITOR_MAX_MSGLEN - (64 * 1024))

எண்ணிக்கை mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

கட்டமைப்பு ssh;
கட்டமைப்பு monitor;
கட்டமைப்பு Authctxt;
கட்டமைப்பு sshkey;
கட்டமைப்பு sshauthopt;
கட்டமைப்பு sshkey_sig_details;

வெறுமை mm_log_handler(LogLevel, முழு, மாறிலி எழுத்து *, வெறுமை *);
முழு mm_is_monitor(வெறுமை);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(முழு, முழு, முழு);
#endif
வெறுமை mm_sshkey_setcompat(கட்டமைப்பு ssh *);
முழு mm_sshkey_sign(கட்டமைப்பு ssh *, கட்டமைப்பு sshkey *, u_char **, size_t *,
    மாறிலி u_char *, size_t, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, u_int compat);
வெறுமை mm_inform_authserv(எழுத்து *, எழுத்து *);
கட்டமைப்பு passwd *mm_getpwnamallow(கட்டமைப்பு ssh *, மாறிலி எழுத்து *);
எழுத்து *mm_auth2_read_banner(வெறுமை);
முழு mm_auth_password(கட்டமைப்பு ssh *, எழுத்து *);
முழு mm_சாவி_allowed(எண்ணிக்கை mm_keytype, மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு sshkey *,
    முழு, கட்டமைப்பு sshauthopt **);
முழு mm_user_சாவி_allowed(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *, கட்டமைப்பு sshkey *, முழு,
    கட்டமைப்பு sshauthopt **);
முழு mm_hostbased_சாவி_allowed(கட்டமைப்பு ssh *, கட்டமைப்பு passwd *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, கட்டமைப்பு sshkey *);
முழு mm_sshkey_verify(மாறிலி கட்டமைப்பு sshkey *, மாறிலி u_char *, size_t,
    மாறிலி u_char *, size_t, மாறிலி எழுத்து *, u_int, கட்டமைப்பு sshkey_sig_details **);

வெறுமை mm_decode_activate_server_options(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
முழு mm_ssh_gssapi_userok(எழுத்து *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
வெறுமை mm_start_pam(கட்டமைப்பு ssh *ssh);
u_int mm_do_pam_account(வெறுமை);
வெறுமை *mm_sshpam_init_ctx(கட்டமைப்பு Authctxt *);
முழு mm_sshpam_query(வெறுமை *, எழுத்து **, எழுத்து **, u_int *, எழுத்து ***, u_int **);
முழு mm_sshpam_respond(வெறுமை *, u_int, எழுத்து **);
வெறுமை mm_sshpam_free_ctx(வெறுமை *);
#endif

#ifdef SSH_AUDIT_EVENTS
#அந்தர்பாவ "audit.h"
வெறுமை mm_audit_event(கட்டமைப்பு ssh *, ssh_audit_event_t);
வெறுமை mm_audit_run_command(மாறிலி எழுத்து *);
#endif

கட்டமைப்பு Session;
வெறுமை mm_terminate(வெறுமை);
முழு mm_pty_allocate(முழு *, முழு *, எழுத்து *, size_t);
வெறுமை mm_session_pty_cleanup2(கட்டமைப்பு Session *);

வெறுமை mm_send_keystate(கட்டமைப்பு ssh *, கட்டமைப்பு monitor*);

/* state */
கட்டமைப்பு ServerOptions;
வெறுமை mm_get_state(கட்டமைப்பு ssh *, கட்டமைப்பு ServerOptions *,
    கட்டமைப்பு sshbuf **, uint64_t *, கட்டமைப்பு sshbuf **, கட்டமைப்பு sshbuf **,
    u_char **, கட்டமைப்பு sshbuf **, கட்டமைப்பு sshbuf **);

/* bsdauth */
முழு mm_bsdauth_query(வெறுமை *, எழுத்து **, எழுத்து **, u_int *, எழுத்து ***, u_int **);
முழு mm_bsdauth_respond(வெறுமை *, u_int, எழுத்து **);

/* config / channels glue */
வெறுமை	 server_process_permitopen(கட்டமைப்பு ssh *);
வெறுமை	 server_process_channel_timeouts(கட்டமைப்பு ssh *ssh);
கட்டமைப்பு connection_info *
	 server_get_connection_info(கட்டமைப்பு ssh *, முழு, முழு);

#endif /* _MM_WRAP_H_ */
