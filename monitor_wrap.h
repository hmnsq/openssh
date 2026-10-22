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

എണ്ണൽ mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

ഘടന ssh;
ഘടന monitor;
ഘടന Authctxt;
ഘടന sshkey;
ഘടന sshauthopt;
ഘടന sshkey_sig_details;

ശൂന്യം mm_log_handler(LogLevel, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, ശൂന്യം *);
പൂർണ്ണസംഖ്യ mm_is_monitor(ശൂന്യം);
#ifdef WITH_OPENSSL
DH *mm_choose_dh(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
#endif
ശൂന്യം mm_sshkey_setcompat(ഘടന ssh *);
പൂർണ്ണസംഖ്യ mm_sshkey_sign(ഘടന ssh *, ഘടന sshkey *, u_char **, size_t *,
    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, u_int compat);
ശൂന്യം mm_inform_authserv(അക്ഷരം *, അക്ഷരം *);
ഘടന passwd *mm_getpwnamallow(ഘടന ssh *, സ്ഥിരം അക്ഷരം *);
അക്ഷരം *mm_auth2_read_banner(ശൂന്യം);
പൂർണ്ണസംഖ്യ mm_auth_password(ഘടന ssh *, അക്ഷരം *);
പൂർണ്ണസംഖ്യ mm_താക്കോൽ_allowed(എണ്ണൽ mm_keytype, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന sshkey *,
    പൂർണ്ണസംഖ്യ, ഘടന sshauthopt **);
പൂർണ്ണസംഖ്യ mm_user_താക്കോൽ_allowed(ഘടന ssh *ssh, ഘടന passwd *, ഘടന sshkey *, പൂർണ്ണസംഖ്യ,
    ഘടന sshauthopt **);
പൂർണ്ണസംഖ്യ mm_hostbased_താക്കോൽ_allowed(ഘടന ssh *, ഘടന passwd *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, ഘടന sshkey *);
പൂർണ്ണസംഖ്യ mm_sshkey_verify(സ്ഥിരം ഘടന sshkey *, സ്ഥിരം u_char *, size_t,
    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *, u_int, ഘടന sshkey_sig_details **);

ശൂന്യം mm_decode_activate_server_options(ഘടന ssh *ssh, ഘടന sshbuf *m);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
പൂർണ്ണസംഖ്യ mm_ssh_gssapi_userok(അക്ഷരം *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
ശൂന്യം mm_start_pam(ഘടന ssh *ssh);
u_int mm_do_pam_account(ശൂന്യം);
ശൂന്യം *mm_sshpam_init_ctx(ഘടന Authctxt *);
പൂർണ്ണസംഖ്യ mm_sshpam_query(ശൂന്യം *, അക്ഷരം **, അക്ഷരം **, u_int *, അക്ഷരം ***, u_int **);
പൂർണ്ണസംഖ്യ mm_sshpam_respond(ശൂന്യം *, u_int, അക്ഷരം **);
ശൂന്യം mm_sshpam_free_ctx(ശൂന്യം *);
#endif

#ifdef SSH_AUDIT_EVENTS
#അന്തര്ഭാവ "audit.h"
ശൂന്യം mm_audit_event(ഘടന ssh *, ssh_audit_event_t);
ശൂന്യം mm_audit_run_command(സ്ഥിരം അക്ഷരം *);
#endif

ഘടന Session;
ശൂന്യം mm_terminate(ശൂന്യം);
പൂർണ്ണസംഖ്യ mm_pty_allocate(പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ *, അക്ഷരം *, size_t);
ശൂന്യം mm_session_pty_cleanup2(ഘടന Session *);

ശൂന്യം mm_send_keystate(ഘടന ssh *, ഘടന monitor*);

/* state */
ഘടന ServerOptions;
ശൂന്യം mm_get_state(ഘടന ssh *, ഘടന ServerOptions *,
    ഘടന sshbuf **, uint64_t *, ഘടന sshbuf **, ഘടന sshbuf **,
    u_char **, ഘടന sshbuf **, ഘടന sshbuf **);

/* bsdauth */
പൂർണ്ണസംഖ്യ mm_bsdauth_query(ശൂന്യം *, അക്ഷരം **, അക്ഷരം **, u_int *, അക്ഷരം ***, u_int **);
പൂർണ്ണസംഖ്യ mm_bsdauth_respond(ശൂന്യം *, u_int, അക്ഷരം **);

/* config / channels glue */
ശൂന്യം	 server_process_permitopen(ഘടന ssh *);
ശൂന്യം	 server_process_channel_timeouts(ഘടന ssh *ssh);
ഘടന connection_info *
	 server_get_connection_info(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);

#endif /* _MM_WRAP_H_ */
