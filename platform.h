/*
 * Copyright (c) 2006 Darren Tucker.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <pwd.h>

ശൂന്യം platform_pre_listen(ശൂന്യം);
ശൂന്യം platform_pre_fork(ശൂന്യം);
ശൂന്യം platform_pre_restart(ശൂന്യം);
ശൂന്യം platform_post_listen(ശൂന്യം);
ശൂന്യം platform_post_fork_parent(pid_t child_pid);
ശൂന്യം platform_post_fork_child(ശൂന്യം);
ശൂന്യം platform_pre_session_start(ശൂന്യം);
പൂർണ്ണസംഖ്യ  platform_privileged_uidswap(ശൂന്യം);
ശൂന്യം platform_setusercontext(ഘടന passwd *);
ശൂന്യം platform_setusercontext_post_groups(ഘടന passwd *);
അക്ഷരം *platform_get_krb5_client(സ്ഥിരം അക്ഷരം *);
അക്ഷരം *platform_krb5_get_principal_name(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ platform_locked_account(ഘടന passwd *);
പൂർണ്ണസംഖ്യ platform_sys_dir_uid(uid_t);
ശൂന്യം platform_disable_tracing(പൂർണ്ണസംഖ്യ);

/* in platform-pledge.c */
ശൂന്യം platform_pledge_agent(ശൂന്യം);
ശൂന്യം platform_pledge_sftp_server(ശൂന്യം);
ശൂന്യം platform_pledge_mux(ശൂന്യം);
