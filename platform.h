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

#شامل <sys/types.h>

#شامل <pwd.h>

خالی platform_pre_listen(خالی);
خالی platform_pre_fork(خالی);
خالی platform_pre_restart(خالی);
خالی platform_post_listen(خالی);
خالی platform_post_fork_والد(pid_t بچہ_pid);
خالی platform_post_fork_بچہ(خالی);
خالی platform_pre_session_آغاز(خالی);
صحیح  platform_privileged_uidswap(خالی);
خالی platform_setusercontext(ساخت passwd *);
خالی platform_setusercontext_post_groups(ساخت passwd *);
حرف *platform_get_krb5_client(ثابت حرف *);
حرف *platform_krb5_get_principal_name(ثابت حرف *);
صحیح platform_locked_account(ساخت passwd *);
صحیح platform_sys_dir_uid(uid_t);
خالی platform_disable_tracing(صحیح);

/* in platform-pledge.c */
خالی platform_pledge_agent(خالی);
خالی platform_pledge_sftp_server(خالی);
خالی platform_pledge_mux(خالی);
