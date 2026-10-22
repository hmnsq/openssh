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

#ضمن <sys/types.h>

#ضمن <pwd.h>

فراغ platform_pre_listen(فراغ);
فراغ platform_pre_fork(فراغ);
فراغ platform_pre_restart(فراغ);
فراغ platform_post_listen(فراغ);
فراغ platform_post_fork_والد(pid_t فرزند_pid);
فراغ platform_post_fork_فرزند(فراغ);
فراغ platform_pre_session_شروع(فراغ);
صحيح  platform_privileged_uidswap(فراغ);
فراغ platform_setusercontext(بنية passwd *);
فراغ platform_setusercontext_post_groups(بنية passwd *);
حرف *platform_get_krb5_client(ثابت حرف *);
حرف *platform_krb5_get_principal_name(ثابت حرف *);
صحيح platform_locked_account(بنية passwd *);
صحيح platform_sys_dir_uid(uid_t);
فراغ platform_disable_tracing(صحيح);

/* in platform-pledge.c */
فراغ platform_pledge_agent(فراغ);
فراغ platform_pledge_sftp_server(فراغ);
فراغ platform_pledge_mux(فراغ);
