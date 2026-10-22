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

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <pwd.h>

শূন্য platform_pre_listen(শূন্য);
শূন্য platform_pre_fork(শূন্য);
শূন্য platform_pre_restart(শূন্য);
শূন্য platform_post_listen(শূন্য);
শূন্য platform_post_fork_parent(pid_t child_pid);
শূন্য platform_post_fork_child(শূন্য);
শূন্য platform_pre_session_start(শূন্য);
পূর্ণাঙ্ক  platform_privileged_uidswap(শূন্য);
শূন্য platform_setusercontext(সংরচনা passwd *);
শূন্য platform_setusercontext_post_groups(সংরচনা passwd *);
বর্ণ *platform_get_krb5_client(ধ্রুব বর্ণ *);
বর্ণ *platform_krb5_get_principal_name(ধ্রুব বর্ণ *);
পূর্ণাঙ্ক platform_locked_account(সংরচনা passwd *);
পূর্ণাঙ্ক platform_sys_dir_uid(uid_t);
শূন্য platform_disable_tracing(পূর্ণাঙ্ক);

/* in platform-pledge.c */
শূন্য platform_pledge_agent(শূন্য);
শূন্য platform_pledge_sftp_server(শূন্য);
শূন্য platform_pledge_mux(শূন্য);
