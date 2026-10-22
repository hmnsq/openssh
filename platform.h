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

#समावेश <sys/types.h>

#समावेश <pwd.h>

व्योम platform_pre_listen(व्योम);
व्योम platform_pre_fork(व्योम);
व्योम platform_pre_restart(व्योम);
व्योम platform_post_listen(व्योम);
व्योम platform_post_fork_parent(pid_t child_pid);
व्योम platform_post_fork_child(व्योम);
व्योम platform_pre_session_start(व्योम);
पूर्णांक  platform_privileged_uidswap(व्योम);
व्योम platform_setusercontext(काष्ठा passwd *);
व्योम platform_setusercontext_post_groups(काष्ठा passwd *);
अक्षर *platform_get_krb5_client(स्थिर अक्षर *);
अक्षर *platform_krb5_get_principal_name(स्थिर अक्षर *);
पूर्णांक platform_locked_account(काष्ठा passwd *);
पूर्णांक platform_sys_dir_uid(uid_t);
व्योम platform_disable_tracing(पूर्णांक);

/* in platform-pledge.c */
व्योम platform_pledge_agent(व्योम);
व्योम platform_pledge_sftp_server(व्योम);
व्योम platform_pledge_mux(व्योम);
