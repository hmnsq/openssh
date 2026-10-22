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

تهی platform_pre_listen(تهی);
تهی platform_pre_fork(تهی);
تهی platform_pre_restart(تهی);
تهی platform_post_listen(تهی);
تهی platform_post_fork_parent(pid_t child_pid);
تهی platform_post_fork_child(تهی);
تهی platform_pre_session_start(تهی);
صحیح  platform_privileged_uidswap(تهی);
تهی platform_setusercontext(ساختار passwd *);
تهی platform_setusercontext_post_groups(ساختار passwd *);
نویسه *platform_get_krb5_client(ثابت نویسه *);
نویسه *platform_krb5_get_principal_name(ثابت نویسه *);
صحیح platform_locked_account(ساختار passwd *);
صحیح platform_sys_dir_uid(uid_t);
تهی platform_disable_tracing(صحیح);

/* in platform-pledge.c */
تهی platform_pledge_agent(تهی);
تهی platform_pledge_sftp_server(تهی);
تهی platform_pledge_mux(تهی);
