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

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <pwd.h>

வெறுமை platform_pre_listen(வெறுமை);
வெறுமை platform_pre_fork(வெறுமை);
வெறுமை platform_pre_restart(வெறுமை);
வெறுமை platform_post_listen(வெறுமை);
வெறுமை platform_post_fork_parent(pid_t child_pid);
வெறுமை platform_post_fork_child(வெறுமை);
வெறுமை platform_pre_session_start(வெறுமை);
முழு  platform_privileged_uidswap(வெறுமை);
வெறுமை platform_setusercontext(கட்டமைப்பு passwd *);
வெறுமை platform_setusercontext_post_groups(கட்டமைப்பு passwd *);
எழுத்து *platform_get_krb5_client(மாறிலி எழுத்து *);
எழுத்து *platform_krb5_get_principal_name(மாறிலி எழுத்து *);
முழு platform_locked_account(கட்டமைப்பு passwd *);
முழு platform_sys_dir_uid(uid_t);
வெறுமை platform_disable_tracing(முழு);

/* in platform-pledge.c */
வெறுமை platform_pledge_agent(வெறுமை);
வெறுமை platform_pledge_sftp_server(வெறுமை);
வெறுமை platform_pledge_mux(வெறுமை);
