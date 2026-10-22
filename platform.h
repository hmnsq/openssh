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

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>

ਖਾਲੀ platform_pre_listen(ਖਾਲੀ);
ਖਾਲੀ platform_pre_fork(ਖਾਲੀ);
ਖਾਲੀ platform_pre_restart(ਖਾਲੀ);
ਖਾਲੀ platform_post_listen(ਖਾਲੀ);
ਖਾਲੀ platform_post_fork_ਮਾਪਾ(pid_t ਬੱਚਾ_pid);
ਖਾਲੀ platform_post_fork_ਬੱਚਾ(ਖਾਲੀ);
ਖਾਲੀ platform_pre_session_ਸ਼ੁਰੂ(ਖਾਲੀ);
ਪੂਰਨ  platform_privileged_uidswap(ਖਾਲੀ);
ਖਾਲੀ platform_setusercontext(ਬਣਤਰ passwd *);
ਖਾਲੀ platform_setusercontext_post_groups(ਬਣਤਰ passwd *);
ਅੱਖਰ *platform_get_krb5_client(ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ *platform_krb5_get_principal_name(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ platform_locked_account(ਬਣਤਰ passwd *);
ਪੂਰਨ platform_sys_dir_uid(uid_t);
ਖਾਲੀ platform_disable_tracing(ਪੂਰਨ);

/* in platform-pledge.c */
ਖਾਲੀ platform_pledge_agent(ਖਾਲੀ);
ਖਾਲੀ platform_pledge_sftp_server(ਖਾਲੀ);
ਖਾਲੀ platform_pledge_mux(ਖਾਲੀ);
