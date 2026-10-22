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

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <pwd.h>

ଶୂନ୍ୟ platform_pre_listen(ଶୂନ୍ୟ);
ଶୂନ୍ୟ platform_pre_fork(ଶୂନ୍ୟ);
ଶୂନ୍ୟ platform_pre_restart(ଶୂନ୍ୟ);
ଶୂନ୍ୟ platform_post_listen(ଶୂନ୍ୟ);
ଶୂନ୍ୟ platform_post_fork_parent(pid_t child_pid);
ଶୂନ୍ୟ platform_post_fork_child(ଶୂନ୍ୟ);
ଶୂନ୍ୟ platform_pre_session_start(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା  platform_privileged_uidswap(ଶୂନ୍ୟ);
ଶୂନ୍ୟ platform_setusercontext(ସଂରଚନା passwd *);
ଶୂନ୍ୟ platform_setusercontext_post_groups(ସଂରଚନା passwd *);
ଅକ୍ଷର *platform_get_krb5_client(ଅଚଳ ଅକ୍ଷର *);
ଅକ୍ଷର *platform_krb5_get_principal_name(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା platform_locked_account(ସଂରଚନା passwd *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା platform_sys_dir_uid(uid_t);
ଶୂନ୍ୟ platform_disable_tracing(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* in platform-pledge.c */
ଶୂନ୍ୟ platform_pledge_agent(ଶୂନ୍ୟ);
ଶୂନ୍ୟ platform_pledge_sftp_server(ଶୂନ୍ୟ);
ଶୂନ୍ୟ platform_pledge_mux(ଶୂନ୍ୟ);
