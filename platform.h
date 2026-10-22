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

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <pwd.h>

શૂન્ય platform_pre_listen(શૂન્ય);
શૂન્ય platform_pre_fork(શૂન્ય);
શૂન્ય platform_pre_restart(શૂન્ય);
શૂન્ય platform_post_listen(શૂન્ય);
શૂન્ય platform_post_fork_parent(pid_t child_pid);
શૂન્ય platform_post_fork_child(શૂન્ય);
શૂન્ય platform_pre_session_start(શૂન્ય);
પૂર્ણાંક  platform_privileged_uidswap(શૂન્ય);
શૂન્ય platform_setusercontext(સંરચના passwd *);
શૂન્ય platform_setusercontext_post_groups(સંરચના passwd *);
અક્ષર *platform_get_krb5_client(અચલ અક્ષર *);
અક્ષર *platform_krb5_get_principal_name(અચલ અક્ષર *);
પૂર્ણાંક platform_locked_account(સંરચના passwd *);
પૂર્ણાંક platform_sys_dir_uid(uid_t);
શૂન્ય platform_disable_tracing(પૂર્ણાંક);

/* in platform-pledge.c */
શૂન્ય platform_pledge_agent(શૂન્ય);
શૂન્ય platform_pledge_sftp_server(શૂન્ય);
શૂન્ય platform_pledge_mux(શૂન્ય);
