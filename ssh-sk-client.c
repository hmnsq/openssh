/* $OpenBSD: ssh-sk-client.c,v 1.18 2026/03/11 09:10:59 dtucker Exp $ */
/*
 * Copyright (c) 2019 Google LLC
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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/wait.h>

#شامل <limits.h>
#شامل <errno.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <fcntl.h>

#شامل "log.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "msg.h"
#شامل "pathnames.h"
#شامل "ssh-sk.h"
#شامل "misc.h"

/* #define DEBUG_SK 1 */

ساکن صحیح
آغاز_helper(صحیح *fdp, pid_t *pidp, خالی (**osigchldp)(صحیح))
{
	خالی (*osigchld)(صحیح);
	صحیح oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	حرف execbuf[100], *helper, *verbosity = تہی;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	اگر (helper == تہی || لڑی_لمبائی(helper) == 0)
		helper = راستہ_SSH_SK_HELPER;
#اگر_تعریف_شدہ DEBUG_SK
	verbosity = "-vvv";
#اگر_ختم

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	اگر (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		واپس SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		واپس SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	اگر ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	}
	اگر (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		اگر ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, حجم execbuf,
			    "dup2: %s", strerror(errno));
			اكتب(execpipe[1], execbuf, لڑی_لمبائی(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == تہی ? "" : verbosity);
		execlp(helper, helper, verbosity, (حرف *)تہی);
		snprintf(execbuf, حجم execbuf,
		    "execlp: %s", strerror(errno));
		اكتب(execpipe[1], execbuf, لڑی_لمبائی(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = اقرأ(execpipe[0], execbuf, حجم execbuf);
	close(execpipe[0]);
	اگر (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		واپس SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (طویل)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	واپس 0;
}

ساکن صحیح
reap_helper(pid_t pid)
{
	صحیح حالت_2, oerrno;

	debug3_f("pid=%ld", (طویل)pid);

	errno = 0;
	جب (waitpid(pid, &حالت_2, 0) == -1) {
		اگر (errno == EINTR) {
			errno = 0;
			جاری;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	}
	اگر (!WIFEXITED(حالت_2)) {
		error_f("helper exited abnormally");
		واپس SSH_ERR_AGENT_FAILURE;
	} ورنہ اگر (WEXITSTATUS(حالت_2) != 0) {
		error_f("helper exited with non-zero exit status");
		واپس SSH_ERR_AGENT_FAILURE;
	}
	واپس 0;
}

ساکن صحیح
client_converse(ساخت sshbuf *پیغام, ساخت sshbuf **respp, u_int type)
{
	صحیح oerrno, fd, r2, ll, r = SSH_ERR_اندرونی_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char نسخہ;
	خالی (*osigchld)(صحیح);
	ساخت sshbuf *req = تہی, *resp = تہی;
	*respp = تہی;

	اگر ((r = آغاز_helper(&fd, &pid, &osigchld)) != 0)
		واپس r;

	اگر ((req = sshbuf_new()) == تہی || (resp = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	اگر ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, پیغام)) != 0) {
		error_fr(r, "compose");
		جاؤ برآمد;
	}
	اگر ((r = ssh_پیغام_send(fd, SSH_SK_HELPER_نسخہ, req)) != 0) {
		error_fr(r, "send");
		جاؤ برآمد;
	}
	اگر ((r = ssh_پیغام_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_u8(resp, &نسخہ)) != 0) {
		error_fr(r, "parse version");
		جاؤ برآمد;
	}
	اگر (نسخہ != SSH_SK_HELPER_نسخہ) {
		error_f("unsupported version: got %u, expected %u",
		    نسخہ, SSH_SK_HELPER_نسخہ);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		جاؤ برآمد;
	}
	اگر (rtype == SSH_SK_HELPER_ERROR) {
		اگر ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			جاؤ برآمد;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		اگر (rerr == 0 || rerr >= زیادہ_سے_زیادہ_عدد)
			r = SSH_ERR_اندرونی_ERROR;
		ورنہ
			r = -(صحیح)rerr;
		جاؤ برآمد;
	} ورنہ اگر (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	oerrno = errno;
	close(fd);
	اگر ((r2 = reap_helper(pid)) != 0) {
		اگر (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	اگر (r == 0) {
		*respp = resp;
		resp = تہی;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	واپس r;

}

صحیح
sshsk_sign(ثابت حرف *provider, ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp, ثابت u_char *ڈیٹا, سائز_t datalen,
    u_int compat, ثابت حرف *pin)
{
	صحیح oerrno, r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *kbuf = تہی, *req = تہی, *resp = تہی;

	*sigp = تہی;
	*lenp = 0;

#اگر_غیر_تعریف_شدہ ENABLE_SK
	واپس SSH_ERR_کلید_TYPE_UNKNOWN;
#اگر_ختم

	اگر ((kbuf = sshbuf_new()) == تہی ||
	    (req = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	اگر ((r = sshkey_نجی_serialize(کلید, kbuf)) != 0) {
		error_fr(r, "encode key");
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, ڈیٹا, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, تہی)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		جاؤ برآمد;
	}

	اگر ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		جاؤ برآمد;

	اگر ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	oerrno = errno;
	اگر (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = تہی;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	واپس r;
}

صحیح
sshsk_enroll(صحیح type, ثابت حرف *provider_راستہ, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, ساخت sshbuf *challenge_buf,
    ساخت sshkey **keyp, ساخت sshbuf *attest)
{
	صحیح oerrno, r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *kbuf = تہی, *abuf = تہی, *req = تہی, *resp = تہی;
	ساخت sshkey *کلید = تہی;

	*keyp = تہی;
	اگر (attest != تہی)
		sshbuf_reset(attest);

#اگر_غیر_تعریف_شدہ ENABLE_SK
	واپس SSH_ERR_کلید_TYPE_UNKNOWN;
#اگر_ختم

	اگر (type < 0)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((abuf = sshbuf_new()) == تہی ||
	    (kbuf = sshbuf_new()) == تہی ||
	    (req = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	اگر ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_راستہ)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		جاؤ برآمد;
	}

	اگر ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		جاؤ برآمد;

	اگر ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((r = sshkey_نجی_deserialize(kbuf, &کلید)) != 0) {
		error_fr(r, "encode");
		جاؤ برآمد;
	}
	اگر (attest != تہی && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		جاؤ برآمد;
	}

	/* success */
	r = 0;
	*keyp = کلید;
	کلید = تہی;
 برآمد:
	oerrno = errno;
	sshkey_free(کلید);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	واپس r;
}

ساکن خالی
sshsk_free_resident_کلید(ساخت sshsk_resident_کلید *srk)
{
	اگر (srk == تہی)
		واپس;
	sshkey_free(srk->کلید);
	freezero(srk->user_id, srk->user_id_len);
	آزاد(srk);
}


خالی
sshsk_free_resident_کلیدیں(ساخت sshsk_resident_کلید **srks, سائز_t nsrks)
{
	سائز_t i;

	اگر (srks == تہی || nsrks == 0)
		واپس;

	برائے (i = 0; i < nsrks; i++)
		sshsk_free_resident_کلید(srks[i]);
	آزاد(srks);
}

صحیح
sshsk_بھرو_resident(ثابت حرف *provider_راستہ, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, ساخت sshsk_resident_کلید ***srksp,
    سائز_t *nsrksp)
{
	صحیح oerrno, r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *kbuf = تہی, *req = تہی, *resp = تہی;
	ساخت sshkey *کلید = تہی;
	ساخت sshsk_resident_کلید *srk = تہی, **srks = تہی, **tmp;
	u_char *userid = تہی;
	سائز_t userid_len = 0, nsrks = 0;

	*srksp = تہی;
	*nsrksp = 0;

	اگر ((kbuf = sshbuf_new()) == تہی ||
	    (req = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	اگر ((r = sshbuf_put_cstring(req, provider_راستہ)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		جاؤ برآمد;
	}

	اگر ((r = client_converse(req, &resp, SSH_SK_HELPER_بھرو_RESIDENT)) != 0)
		جاؤ برآمد;

	جب (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		اگر ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, تہی, تہی)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر ((r = sshkey_نجی_deserialize(kbuf, &کلید)) != 0) {
			error_fr(r, "decode key");
			جاؤ برآمد;
		}
		اگر ((srk = صفر_حافظہ_دو(1, حجم(*srk))) == تہی) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		srk->کلید = کلید;
		کلید = تہی;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = تہی;
		userid_len = 0;
		اگر ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    حجم(*srks))) == تہی) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->کلید), srk->کلید->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = تہی;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = تہی;
	nsrks = 0;
 برآمد:
	oerrno = errno;
	sshsk_free_resident_کلید(srk);
	sshsk_free_resident_کلیدیں(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(کلید);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	واپس r;
}
