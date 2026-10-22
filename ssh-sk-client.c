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

ایستا صحیح
start_helper(صحیح *fdp, pid_t *pidp, تهی (**osigchldp)(صحیح))
{
	تهی (*osigchld)(صحیح);
	صحیح oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	نویسه execbuf[100], *helper, *verbosity = پوچ;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	اگر (helper == پوچ || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	اگر (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		بازگشت SSH_ERR_SYSTEM_ERROR;
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
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}
	اگر (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		اگر ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, اندازه execbuf,
			    "dup2: %s", strerror(errno));
			اكتب(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == پوچ ? "" : verbosity);
		execlp(helper, helper, verbosity, (نویسه *)پوچ);
		snprintf(execbuf, اندازه execbuf,
		    "execlp: %s", strerror(errno));
		اكتب(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = اقرأ(execpipe[0], execbuf, اندازه execbuf);
	close(execpipe[0]);
	اگر (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		بازگشت SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	بازگشت 0;
}

ایستا صحیح
reap_helper(pid_t pid)
{
	صحیح status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	وقتی (waitpid(pid, &status, 0) == -1) {
		اگر (errno == EINTR) {
			errno = 0;
			ادامه;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}
	اگر (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		بازگشت SSH_ERR_AGENT_FAILURE;
	} وگرنه اگر (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		بازگشت SSH_ERR_AGENT_FAILURE;
	}
	بازگشت 0;
}

ایستا صحیح
client_converse(ساختار sshbuf *پیام, ساختار sshbuf **respp, u_int type)
{
	صحیح oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	تهی (*osigchld)(صحیح);
	ساختار sshbuf *req = پوچ, *resp = پوچ;
	*respp = پوچ;

	اگر ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		بازگشت r;

	اگر ((req = sshbuf_new()) == پوچ || (resp = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	اگر ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, پیام)) != 0) {
		error_fr(r, "compose");
		برو out;
	}
	اگر ((r = ssh_پیام_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		برو out;
	}
	اگر ((r = ssh_پیام_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		برو out;
	}
	اگر ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		برو out;
	}
	اگر (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		برو out;
	}
	اگر (rtype == SSH_SK_HELPER_ERROR) {
		اگر ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			برو out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		اگر (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		وگرنه
			r = -(صحیح)rerr;
		برو out;
	} وگرنه اگر (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	/* success */
	r = 0;
 out:
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
		resp = پوچ;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	بازگشت r;

}

صحیح
sshsk_sign(ثابت نویسه *provider, ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp, ثابت u_char *data, size_t datalen,
    u_int compat, ثابت نویسه *pin)
{
	صحیح oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *kbuf = پوچ, *req = پوچ, *resp = پوچ;

	*sigp = پوچ;
	*lenp = 0;

#ifndef ENABLE_SK
	بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
#endif

	اگر ((kbuf = sshbuf_new()) == پوچ ||
	    (req = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	اگر ((r = sshkey_private_serialize(کلید, kbuf)) != 0) {
		error_fr(r, "encode key");
		برو out;
	}
	اگر ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, پوچ)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		برو out;
	}

	اگر ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		برو out;

	اگر ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	اگر (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = پوچ;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	بازگشت r;
}

صحیح
sshsk_enroll(صحیح type, ثابت نویسه *provider_path, ثابت نویسه *device,
    ثابت نویسه *application, ثابت نویسه *userid, uint8_t flags,
    ثابت نویسه *pin, ساختار sshbuf *challenge_buf,
    ساختار sshkey **keyp, ساختار sshbuf *attest)
{
	صحیح oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *kbuf = پوچ, *abuf = پوچ, *req = پوچ, *resp = پوچ;
	ساختار sshkey *کلید = پوچ;

	*keyp = پوچ;
	اگر (attest != پوچ)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
#endif

	اگر (type < 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((abuf = sshbuf_new()) == پوچ ||
	    (kbuf = sshbuf_new()) == پوچ ||
	    (req = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	اگر ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		برو out;
	}

	اگر ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		برو out;

	اگر ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((r = sshkey_private_deserialize(kbuf, &کلید)) != 0) {
		error_fr(r, "encode");
		برو out;
	}
	اگر (attest != پوچ && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		برو out;
	}

	/* success */
	r = 0;
	*keyp = کلید;
	کلید = پوچ;
 out:
	oerrno = errno;
	sshkey_free(کلید);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	بازگشت r;
}

ایستا تهی
sshsk_free_resident_کلید(ساختار sshsk_resident_کلید *srk)
{
	اگر (srk == پوچ)
		بازگشت;
	sshkey_free(srk->کلید);
	freezero(srk->user_id, srk->user_id_len);
	آزاد(srk);
}


تهی
sshsk_free_resident_کلیدها(ساختار sshsk_resident_کلید **srks, size_t nsrks)
{
	size_t i;

	اگر (srks == پوچ || nsrks == 0)
		بازگشت;

	برای (i = 0; i < nsrks; i++)
		sshsk_free_resident_کلید(srks[i]);
	آزاد(srks);
}

صحیح
sshsk_load_resident(ثابت نویسه *provider_path, ثابت نویسه *device,
    ثابت نویسه *pin, u_int flags, ساختار sshsk_resident_کلید ***srksp,
    size_t *nsrksp)
{
	صحیح oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *kbuf = پوچ, *req = پوچ, *resp = پوچ;
	ساختار sshkey *کلید = پوچ;
	ساختار sshsk_resident_کلید *srk = پوچ, **srks = پوچ, **tmp;
	u_char *userid = پوچ;
	size_t userid_len = 0, nsrks = 0;

	*srksp = پوچ;
	*nsrksp = 0;

	اگر ((kbuf = sshbuf_new()) == پوچ ||
	    (req = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	اگر ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		برو out;
	}

	اگر ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		برو out;

	وقتی (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		اگر ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, پوچ, پوچ)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر ((r = sshkey_private_deserialize(kbuf, &کلید)) != 0) {
			error_fr(r, "decode key");
			برو out;
		}
		اگر ((srk = calloc(1, اندازه(*srk))) == پوچ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		srk->کلید = کلید;
		کلید = پوچ;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = پوچ;
		userid_len = 0;
		اگر ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    اندازه(*srks))) == پوچ) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->کلید), srk->کلید->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = پوچ;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = پوچ;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_کلید(srk);
	sshsk_free_resident_کلیدها(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(کلید);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	بازگشت r;
}
