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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/wait.h>

#ضمن <limits.h>
#ضمن <errno.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <fcntl.h>

#ضمن "log.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "msg.h"
#ضمن "pathnames.h"
#ضمن "ssh-sk.h"
#ضمن "misc.h"

/* #define DEBUG_SK 1 */

ساكن صحيح
start_helper(صحيح *fdp, pid_t *pidp, فراغ (**osigchldp)(صحيح))
{
	فراغ (*osigchld)(صحيح);
	صحيح oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	حرف execbuf[100], *helper, *verbosity = عدم;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	إذا (helper == عدم || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	إذا (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	إذا ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	إذا (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		إذا ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, حجم execbuf,
			    "dup2: %s", strerror(errno));
			اكتب(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == عدم ? "" : verbosity);
		execlp(helper, helper, verbosity, (حرف *)عدم);
		snprintf(execbuf, حجم execbuf,
		    "execlp: %s", strerror(errno));
		اكتب(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = اقرأ(execpipe[0], execbuf, حجم execbuf);
	close(execpipe[0]);
	إذا (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		أرجع SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	أرجع 0;
}

ساكن صحيح
reap_helper(pid_t pid)
{
	صحيح status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	طالما (waitpid(pid, &status, 0) == -1) {
		إذا (errno == EINTR) {
			errno = 0;
			استمر;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	إذا (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		أرجع SSH_ERR_AGENT_FAILURE;
	} وإلا إذا (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		أرجع SSH_ERR_AGENT_FAILURE;
	}
	أرجع 0;
}

ساكن صحيح
client_converse(بنية sshbuf *ئۇچۇر, بنية sshbuf **respp, u_int type)
{
	صحيح oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	فراغ (*osigchld)(صحيح);
	بنية sshbuf *req = عدم, *resp = عدم;
	*respp = عدم;

	إذا ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		أرجع r;

	إذا ((req = sshbuf_new()) == عدم || (resp = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	إذا ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, ئۇچۇر)) != 0) {
		error_fr(r, "compose");
		اذهب out;
	}
	إذا ((r = ssh_ئۇچۇر_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		اذهب out;
	}
	إذا ((r = ssh_ئۇچۇر_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		اذهب out;
	}
	إذا ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		اذهب out;
	}
	إذا (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		اذهب out;
	}
	إذا (rtype == SSH_SK_HELPER_ERROR) {
		إذا ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			اذهب out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		إذا (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		وإلا
			r = -(صحيح)rerr;
		اذهب out;
	} وإلا إذا (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	إذا ((r2 = reap_helper(pid)) != 0) {
		إذا (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	إذا (r == 0) {
		*respp = resp;
		resp = عدم;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	أرجع r;

}

صحيح
sshsk_sign(ثابت حرف *provider, بنية sshkey *ئاچقۇچ,
    u_char **sigp, size_t *lenp, ثابت u_char *data, size_t datalen,
    u_int compat, ثابت حرف *pin)
{
	صحيح oerrno, r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *kbuf = عدم, *req = عدم, *resp = عدم;

	*sigp = عدم;
	*lenp = 0;

#ifndef ENABLE_SK
	أرجع SSH_ERR_ئاچقۇچ_TYPE_UNKNOWN;
#endif

	إذا ((kbuf = sshbuf_new()) == عدم ||
	    (req = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	إذا ((r = sshkey_private_serialize(ئاچقۇچ, kbuf)) != 0) {
		error_fr(r, "encode key");
		اذهب out;
	}
	إذا ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, عدم)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		اذهب out;
	}

	إذا ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		اذهب out;

	إذا ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	إذا (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = عدم;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	أرجع r;
}

صحيح
sshsk_enroll(صحيح type, ثابت حرف *provider_path, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, بنية sshbuf *challenge_buf,
    بنية sshkey **keyp, بنية sshbuf *attest)
{
	صحيح oerrno, r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *kbuf = عدم, *abuf = عدم, *req = عدم, *resp = عدم;
	بنية sshkey *ئاچقۇچ = عدم;

	*keyp = عدم;
	إذا (attest != عدم)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	أرجع SSH_ERR_ئاچقۇچ_TYPE_UNKNOWN;
#endif

	إذا (type < 0)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	إذا ((abuf = sshbuf_new()) == عدم ||
	    (kbuf = sshbuf_new()) == عدم ||
	    (req = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	إذا ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		اذهب out;
	}

	إذا ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		اذهب out;

	إذا ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((r = sshkey_private_deserialize(kbuf, &ئاچقۇچ)) != 0) {
		error_fr(r, "encode");
		اذهب out;
	}
	إذا (attest != عدم && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		اذهب out;
	}

	/* success */
	r = 0;
	*keyp = ئاچقۇچ;
	ئاچقۇچ = عدم;
 out:
	oerrno = errno;
	sshkey_free(ئاچقۇچ);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	أرجع r;
}

ساكن فراغ
sshsk_free_resident_ئاچقۇچ(بنية sshsk_resident_ئاچقۇچ *srk)
{
	إذا (srk == عدم)
		أرجع;
	sshkey_free(srk->ئاچقۇچ);
	freezero(srk->user_id, srk->user_id_len);
	حرر(srk);
}


فراغ
sshsk_free_resident_ئاچقۇچلار(بنية sshsk_resident_ئاچقۇچ **srks, size_t nsrks)
{
	size_t i;

	إذا (srks == عدم || nsrks == 0)
		أرجع;

	لكل (i = 0; i < nsrks; i++)
		sshsk_free_resident_ئاچقۇچ(srks[i]);
	حرر(srks);
}

صحيح
sshsk_load_resident(ثابت حرف *provider_path, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, بنية sshsk_resident_ئاچقۇچ ***srksp,
    size_t *nsrksp)
{
	صحيح oerrno, r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *kbuf = عدم, *req = عدم, *resp = عدم;
	بنية sshkey *ئاچقۇچ = عدم;
	بنية sshsk_resident_ئاچقۇچ *srk = عدم, **srks = عدم, **tmp;
	u_char *userid = عدم;
	size_t userid_len = 0, nsrks = 0;

	*srksp = عدم;
	*nsrksp = 0;

	إذا ((kbuf = sshbuf_new()) == عدم ||
	    (req = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	إذا ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		اذهب out;
	}

	إذا ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		اذهب out;

	طالما (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		إذا ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, عدم, عدم)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		إذا ((r = sshkey_private_deserialize(kbuf, &ئاچقۇچ)) != 0) {
			error_fr(r, "decode key");
			اذهب out;
		}
		إذا ((srk = calloc(1, حجم(*srk))) == عدم) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		srk->ئاچقۇچ = ئاچقۇچ;
		ئاچقۇچ = عدم;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = عدم;
		userid_len = 0;
		إذا ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    حجم(*srks))) == عدم) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->ئاچقۇچ), srk->ئاچقۇچ->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = عدم;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = عدم;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_ئاچقۇچ(srk);
	sshsk_free_resident_ئاچقۇچلار(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(ئاچقۇچ);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	أرجع r;
}
