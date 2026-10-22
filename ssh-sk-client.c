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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/wait.h>

#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <fcntl.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "misc.h"

/* #define DEBUG_SK 1 */

স্থির পূর্ণসংখ্যা
start_helper(পূর্ণসংখ্যা *fdp, pid_t *pidp, শূন্য (**osigchldp)(পূর্ণসংখ্যা))
{
	শূন্য (*osigchld)(পূর্ণসংখ্যা);
	পূর্ণসংখ্যা oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	অক্ষর execbuf[100], *helper, *verbosity = ফাঁকা;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	যদি (helper == ফাঁকা || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	যদি (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	যদি ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}
	যদি (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		যদি ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, আকার execbuf,
			    "dup2: %s", strerror(errno));
			লিখ(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == ফাঁকা ? "" : verbosity);
		execlp(helper, helper, verbosity, (অক্ষর *)ফাঁকা);
		snprintf(execbuf, আকার execbuf,
		    "execlp: %s", strerror(errno));
		লিখ(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = পঠ(execpipe[0], execbuf, আকার execbuf);
	close(execpipe[0]);
	যদি (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		ফেরত SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
reap_helper(pid_t pid)
{
	পূর্ণসংখ্যা status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	যখন (waitpid(pid, &status, 0) == -1) {
		যদি (errno == EINTR) {
			errno = 0;
			চালু;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}
	যদি (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		ফেরত SSH_ERR_AGENT_FAILURE;
	} অন্যথা যদি (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		ফেরত SSH_ERR_AGENT_FAILURE;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
client_converse(কাঠামো sshbuf *বার্তা, কাঠামো sshbuf **respp, u_int type)
{
	পূর্ণসংখ্যা oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	শূন্য (*osigchld)(পূর্ণসংখ্যা);
	কাঠামো sshbuf *req = ফাঁকা, *resp = ফাঁকা;
	*respp = ফাঁকা;

	যদি ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		ফেরত r;

	যদি ((req = sshbuf_new()) == ফাঁকা || (resp = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	যদি ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, বার্তা)) != 0) {
		error_fr(r, "compose");
		যাও out;
	}
	যদি ((r = ssh_বার্তা_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		যাও out;
	}
	যদি ((r = ssh_বার্তা_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		যাও out;
	}
	যদি ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		যাও out;
	}
	যদি (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		যাও out;
	}
	যদি (rtype == SSH_SK_HELPER_ERROR) {
		যদি ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			যাও out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		যদি (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		অন্যথা
			r = -(পূর্ণসংখ্যা)rerr;
		যাও out;
	} অন্যথা যদি (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	যদি ((r2 = reap_helper(pid)) != 0) {
		যদি (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	যদি (r == 0) {
		*respp = resp;
		resp = ফাঁকা;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	ফেরত r;

}

পূর্ণসংখ্যা
sshsk_sign(ধ্রুবক অক্ষর *provider, কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp, ধ্রুবক u_char *তথ্য, আকার_t datalen,
    u_int compat, ধ্রুবক অক্ষর *pin)
{
	পূর্ণসংখ্যা oerrno, r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *kbuf = ফাঁকা, *req = ফাঁকা, *resp = ফাঁকা;

	*sigp = ফাঁকা;
	*lenp = 0;

#ifndef ENABLE_SK
	ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
#endif

	যদি ((kbuf = sshbuf_new()) == ফাঁকা ||
	    (req = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	যদি ((r = sshkey_private_serialize(চাবি, kbuf)) != 0) {
		error_fr(r, "encode key");
		যাও out;
	}
	যদি ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, তথ্য, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, ফাঁকা)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		যাও out;
	}

	যদি ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		যাও out;

	যদি ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	যদি (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = ফাঁকা;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ফেরত r;
}

পূর্ণসংখ্যা
sshsk_enroll(পূর্ণসংখ্যা type, ধ্রুবক অক্ষর *provider_path, ধ্রুবক অক্ষর *device,
    ধ্রুবক অক্ষর *application, ধ্রুবক অক্ষর *userid, uint8_t flags,
    ধ্রুবক অক্ষর *pin, কাঠামো sshbuf *challenge_buf,
    কাঠামো sshkey **keyp, কাঠামো sshbuf *attest)
{
	পূর্ণসংখ্যা oerrno, r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *kbuf = ফাঁকা, *abuf = ফাঁকা, *req = ফাঁকা, *resp = ফাঁকা;
	কাঠামো sshkey *চাবি = ফাঁকা;

	*keyp = ফাঁকা;
	যদি (attest != ফাঁকা)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
#endif

	যদি (type < 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি ((abuf = sshbuf_new()) == ফাঁকা ||
	    (kbuf = sshbuf_new()) == ফাঁকা ||
	    (req = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	যদি ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		যাও out;
	}

	যদি ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		যাও out;

	যদি ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((r = sshkey_private_deserialize(kbuf, &চাবি)) != 0) {
		error_fr(r, "encode");
		যাও out;
	}
	যদি (attest != ফাঁকা && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		যাও out;
	}

	/* success */
	r = 0;
	*keyp = চাবি;
	চাবি = ফাঁকা;
 out:
	oerrno = errno;
	sshkey_free(চাবি);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ফেরত r;
}

স্থির শূন্য
sshsk_free_resident_চাবি(কাঠামো sshsk_resident_চাবি *srk)
{
	যদি (srk == ফাঁকা)
		ফেরত;
	sshkey_free(srk->চাবি);
	freezero(srk->user_id, srk->user_id_len);
	মুক্ত(srk);
}


শূন্য
sshsk_free_resident_চাবিগুলি(কাঠামো sshsk_resident_চাবি **srks, আকার_t nsrks)
{
	আকার_t i;

	যদি (srks == ফাঁকা || nsrks == 0)
		ফেরত;

	জন্য (i = 0; i < nsrks; i++)
		sshsk_free_resident_চাবি(srks[i]);
	মুক্ত(srks);
}

পূর্ণসংখ্যা
sshsk_load_resident(ধ্রুবক অক্ষর *provider_path, ধ্রুবক অক্ষর *device,
    ধ্রুবক অক্ষর *pin, u_int flags, কাঠামো sshsk_resident_চাবি ***srksp,
    আকার_t *nsrksp)
{
	পূর্ণসংখ্যা oerrno, r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *kbuf = ফাঁকা, *req = ফাঁকা, *resp = ফাঁকা;
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো sshsk_resident_চাবি *srk = ফাঁকা, **srks = ফাঁকা, **tmp;
	u_char *userid = ফাঁকা;
	আকার_t userid_len = 0, nsrks = 0;

	*srksp = ফাঁকা;
	*nsrksp = 0;

	যদি ((kbuf = sshbuf_new()) == ফাঁকা ||
	    (req = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	যদি ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		যাও out;
	}

	যদি ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		যাও out;

	যখন (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		যদি ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, ফাঁকা, ফাঁকা)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি ((r = sshkey_private_deserialize(kbuf, &চাবি)) != 0) {
			error_fr(r, "decode key");
			যাও out;
		}
		যদি ((srk = calloc(1, আকার(*srk))) == ফাঁকা) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		srk->চাবি = চাবি;
		চাবি = ফাঁকা;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = ফাঁকা;
		userid_len = 0;
		যদি ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    আকার(*srks))) == ফাঁকা) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->চাবি), srk->চাবি->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ফাঁকা;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ফাঁকা;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_চাবি(srk);
	sshsk_free_resident_চাবিগুলি(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(চাবি);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ফেরত r;
}
