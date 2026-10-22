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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>

#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "ssh-sk.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

/* #define DEBUG_SK 1 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
start_helper(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fdp, pid_t *pidp, ଶୂନ୍ୟ (**osigchldp)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା))
{
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	ଅକ୍ଷର execbuf[100], *helper, *verbosity = ଖାଲି;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	ଯଦି (helper == ଖାଲି || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	ଯଦି (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ଯଦି ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}
	ଯଦି (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		ଯଦି ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, ଆକାର execbuf,
			    "dup2: %s", strerror(errno));
			ଲିଖ(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == ଖାଲି ? "" : verbosity);
		execlp(helper, helper, verbosity, (ଅକ୍ଷର *)ଖାଲି);
		snprintf(execbuf, ଆକାର execbuf,
		    "execlp: %s", strerror(errno));
		ଲିଖ(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = ପଠ(execpipe[0], execbuf, ଆକାର execbuf);
	close(execpipe[0]);
	ଯଦି (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		ଫେରନ୍ତୁ SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
reap_helper(pid_t pid)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	ଯେତେବେଳେ (waitpid(pid, &status, 0) == -1) {
		ଯଦି (errno == EINTR) {
			errno = 0;
			ଜାରି;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}
	ଯଦି (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		ଫେରନ୍ତୁ SSH_ERR_AGENT_FAILURE;
	} ଅନ୍ୟଥା ଯଦି (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		ଫେରନ୍ତୁ SSH_ERR_AGENT_FAILURE;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
client_converse(ସଂରଚନା sshbuf *ସନ୍ଦେଶ, ସଂରଚନା sshbuf **respp, u_int type)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
	ସଂରଚନା sshbuf *req = ଖାଲି, *resp = ଖାଲି;
	*respp = ଖାଲି;

	ଯଦି ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		ଫେରନ୍ତୁ r;

	ଯଦି ((req = sshbuf_new()) == ଖାଲି || (resp = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	ଯଦି ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, ସନ୍ଦେଶ)) != 0) {
		error_fr(r, "compose");
		ଯାଅ out;
	}
	ଯଦି ((r = ssh_ସନ୍ଦେଶ_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		ଯାଅ out;
	}
	ଯଦି ((r = ssh_ସନ୍ଦେଶ_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		ଯାଅ out;
	}
	ଯଦି (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		ଯାଅ out;
	}
	ଯଦି (rtype == SSH_SK_HELPER_ERROR) {
		ଯଦି ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			ଯାଅ out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		ଯଦି (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		ଅନ୍ୟଥା
			r = -(ପୂର୍ଣ୍ଣସଂଖ୍ୟା)rerr;
		ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	ଯଦି ((r2 = reap_helper(pid)) != 0) {
		ଯଦି (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	ଯଦି (r == 0) {
		*respp = resp;
		resp = ଖାଲି;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	ଫେରନ୍ତୁ r;

}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_sign(ଅଚଳ ଅକ୍ଷର *provider, ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp, ଅଚଳ u_char *data, size_t datalen,
    u_int compat, ଅଚଳ ଅକ୍ଷର *pin)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *kbuf = ଖାଲି, *req = ଖାଲି, *resp = ଖାଲି;

	*sigp = ଖାଲି;
	*lenp = 0;

#ifndef ENABLE_SK
	ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
#endif

	ଯଦି ((kbuf = sshbuf_new()) == ଖାଲି ||
	    (req = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	ଯଦି ((r = sshkey_private_serialize(ଚାବି, kbuf)) != 0) {
		error_fr(r, "encode key");
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, ଖାଲି)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		ଯାଅ out;
	}

	ଯଦି ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		ଯାଅ out;

	ଯଦି ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	ଯଦି (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = ଖାଲି;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_enroll(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *provider_path, ଅଚଳ ଅକ୍ଷର *device,
    ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ ଅକ୍ଷର *userid, uint8_t flags,
    ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sshbuf *challenge_buf,
    ସଂରଚନା sshkey **keyp, ସଂରଚନା sshbuf *attest)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *kbuf = ଖାଲି, *abuf = ଖାଲି, *req = ଖାଲି, *resp = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;

	*keyp = ଖାଲି;
	ଯଦି (attest != ଖାଲି)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
#endif

	ଯଦି (type < 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((abuf = sshbuf_new()) == ଖାଲି ||
	    (kbuf = sshbuf_new()) == ଖାଲି ||
	    (req = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	ଯଦି ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		ଯାଅ out;
	}

	ଯଦି ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		ଯାଅ out;

	ଯଦି ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_private_deserialize(kbuf, &ଚାବି)) != 0) {
		error_fr(r, "encode");
		ଯାଅ out;
	}
	ଯଦି (attest != ଖାଲି && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		ଯାଅ out;
	}

	/* success */
	r = 0;
	*keyp = ଚାବି;
	ଚାବି = ଖାଲି;
 out:
	oerrno = errno;
	sshkey_free(ଚାବି);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଶୂନ୍ୟ
sshsk_free_resident_ଚାବି(ସଂରଚନା sshsk_resident_ଚାବି *srk)
{
	ଯଦି (srk == ଖାଲି)
		ଫେରନ୍ତୁ;
	sshkey_free(srk->ଚାବି);
	freezero(srk->user_id, srk->user_id_len);
	ମୁକ୍ତ(srk);
}


ଶୂନ୍ୟ
sshsk_free_resident_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା sshsk_resident_ଚାବି **srks, size_t nsrks)
{
	size_t i;

	ଯଦି (srks == ଖାଲି || nsrks == 0)
		ଫେରନ୍ତୁ;

	ପାଇଁ (i = 0; i < nsrks; i++)
		sshsk_free_resident_ଚାବି(srks[i]);
	ମୁକ୍ତ(srks);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_load_resident(ଅଚଳ ଅକ୍ଷର *provider_path, ଅଚଳ ଅକ୍ଷର *device,
    ଅଚଳ ଅକ୍ଷର *pin, u_int flags, ସଂରଚନା sshsk_resident_ଚାବି ***srksp,
    size_t *nsrksp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *kbuf = ଖାଲି, *req = ଖାଲି, *resp = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା sshsk_resident_ଚାବି *srk = ଖାଲି, **srks = ଖାଲି, **tmp;
	u_char *userid = ଖାଲି;
	size_t userid_len = 0, nsrks = 0;

	*srksp = ଖାଲି;
	*nsrksp = 0;

	ଯଦି ((kbuf = sshbuf_new()) == ଖାଲି ||
	    (req = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	ଯଦି ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		ଯାଅ out;
	}

	ଯଦି ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		ଯାଅ out;

	ଯେତେବେଳେ (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		ଯଦି ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, ଖାଲି, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି ((r = sshkey_private_deserialize(kbuf, &ଚାବି)) != 0) {
			error_fr(r, "decode key");
			ଯାଅ out;
		}
		ଯଦି ((srk = calloc(1, ଆକାର(*srk))) == ଖାଲି) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		srk->ଚାବି = ଚାବି;
		ଚାବି = ଖାଲି;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = ଖାଲି;
		userid_len = 0;
		ଯଦି ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    ଆକାର(*srks))) == ଖାଲି) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->ଚାବି), srk->ଚାବି->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ଖାଲି;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ଖାଲି;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_ଚାବି(srk);
	sshsk_free_resident_ଚାବିଗୁଡ଼ିକ(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(ଚାବି);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	ଫେରନ୍ତୁ r;
}
