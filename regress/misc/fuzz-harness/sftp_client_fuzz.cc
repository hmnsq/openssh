/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for OpenSSH SFTP client response parser (sftp-client.c)
 *
 * Target: sftp-client.c
 *
 * Drives every public sftp-client API on a socketpair using the
 * fuzzer input as the reply payload. A helper opens a fresh
 * socketpair, pre-fills a valid FXP_VERSION reply so sftp_init
 * succeeds, then writes the fuzzer body which the API call consumes
 * as its own response. Each iteration runs all 12 APIs on the same
 * input so no API is starved by a selector byte.
 *
 * Primary functions exercised:
 * - sftp_init, sftp_stat, sftp_lstat, sftp_realpath, sftp_expand_path
 * - sftp_readdir, sftp_statvfs, sftp_get_limits
 * - sftp_rm, sftp_mkdir, sftp_rmdir, sftp_rename, sftp_symlink
 * - decode_attrib via every reply path (sftp-common.c)
 *
 * Threat model: a malicious SFTP server returning crafted attribute
 * lists, name lists, status responses, and statvfs payloads to a
 * connected client (sshfs, sftp, scp to a hostile host).
 *
 * Failure handling: sftp-client.c calls fatal() liberally on
 * protocol violations. A custom cleanup_exit() longjmp()s back to
 * the helper. fuzz_arena (linker --wrap'd malloc family) frees
 * every still-live allocation on both the success and longjmp paths
 * so LSan sees zero per-iteration leaks.
 */

#ଅନ୍ତର୍ଭାଵ <setjmp.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

ବାହ୍ୟ "C" {
#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sftp.h"
#ଅନ୍ତର୍ଭାଵ "sftp-common.h"
#ଅନ୍ତର୍ଭାଵ "sftp-client.h"

ଶୂନ୍ୟ fuzz_arena_begin(ଶୂନ୍ୟ);
ଶୂନ୍ୟ fuzz_arena_cleanup(ଶୂନ୍ୟ);
}

ବାହ୍ୟ "C" ଅସ୍ଥିର sig_atomic_t interrupted = 0;
ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା showprogress = 0;
ବାହ୍ୟ "C" ଶୂନ୍ୟ start_progress_meter(ଅଚଳ ଅକ୍ଷର *file, off_t filesize,
    off_t *ctr) { (ଶୂନ୍ୟ)file; (ଶୂନ୍ୟ)filesize; (ଶୂନ୍ୟ)ctr; }
ବାହ୍ୟ "C" ଶୂନ୍ୟ refresh_progress_meter(ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_update) { (ଶୂନ୍ୟ)force_update; }
ବାହ୍ୟ "C" ଶୂନ୍ୟ stop_progress_meter(ଶୂନ୍ୟ) { }

ସ୍ଥିର jmp_buf fuzz_env;
ସ୍ଥିର ଅସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fuzz = 0;

ବାହ୍ୟ "C" ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା code)
{
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ସ୍ଥିର ଅଚଳ uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

ଗଣନା {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_PATH,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_ଗଣନା,
};

ସ୍ଥିର ଶୂନ୍ୟ
run_one(ପୂର୍ଣ୍ଣସଂଖ୍ୟା api, ଅଚଳ uint8_t *body, size_t bsize)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sv[2] = { -1, -1 };
	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ଫେରନ୍ତୁ;

	ssize_t w = ଲିଖ(sv[0], k_version_reply, ଆକାର(k_version_reply));
	(ଶୂନ୍ୟ)w;
	ଯଦି (bsize > 0)
		w = ଲିଖ(sv[0], body, bsize);
	(ଶୂନ୍ୟ)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	ଯଦି (setjmp(fuzz_env) == 0) {
		ସଂରଚନା sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		ଯଦି (conn != ଖାଲି) {
			Attrib attr;
			attrib_clear(&attr);

			ବାଛ (api) {
			ସ୍ଥିତି API_STAT: {
				Attrib a;
				(ଶୂନ୍ୟ)sftp_stat(conn, "/fuzz", 1, &a);
				ଭାଙ୍ଗ;
			}
			ସ୍ଥିତି API_LSTAT: {
				Attrib a;
				(ଶୂନ୍ୟ)sftp_lstat(conn, "/fuzz", 1, &a);
				ଭାଙ୍ଗ;
			}
			ସ୍ଥିତି API_REALPATH: {
				ଅକ୍ଷର *p = sftp_realpath(conn, "/fuzz");
				ମୁକ୍ତ(p);
				ଭାଙ୍ଗ;
			}
			ସ୍ଥିତି API_EXPAND_PATH: {
				ଅକ୍ଷର *p = sftp_expand_path(conn, "~");
				ମୁକ୍ତ(p);
				ଭାଙ୍ଗ;
			}
			ସ୍ଥିତି API_READDIR: {
				SFTP_DIRENT **dir = ଖାଲି;
				(ଶୂନ୍ୟ)sftp_readdir(conn, "/fuzz", &dir);
				ଯଦି (dir != ଖାଲି)
					sftp_free_dirents(dir);
				ଭାଙ୍ଗ;
			}
			ସ୍ଥିତି API_STATVFS: {
				ସଂରଚନା sftp_statvfs vfs;
				(ଶୂନ୍ୟ)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				ଭାଙ୍ଗ;
			}
			ସ୍ଥିତି API_GET_LIMITS: {
				ସଂରଚନା sftp_limits lim;
				(ଶୂନ୍ୟ)sftp_get_limits(conn, &lim);
				ଭାଙ୍ଗ;
			}
			ସ୍ଥିତି API_RM:
				(ଶୂନ୍ୟ)sftp_rm(conn, "/fuzz");
				ଭାଙ୍ଗ;
			ସ୍ଥିତି API_MKDIR:
				(ଶୂନ୍ୟ)sftp_mkdir(conn, "/fuzz", &attr, 0);
				ଭାଙ୍ଗ;
			ସ୍ଥିତି API_RMDIR:
				(ଶୂନ୍ୟ)sftp_rmdir(conn, "/fuzz");
				ଭାଙ୍ଗ;
			ସ୍ଥିତି API_RENAME:
				(ଶୂନ୍ୟ)sftp_rename(conn, "/a", "/b", 0);
				ଭାଙ୍ଗ;
			ସ୍ଥିତି API_SYMLINK:
				(ଶୂନ୍ୟ)sftp_symlink(conn, "/a", "/b");
				ଭାଙ୍ଗ;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା
LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t *data, size_t size)
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା initialized = 0;
	ଯଦି (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	ଯଦି (size > 65536)
		ଫେରନ୍ତୁ 0;

	ପାଇଁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା api = 0; api < API_ଗଣନା; api++)
		run_one(api, data, size);

	ଫେରନ୍ତୁ 0;
}
