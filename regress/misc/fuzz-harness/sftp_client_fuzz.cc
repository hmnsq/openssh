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

#অন্তর্ভাব <setjmp.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/types.h>

বাহ্যিক "C" {
#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sftp.h"
#অন্তর্ভাব "sftp-common.h"
#অন্তর্ভাব "sftp-client.h"

শূন্য fuzz_arena_begin(শূন্য);
শূন্য fuzz_arena_cleanup(শূন্য);
}

বাহ্যিক "C" অস্থির sig_atomic_t interrupted = 0;
বাহ্যিক "C" পূর্ণসংখ্যা showprogress = 0;
বাহ্যিক "C" শূন্য start_progress_meter(ধ্রুবক অক্ষর *file, off_t filesize,
    off_t *ctr) { (শূন্য)file; (শূন্য)filesize; (শূন্য)ctr; }
বাহ্যিক "C" শূন্য refresh_progress_meter(পূর্ণসংখ্যা force_update) { (শূন্য)force_update; }
বাহ্যিক "C" শূন্য stop_progress_meter(শূন্য) { }

স্থির jmp_buf fuzz_env;
স্থির অস্থির পূর্ণসংখ্যা in_fuzz = 0;

বাহ্যিক "C" শূন্য
cleanup_exit(পূর্ণসংখ্যা code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

স্থির ধ্রুবক uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

গণনা {
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
	API_গুনতি,
};

স্থির শূন্য
run_one(পূর্ণসংখ্যা api, ধ্রুবক uint8_t *body, আকার_t bsize)
{
	পূর্ণসংখ্যা sv[2] = { -1, -1 };
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ফেরত;

	ssize_t w = লিখ(sv[0], k_version_reply, আকার(k_version_reply));
	(শূন্য)w;
	যদি (bsize > 0)
		w = লিখ(sv[0], body, bsize);
	(শূন্য)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		কাঠামো sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		যদি (conn != ফাঁকা) {
			Attrib attr;
			attrib_clear(&attr);

			নির্বাচন (api) {
			ক্ষেত্র API_STAT: {
				Attrib a;
				(শূন্য)sftp_stat(conn, "/fuzz", 1, &a);
				বিরতি;
			}
			ক্ষেত্র API_LSTAT: {
				Attrib a;
				(শূন্য)sftp_lstat(conn, "/fuzz", 1, &a);
				বিরতি;
			}
			ক্ষেত্র API_REALPATH: {
				অক্ষর *p = sftp_realpath(conn, "/fuzz");
				মুক্ত(p);
				বিরতি;
			}
			ক্ষেত্র API_EXPAND_PATH: {
				অক্ষর *p = sftp_expand_path(conn, "~");
				মুক্ত(p);
				বিরতি;
			}
			ক্ষেত্র API_READDIR: {
				SFTP_DIRENT **dir = ফাঁকা;
				(শূন্য)sftp_readdir(conn, "/fuzz", &dir);
				যদি (dir != ফাঁকা)
					sftp_free_dirents(dir);
				বিরতি;
			}
			ক্ষেত্র API_STATVFS: {
				কাঠামো sftp_statvfs vfs;
				(শূন্য)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				বিরতি;
			}
			ক্ষেত্র API_GET_LIMITS: {
				কাঠামো sftp_limits lim;
				(শূন্য)sftp_get_limits(conn, &lim);
				বিরতি;
			}
			ক্ষেত্র API_RM:
				(শূন্য)sftp_rm(conn, "/fuzz");
				বিরতি;
			ক্ষেত্র API_MKDIR:
				(শূন্য)sftp_mkdir(conn, "/fuzz", &attr, 0);
				বিরতি;
			ক্ষেত্র API_RMDIR:
				(শূন্য)sftp_rmdir(conn, "/fuzz");
				বিরতি;
			ক্ষেত্র API_RENAME:
				(শূন্য)sftp_rename(conn, "/a", "/b", 0);
				বিরতি;
			ক্ষেত্র API_SYMLINK:
				(শূন্য)sftp_symlink(conn, "/a", "/b");
				বিরতি;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

বাহ্যিক "C" পূর্ণসংখ্যা
LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	স্থির পূর্ণসংখ্যা initialized = 0;
	যদি (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	যদি (আকার_2 > 65536)
		ফেরত 0;

	জন্য (পূর্ণসংখ্যা api = 0; api < API_গুনতি; api++)
		run_one(api, তথ্য, আকার_2);

	ফেরত 0;
}
