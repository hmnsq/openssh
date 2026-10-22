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

#অন্তর্ভাৱ <setjmp.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/types.h>

বাহ্য "C" {
#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "sftp.h"
#অন্তর্ভাৱ "sftp-common.h"
#অন্তর্ভাৱ "sftp-client.h"

শূন্য fuzz_arena_begin(শূন্য);
শূন্য fuzz_arena_cleanup(শূন্য);
}

বাহ্য "C" চঞ্চল sig_atomic_t interrupted = 0;
বাহ্য "C" পূর্ণাঙ্ক showprogress = 0;
বাহ্য "C" শূন্য start_progress_meter(ধ্রুৱ ৱর্ণ *file, off_t filesize,
    off_t *ctr) { (শূন্য)file; (শূন্য)filesize; (শূন্য)ctr; }
বাহ্য "C" শূন্য refresh_progress_meter(পূর্ণাঙ্ক force_update) { (শূন্য)force_update; }
বাহ্য "C" শূন্য stop_progress_meter(শূন্য) { }

স্থির jmp_buf fuzz_env;
স্থির চঞ্চল পূর্ণাঙ্ক in_fuzz = 0;

বাহ্য "C" শূন্য
cleanup_exit(পূর্ণাঙ্ক code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

স্থির ধ্রুৱ uint8_t k_version_reply[] = {
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
run_one(পূর্ণাঙ্ক api, ধ্রুৱ uint8_t *body, size_t bsize)
{
	পূর্ণাঙ্ক sv[2] = { -1, -1 };
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ঘূৰাই;

	ssize_t w = লিখ(sv[0], k_version_reply, পরিমাণ(k_version_reply));
	(শূন্য)w;
	যদি (bsize > 0)
		w = লিখ(sv[0], body, bsize);
	(শূন্য)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		সংরচনা sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		যদি (conn != রিক্ত) {
			Attrib attr;
			attrib_clear(&attr);

			ৱিকল্প (api) {
			পক্ষ API_STAT: {
				Attrib a;
				(শূন্য)sftp_stat(conn, "/fuzz", 1, &a);
				ভঙ্গ;
			}
			পক্ষ API_LSTAT: {
				Attrib a;
				(শূন্য)sftp_lstat(conn, "/fuzz", 1, &a);
				ভঙ্গ;
			}
			পক্ষ API_REALPATH: {
				ৱর্ণ *p = sftp_realpath(conn, "/fuzz");
				মুক্ত(p);
				ভঙ্গ;
			}
			পক্ষ API_EXPAND_PATH: {
				ৱর্ণ *p = sftp_expand_path(conn, "~");
				মুক্ত(p);
				ভঙ্গ;
			}
			পক্ষ API_READDIR: {
				SFTP_DIRENT **dir = রিক্ত;
				(শূন্য)sftp_readdir(conn, "/fuzz", &dir);
				যদি (dir != রিক্ত)
					sftp_free_dirents(dir);
				ভঙ্গ;
			}
			পক্ষ API_STATVFS: {
				সংরচনা sftp_statvfs vfs;
				(শূন্য)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				ভঙ্গ;
			}
			পক্ষ API_GET_LIMITS: {
				সংরচনা sftp_limits lim;
				(শূন্য)sftp_get_limits(conn, &lim);
				ভঙ্গ;
			}
			পক্ষ API_RM:
				(শূন্য)sftp_rm(conn, "/fuzz");
				ভঙ্গ;
			পক্ষ API_MKDIR:
				(শূন্য)sftp_mkdir(conn, "/fuzz", &attr, 0);
				ভঙ্গ;
			পক্ষ API_RMDIR:
				(শূন্য)sftp_rmdir(conn, "/fuzz");
				ভঙ্গ;
			পক্ষ API_RENAME:
				(শূন্য)sftp_rename(conn, "/a", "/b", 0);
				ভঙ্গ;
			পক্ষ API_SYMLINK:
				(শূন্য)sftp_symlink(conn, "/a", "/b");
				ভঙ্গ;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

বাহ্য "C" পূর্ণাঙ্ক
LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t *data, size_t size)
{
	স্থির পূর্ণাঙ্ক initialized = 0;
	যদি (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	যদি (size > 65536)
		ঘূৰাই 0;

	বাবে (পূর্ণাঙ্ক api = 0; api < API_গুনতি; api++)
		run_one(api, data, size);

	ঘূৰাই 0;
}
