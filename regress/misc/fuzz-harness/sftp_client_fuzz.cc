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

#ضمن <setjmp.h>
#ضمن <signal.h>
#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <sys/socket.h>
#ضمن <sys/types.h>

خارجي "C" {
#ضمن "includes.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "log.h"
#ضمن "sftp.h"
#ضمن "sftp-common.h"
#ضمن "sftp-client.h"

فراغ fuzz_arena_begin(فراغ);
فراغ fuzz_arena_cleanup(فراغ);
}

خارجي "C" متطاير sig_atomic_t interrupted = 0;
خارجي "C" صحيح showprogress = 0;
خارجي "C" فراغ پیل_پرمختګ_meter(ثابت حرف *file, off_t filesize,
    off_t *ctr) { (فراغ)file; (فراغ)filesize; (فراغ)ctr; }
خارجي "C" فراغ refresh_پرمختګ_meter(صحيح force_update) { (فراغ)force_update; }
خارجي "C" فراغ stop_پرمختګ_meter(فراغ) { }

ساكن jmp_buf fuzz_env;
ساكن متطاير صحيح دننه_fuzz = 0;

خارجي "C" فراغ
cleanup_exit(صحيح کوډ)
{
	إذا (دننه_fuzz)
		longjmp(fuzz_env, کوډ ? کوډ : 1);
	_exit(کوډ);
}

ساكن ثابت uint8_t k_نسخه_ځواب[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

تعداد {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_لار,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_شمېر,
};

ساكن فراغ
پرلپسې_one(صحيح api, ثابت uint8_t *body, اندازه_t bsize)
{
	صحيح sv[2] = { -1, -1 };
	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		أرجع;

	ssize_t w = اكتب(sv[0], k_نسخه_ځواب, حجم(k_نسخه_ځواب));
	(فراغ)w;
	إذا (bsize > 0)
		w = اكتب(sv[0], body, bsize);
	(فراغ)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	دننه_fuzz = 1;
	إذا (setjmp(fuzz_env) == 0) {
		بنية sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		إذا (conn != عدم) {
			Attrib attr;
			attrib_clear(&attr);

			بدل (api) {
			حالة API_STAT: {
				Attrib a;
				(فراغ)sftp_stat(conn, "/fuzz", 1, &a);
				اكسر;
			}
			حالة API_LSTAT: {
				Attrib a;
				(فراغ)sftp_lstat(conn, "/fuzz", 1, &a);
				اكسر;
			}
			حالة API_REALPATH: {
				حرف *p = sftp_realpath(conn, "/fuzz");
				حرر(p);
				اكسر;
			}
			حالة API_EXPAND_لار: {
				حرف *p = sftp_expand_لار(conn, "~");
				حرر(p);
				اكسر;
			}
			حالة API_READDIR: {
				SFTP_DIRENT **dir = عدم;
				(فراغ)sftp_readdir(conn, "/fuzz", &dir);
				إذا (dir != عدم)
					sftp_free_dirents(dir);
				اكسر;
			}
			حالة API_STATVFS: {
				بنية sftp_statvfs vfs;
				(فراغ)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				اكسر;
			}
			حالة API_GET_LIMITS: {
				بنية sftp_limits lim;
				(فراغ)sftp_get_limits(conn, &lim);
				اكسر;
			}
			حالة API_RM:
				(فراغ)sftp_rm(conn, "/fuzz");
				اكسر;
			حالة API_MKDIR:
				(فراغ)sftp_mkdir(conn, "/fuzz", &attr, 0);
				اكسر;
			حالة API_RMDIR:
				(فراغ)sftp_rmdir(conn, "/fuzz");
				اكسر;
			حالة API_RENAME:
				(فراغ)sftp_rename(conn, "/a", "/b", 0);
				اكسر;
			حالة API_SYMLINK:
				(فراغ)sftp_symlink(conn, "/a", "/b");
				اكسر;
			}

			sftp_free(conn);
		}
	}
	دننه_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

خارجي "C" صحيح
LLVMFuzzer_Test_One_ننوت(ثابت uint8_t *معلومات, اندازه_t اندازه)
{
	ساكن صحيح initialized = 0;
	إذا (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	إذا (اندازه > 65536)
		أرجع 0;

	لكل (صحيح api = 0; api < API_شمېر; api++)
		پرلپسې_one(api, معلومات, اندازه);

	أرجع 0;
}
