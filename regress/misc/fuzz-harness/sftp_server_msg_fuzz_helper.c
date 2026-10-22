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
 * Fuzzer for OpenSSH SFTP server message dispatch (sftp-server.c)
 *
 * Target: sftp-server.c
 *
 * Follows the agent_fuzz_helper.c pattern: #include's sftp-server.c so
 * process() and the static process_* handlers, plus the file-scope
 * globals (iqueue, oqueue, pw, init_done, handles), are reachable from
 * this translation unit. Each iteration bootstraps an FXP_INIT then
 * feeds the fuzzer input as a single framed SFTP message.
 *
 * Primary functions exercised:
 * - process() and the 17 base process_* handlers (open / close / read /
 *   write / stat / lstat / fstat / setstat / fsetstat / opendir /
 *   readdir / remove / mkdir / rmdir / realpath / rename / readlink /
 *   symlink)
 * - process_extended_* (11 variants including posix-rename, statvfs,
 *   hardlink, fsync, lsetstat, limits, expand-path, copy-data,
 *   home-directory, users-groups-by-id)
 * - decode_attrib / encode_attrib (sftp-common.c)
 *
 * Failure handling: fatal() -> cleanup_exit() and
 * sftp_server_cleanup_exit() are intercepted with overriding
 * definitions that longjmp() back to the entry point. fuzz_arena
 * (linker --wrap'd malloc family) frees every still-live allocation on
 * recovery so LSan sees zero per-iteration leaks.
 */

#অন্তর্ভাব <setjmp.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব "log.h"

বাহ্যিক শূন্য fuzz_arena_begin(শূন্য);
বাহ্যিক শূন্য fuzz_arena_release(শূন্য);
বাহ্যিক শূন্য fuzz_arena_cleanup(শূন্য);

স্থির jmp_buf fuzz_server_env;
স্থির অস্থির পূর্ণসংখ্যা in_fuzz_server = 0;

শূন্য
cleanup_exit(পূর্ণসংখ্যা code)
{
	যদি (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#অন্তর্ভাব "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

শূন্য
sftp_server_cleanup_exit(পূর্ণসংখ্যা code)
{
	যদি (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

স্থির শূন্য (* ধ্রুবক __force_use_renamed)(পূর্ণসংখ্যা) =
    __orig_sftp_server_cleanup_exit;

স্থির কাঠামো passwd fuzz_pw;
স্থির পূর্ণসংখ্যা log_initialized = 0;

স্থির শূন্য
cleanup_handles(শূন্য)
{
	u_int i;
	যদি (handles == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < অঙ্ক_handles; i++) {
		যদি (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		অন্যথা যদি (handles[i].use == HANDLE_DIR && handles[i].dirp != ফাঁকা)
			closedir(handles[i].dirp);
		মুক্ত(handles[i].name);
	}
	মুক্ত(handles);
	handles = ফাঁকা;
	অঙ্ক_handles = 0;
	first_unused_handle = -1;
}

স্থির শূন্য
reset_module_globals(শূন্য)
{
	pw = &fuzz_pw;
	client_addr = ফাঁকা;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = ফাঁকা;
	request_denylist = ফাঁকা;
	handles = ফাঁকা;
	অঙ্ক_handles = 0;
	first_unused_handle = -1;
	iqueue = ফাঁকা;
	oqueue = ফাঁকা;
}

শূন্য
fuzz_server_one(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	যদি (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		অক্ষর tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		যদি (mkdtemp(tmpdir) != ফাঁকা && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, আকার(fuzz_pw));
		fuzz_pw.pw_name = (অক্ষর *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (অক্ষর *)"/tmp";
		fuzz_pw.pw_shell = (অক্ষর *)"/bin/sh";
	}

	যদি (আকার_2 == 0 || আকার_2 > 65000)
		ফেরত;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	যদি (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		যদি (iqueue == ফাঁকা || oqueue == ফাঁকা)
			যাও out;

		ধ্রুবক uint8_t init_বার্তা[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		যদি (sshbuf_put(iqueue, init_বার্তা, আকার(init_বার্তা)) != 0)
			যাও out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((আকার_2 >> 24) & 0xff),
		    (uint8_t)((আকার_2 >> 16) & 0xff),
		    (uint8_t)((আকার_2 >> 8) & 0xff),
		    (uint8_t)(আকার_2 & 0xff),
		};
		যদি (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, তথ্য, আকার_2) != 0)
			যাও out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		মুক্ত(client_addr);
		iqueue = oqueue = ফাঁকা;
		client_addr = ফাঁকা;
		in_fuzz_server = 0;
		fuzz_arena_release();
		ফেরত;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = ফাঁকা;
	client_addr = ফাঁকা;
}
