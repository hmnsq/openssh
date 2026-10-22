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

#অন্তর্ভাৱ <setjmp.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ "log.h"

বাহ্য শূন্য fuzz_arena_begin(শূন্য);
বাহ্য শূন্য fuzz_arena_release(শূন্য);
বাহ্য শূন্য fuzz_arena_cleanup(শূন্য);

স্থির jmp_buf fuzz_server_env;
স্থির চঞ্চল পূর্ণাঙ্ক in_fuzz_server = 0;

শূন্য
cleanup_exit(পূর্ণাঙ্ক code)
{
	যদি (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#অন্তর্ভাৱ "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

শূন্য
sftp_server_cleanup_exit(পূর্ণাঙ্ক code)
{
	যদি (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

স্থির শূন্য (* ধ্রুৱ __force_use_renamed)(পূর্ণাঙ্ক) =
    __orig_sftp_server_cleanup_exit;

স্থির সংরচনা passwd fuzz_pw;
স্থির পূর্ণাঙ্ক log_initialized = 0;

স্থির শূন্য
cleanup_handles(শূন্য)
{
	u_int i;
	যদি (handles == রিক্ত)
		ঘূৰাই;
	বাবে (i = 0; i < অঙ্ক_handles; i++) {
		যদি (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		অন্যথা যদি (handles[i].use == HANDLE_DIR && handles[i].dirp != রিক্ত)
			closedir(handles[i].dirp);
		মুক্ত(handles[i].name);
	}
	মুক্ত(handles);
	handles = রিক্ত;
	অঙ্ক_handles = 0;
	first_unused_handle = -1;
}

স্থির শূন্য
reset_module_globals(শূন্য)
{
	pw = &fuzz_pw;
	client_addr = রিক্ত;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = রিক্ত;
	request_denylist = রিক্ত;
	handles = রিক্ত;
	অঙ্ক_handles = 0;
	first_unused_handle = -1;
	iqueue = রিক্ত;
	oqueue = রিক্ত;
}

শূন্য
fuzz_server_one(ধ্রুৱ uint8_t *data, size_t size)
{
	যদি (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		ৱর্ণ tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		যদি (mkdtemp(tmpdir) != রিক্ত && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, পরিমাণ(fuzz_pw));
		fuzz_pw.pw_name = (ৱর্ণ *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (ৱর্ণ *)"/tmp";
		fuzz_pw.pw_shell = (ৱর্ণ *)"/bin/sh";
	}

	যদি (size == 0 || size > 65000)
		ঘূৰাই;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	যদি (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		যদি (iqueue == রিক্ত || oqueue == রিক্ত)
			গচ্ছ out;

		ধ্রুৱ uint8_t init_বাৰ্তা[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		যদি (sshbuf_put(iqueue, init_বাৰ্তা, পরিমাণ(init_বাৰ্তা)) != 0)
			গচ্ছ out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((size >> 24) & 0xff),
		    (uint8_t)((size >> 16) & 0xff),
		    (uint8_t)((size >> 8) & 0xff),
		    (uint8_t)(size & 0xff),
		};
		যদি (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, data, size) != 0)
			গচ্ছ out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		মুক্ত(client_addr);
		iqueue = oqueue = রিক্ত;
		client_addr = রিক্ত;
		in_fuzz_server = 0;
		fuzz_arena_release();
		ঘূৰাই;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = রিক্ত;
	client_addr = রিক্ত;
}
