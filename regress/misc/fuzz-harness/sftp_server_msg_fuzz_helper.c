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

#अन्तर्भाव <setjmp.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <sys/types.h>

#अन्तर्भाव "log.h"

बाह्य शून्य fuzz_arena_begin(शून्य);
बाह्य शून्य fuzz_arena_release(शून्य);
बाह्य शून्य fuzz_arena_cleanup(शून्य);

स्थिर jmp_buf fuzz_server_env;
स्थिर चञ्चल पूर्णाङ्क अन्तर्_fuzz_server = 0;

शून्य
cleanup_exit(पूर्णाङ्क संहिता)
{
	यदि (अन्तर्_fuzz_server)
		longjmp(fuzz_server_env, संहिता ? संहिता : 1);
	_exit(संहिता);
}

#परिभाषय sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#अन्तर्भाव "../../../sftp-server.c"
#अपरिभाषय sftp_server_cleanup_exit

शून्य
sftp_server_cleanup_exit(पूर्णाङ्क संहिता)
{
	यदि (अन्तर्_fuzz_server)
		longjmp(fuzz_server_env, संहिता ? संहिता : 1);
	_exit(संहिता);
}

स्थिर शून्य (* ध्रुव __force_use_renamed)(पूर्णाङ्क) =
    __orig_sftp_server_cleanup_exit;

स्थिर संरचना passwd fuzz_pw;
स्थिर पूर्णाङ्क log_initialized = 0;

स्थिर शून्य
cleanup_handles(शून्य)
{
	u_int i;
	यदि (handles == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < अङ्कः_handles; i++) {
		यदि (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		अन्यथा यदि (handles[i].use == HANDLE_DIR && handles[i].dirp != रिक्त)
			closedir(handles[i].dirp);
		मुक्त(handles[i].name);
	}
	मुक्त(handles);
	handles = रिक्त;
	अङ्कः_handles = 0;
	first_अप्रयुक्तम्_handle = -1;
}

स्थिर शून्य
reset_module_globals(शून्य)
{
	pw = &fuzz_pw;
	client_addr = रिक्त;
	संस्करणम् = 0;
	init_समाप्तम् = 0;
	readonly = 0;
	request_allowlist = रिक्त;
	request_denylist = रिक्त;
	handles = रिक्त;
	अङ्कः_handles = 0;
	first_अप्रयुक्तम्_handle = -1;
	iqueue = रिक्त;
	oqueue = रिक्त;
}

शून्य
fuzz_server_one(ध्रुव uint8_t *दत्त, आकार_t आकार)
{
	यदि (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		वर्ण tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		यदि (mkdtemp(tmpdir) != रिक्त && chdir(tmpdir) != 0)
			_exit(1);

		स्मृतिं_पूरय(&fuzz_pw, 0, परिमाण(fuzz_pw));
		fuzz_pw.pw_name = (वर्ण *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (वर्ण *)"/tmp";
		fuzz_pw.pw_shell = (वर्ण *)"/bin/sh";
	}

	यदि (आकार == 0 || आकार > 65000)
		प्रत्यागम;

	reset_module_globals();

	fuzz_arena_begin();
	अन्तर्_fuzz_server = 1;
	यदि (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		यदि (iqueue == रिक्त || oqueue == रिक्त)
			गच्छ बहिर्गमनम्;

		ध्रुव uint8_t init_सन्देशः[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		यदि (sshbuf_put(iqueue, init_सन्देशः, परिमाण(init_सन्देशः)) != 0)
			गच्छ बहिर्गमनम्;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((आकार >> 24) & 0xff),
		    (uint8_t)((आकार >> 16) & 0xff),
		    (uint8_t)((आकार >> 8) & 0xff),
		    (uint8_t)(आकार & 0xff),
		};
		यदि (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, दत्त, आकार) != 0)
			गच्छ बहिर्गमनम्;
		process();
	बहिर्गमनम्:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		मुक्त(client_addr);
		iqueue = oqueue = रिक्त;
		client_addr = रिक्त;
		अन्तर्_fuzz_server = 0;
		fuzz_arena_release();
		प्रत्यागम;
	}
	cleanup_handles();
	अन्तर्_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = रिक्त;
	client_addr = रिक्त;
}
