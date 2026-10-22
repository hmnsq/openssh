// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <unistd.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "readconf.h"
#അന്തര്ഭാവ "xmalloc.h"

// Stub out log output to reduce noise
ശൂന്യം sshsig_free(ഘടന sshsig_ctx *ctx) {}

}  // extern "C"

സ്ഥിതം ഘടന passwd fuzz_pw;
സ്ഥിതം അക്ഷരം fuzz_username[] = "fuzzer";
സ്ഥിതം അക്ഷരം fuzz_home[] = "/tmp";
സ്ഥിതം അക്ഷരം fuzz_shell[] = "/bin/sh";

സ്ഥിതം ശൂന്യം init_pw(ശൂന്യം) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t *data, size_t size) {
    സ്ഥിതം പൂർണ്ണസംഖ്യ initialized = 0;
    എങ്കിൽ (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    അക്ഷരം tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    പൂർണ്ണസംഖ്യ fd = mkstemp(tmpfile);
    എങ്കിൽ (fd < 0)
        തിരികെ 0;

    എങ്കിൽ (ലിഖ(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        തിരികെ 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     ശൂന്യ, &options, 0, ശൂന്യ);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    തിരികെ 0;
}
