// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <unistd.h>

બાહ્ય "C" {

#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "readconf.h"
#અન્તર્ભાવ "xmalloc.h"

// Stub out log output to reduce noise
શૂન્ય sshsig_free(સંરચના sshsig_ctx *ctx) {}

}  // extern "C"

સ્થિર સંરચના passwd fuzz_pw;
સ્થિર અક્ષર fuzz_username[] = "fuzzer";
સ્થિર અક્ષર fuzz_home[] = "/tmp";
સ્થિર અક્ષર fuzz_shell[] = "/bin/sh";

સ્થિર શૂન્ય init_pw(શૂન્ય) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

બાહ્ય "C" પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t *data, size_t size) {
    સ્થિર પૂર્ણાંક initialized = 0;
    જો (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    અક્ષર tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    પૂર્ણાંક fd = mkstemp(tmpfile);
    જો (fd < 0)
        પાછા 0;

    જો (લિખ(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        પાછા 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     ખાલી, &options, 0, ખાલી);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    પાછા 0;
}
