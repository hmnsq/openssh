// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

// Stub out log output to reduce noise
ଶୂନ୍ୟ sshsig_free(ସଂରଚନା sshsig_ctx *ctx) {}

}  // extern "C"

ସ୍ଥିର ସଂରଚନା passwd fuzz_pw;
ସ୍ଥିର ଅକ୍ଷର fuzz_username[] = "fuzzer";
ସ୍ଥିର ଅକ୍ଷର fuzz_home[] = "/tmp";
ସ୍ଥିର ଅକ୍ଷର fuzz_shell[] = "/bin/sh";

ସ୍ଥିର ଶୂନ୍ୟ init_pw(ଶୂନ୍ୟ) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t *data, size_t size) {
    ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା initialized = 0;
    ଯଦି (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    ଅକ୍ଷର tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd = mkstemp(tmpfile);
    ଯଦି (fd < 0)
        ଫେରନ୍ତୁ 0;

    ଯଦି (ଲିଖ(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        ଫେରନ୍ତୁ 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     ଖାଲି, &options, 0, ଖାଲି);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    ଫେରନ୍ତୁ 0;
}
