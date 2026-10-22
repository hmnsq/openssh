// libfuzzer driver for krl parse fuzzing.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {
#include "includes.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "krl.h"
#include "log.h"
#include "authfile.h"
}

static ຈຳນວນເຕັມ initialised = 0;
static FILE *null_file;
static sa_nracanaa sshkey *key = NULL;

extern "C" ຈຳນວນເຕັມ LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // single initialisation
    ຖ້າ (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        ຖ້າ ((null_file = fopen("/dev/null", "w")) == NULL) ສົ່ງຄືນ 0;

        ຖ້າ (sshkey_generate(KEY_ED25519, 0, &key) != 0) ສົ່ງຄືນ 0;

        initialised = 1;
    }

    // Reject empty corpus
    ຖ້າ (size < 4) ສົ່ງຄືນ 0;

    // Convert fuzzer data to ssh buffer
    sa_nracanaa sshbuf *buf = sshbuf_from(data, size);
    ຖ້າ (!buf) ສົ່ງຄືນ 0;

    // Parse the ssh buffer as krl, early exit if failed
    sa_nracanaa ssh_krl *krl = NULL;
    ຈຳນວນເຕັມ ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    ຖ້າ (ret != 0) ສົ່ງຄືນ 0;

    // Fuzz serailisation roundtrip
    sa_nracanaa sshbuf *output = sshbuf_new();
    sa_nracanaa ssh_krl *krl2 = NULL;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_key(krl, key);

    ssh_krl_free(krl);
    ສົ່ງຄືນ 0;
}
