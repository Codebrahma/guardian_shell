#!/bin/bash
# Landlock + exec diagnostic script for Fedora/SELinux
# Run as root: sudo bash scripts/diagnose-landlock.sh
#
# Tests the landlock+exec incompatibility documented in
# docs/landlock-exec-investigation.md

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Must run as root: sudo bash $0${NC}"
    exit 1
fi

echo "=== Landlock + exec Diagnostic ==="
echo "Kernel: $(uname -r)"
echo "SELinux: $(getenforce 2>/dev/null || echo 'disabled')"
echo "Context: $(id -Z 2>/dev/null || echo 'n/a')"
echo ""

# Build a minimal C test program that does landlock restrict_self() + exec
TESTDIR=$(mktemp -d)
cat > "$TESTDIR/landlock_test.c" << 'CEOF'
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#ifndef LANDLOCK_ACCESS_FS_READ_FILE
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_DIR
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 1)
#endif

static int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static int landlock_add_rule(int fd, enum landlock_rule_type type, const void *attr, __u32 flags) {
    return syscall(__NR_landlock_add_rule, fd, type, attr, flags);
}
static int landlock_restrict_self(int fd, __u32 flags) {
    return syscall(__NR_landlock_restrict_self, fd, flags);
}

int main(int argc, char *argv[]) {
    int do_nnp = 1;
    if (argc > 1 && strcmp(argv[1], "--no-nnp") == 0) do_nnp = 0;

    /* Create minimal landlock ruleset: just ReadFile|ReadDir */
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
    };
    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "landlock_create_ruleset: %s\n", strerror(errno));
        return 1;
    }

    /* Add rule: allow ReadFile|ReadDir on entire filesystem */
    struct landlock_path_beneath_attr path_attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
        .parent_fd = open("/", O_PATH | O_CLOEXEC),
    };
    if (path_attr.parent_fd < 0) {
        perror("open /");
        return 1;
    }
    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0)) {
        fprintf(stderr, "landlock_add_rule: %s\n", strerror(errno));
        return 1;
    }
    close(path_attr.parent_fd);

    /* NNP */
    if (do_nnp) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
            fprintf(stderr, "prctl NNP: %s\n", strerror(errno));
            return 1;
        }
        printf("NNP: set\n");
    } else {
        printf("NNP: skipped\n");
    }

    /* Restrict self */
    if (landlock_restrict_self(ruleset_fd, 0)) {
        fprintf(stderr, "landlock_restrict_self: %s\n", strerror(errno));
        return 1;
    }
    close(ruleset_fd);
    printf("Landlock: restricted (ReadFile|ReadDir on /)\n");

    /* Exec */
    printf("Exec: /usr/bin/echo hello\n");
    execl("/usr/bin/echo", "echo", "SUCCESS: exec after landlock works!", NULL);
    fprintf(stderr, "execl failed: %s (errno %d)\n", strerror(errno), errno);
    return 1;
}
CEOF

echo "--- Step 1: Compile test program ---"
gcc -o "$TESTDIR/landlock_test" "$TESTDIR/landlock_test.c"
echo -e "${GREEN}Compiled: $TESTDIR/landlock_test${NC}"
echo ""

echo "--- Step 2: Test as root with SELinux ENFORCING ---"
echo "Running: landlock restrict_self() + exec as root..."
if "$TESTDIR/landlock_test" 2>&1; then
    echo -e "${GREEN}PASSED: Landlock + exec works as root with SELinux enforcing!${NC}"
    echo "The issue may be specific to guardian-launch, not Landlock+exec in general."
    ENFORCING_WORKS=1
else
    echo -e "${RED}FAILED: Landlock + exec broken as root with SELinux enforcing${NC}"
    ENFORCING_WORKS=0
fi
echo ""

echo "--- Step 3: Test without NNP ---"
if "$TESTDIR/landlock_test" --no-nnp 2>&1; then
    echo -e "${GREEN}PASSED: Works without NNP${NC}"
else
    echo -e "${RED}FAILED: Still broken without NNP${NC}"
fi
echo ""

if [ "$ENFORCING_WORKS" = "0" ]; then
    echo "--- Step 4: Test with SELinux PERMISSIVE ---"
    ORIG_MODE=$(getenforce)
    setenforce 0
    echo "SELinux set to: $(getenforce)"
    if "$TESTDIR/landlock_test" 2>&1; then
        echo -e "${GREEN}PASSED: Landlock + exec works with SELinux permissive!${NC}"
        echo -e "${YELLOW}CONCLUSION: SELinux is blocking exec after landlock_restrict_self()${NC}"
        PERMISSIVE_WORKS=1
    else
        echo -e "${RED}FAILED: Still broken even with SELinux permissive${NC}"
        echo "The issue is NOT SELinux — may be a kernel Landlock bug."
        PERMISSIVE_WORKS=0
    fi
    setenforce "$ORIG_MODE"
    echo "SELinux restored to: $(getenforce)"
    echo ""
fi

if [ "${PERMISSIVE_WORKS:-0}" = "1" ]; then
    echo "--- Step 5: Disable dontaudit rules to find hidden denial ---"
    echo "Running: semodule -DB (this takes a moment)..."
    semodule -DB 2>/dev/null
    echo "dontaudit rules disabled"

    echo "Reproducing failure..."
    "$TESTDIR/landlock_test" 2>&1 || true

    echo ""
    echo "Checking audit log for AVC denials..."
    AVC_OUTPUT=$(ausearch -m AVC -ts recent 2>&1 || true)
    echo "$AVC_OUTPUT"

    echo ""
    echo "Restoring dontaudit rules..."
    semodule -B 2>/dev/null
    echo "dontaudit rules restored"
    echo ""

    if echo "$AVC_OUTPUT" | grep -q "avc:.*denied"; then
        echo -e "${GREEN}Found SELinux denial! Creating policy module...${NC}"
        echo "$AVC_OUTPUT" | audit2allow -M guardian_landlock 2>&1 || true
        echo ""
        echo "To install the fix:"
        echo "  sudo semodule -i guardian_landlock.pp"
        echo ""
        echo "After installing, test again:"
        echo "  sudo $TESTDIR/landlock_test"
    else
        echo -e "${YELLOW}No AVC denial found even with dontaudit disabled.${NC}"
        echo "The denial may come from a non-SELinux security check."
    fi
fi

echo ""
echo "--- Step 6: Test guardian-launch directly ---"
GUARDIAN_BIN="$(dirname "$0")/../target/release/guardian-launch"
if [ -x "$GUARDIAN_BIN" ]; then
    echo "Testing guardian-launch with --no-landlock (baseline)..."
    timeout 5 "$GUARDIAN_BIN" --name test-diag -- /usr/bin/echo "baseline OK" 2>&1 || true
    echo ""
    echo "Testing guardian-launch WITH Landlock..."
    timeout 5 "$GUARDIAN_BIN" --name test-diag2 -- /usr/bin/echo "landlock OK" 2>&1 || true
else
    echo "guardian-launch not found at $GUARDIAN_BIN (skip)"
fi

echo ""
echo "=== Diagnostic complete ==="
echo "Test binary: $TESTDIR/landlock_test"

# Cleanup
rm -f "$TESTDIR/landlock_test.c" "$TESTDIR/landlock_test"
rmdir "$TESTDIR" 2>/dev/null || true
