/* Diagnostic only: execute CPU instructions; never print or supply entropy. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/auxv.h>
#endif
#ifdef __APPLE__
#include <Hypervisor/Hypervisor.h>
#endif

static void probe(int which) {
    uint64_t value;
    if (which == 0) {
        __asm__ volatile("mrs %0, ID_AA64ISAR0_EL1" : "=r"(value));
        printf("host ISAR0=%#018llx RNDR=%llu\n",
               (unsigned long long)value, (unsigned long long)(value >> 60));
        return;
    }
    unsigned successes = 0;
    for (unsigned i = 0; i < 100; i++) {
        unsigned ok;
        if (which == 1) {
            __asm__ volatile("mrs %0, S3_3_C2_C4_0\n\tcset %w1, ne"
                             : "=r"(value), "=r"(ok) :: "cc");
        } else {
            __asm__ volatile("mrs %0, S3_3_C2_C4_1\n\tcset %w1, ne"
                             : "=r"(value), "=r"(ok) :: "cc");
        }
        successes += ok;
    }
    printf("%s executed: %u successful reads / 100\n",
           which == 1 ? "RNDR" : "RNDRRS", successes);
}

int main(void) {
#ifdef __linux__
    unsigned long caps = getauxval(AT_HWCAP2);
    printf("host HWCAP2=%#lx RNG=%lu\n", caps, (caps >> 16) & 1);
#endif
#ifdef __APPLE__
    hv_vcpu_config_t config = hv_vcpu_config_create();
    uint64_t value = 0;
    hv_return_t status = hv_vcpu_config_get_feature_reg(
        config, HV_FEATURE_REG_ID_AA64ISAR0_EL1, &value);
    printf("HVF default config status=%#x ISAR0=%#018llx RNDR=%llu\n",
           status, (unsigned long long)value, (unsigned long long)(value >> 60));
    os_release(config);
#endif
    const char *names[] = {"host ID register", "host RNDR", "host RNDRRS"};
    for (int i = 0; i < 3; i++) {
        fflush(NULL);
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid == 0) { probe(i); fflush(NULL); _exit(0); }
        int status;
        if (waitpid(pid, &status, 0) != pid) { perror("waitpid"); return 1; }
        if (WIFSIGNALED(status))
            printf("%s: signal %d\n", names[i], WTERMSIG(status));
        else
            printf("%s: exit %d\n", names[i], WEXITSTATUS(status));
    }
    return 0;
}
