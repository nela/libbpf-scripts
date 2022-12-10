#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "nginx.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

ssize_t get_uprobe_offset(const void *addr)
{
    size_t start, end, base;
    char buf[256];
    bool found = false;
    FILE *f;

    f = fopen("/proc/self/maps", "r");
    if (!f)
        return -errno;

    while (fscanf(f, "%zx-%zx %s %zx %*[^\n]\n", &start, &end, buf, &base) == 4) {
        if (buf[2] == 'x' && (uintptr_t)addr >= start && (uintptr_t)addr < end) {
            found = true;
            break;
        }
    }

    fclose(f);

    if (!found)
        return -ESRCH;

    return (uintptr_t)addr - start + base;
}

int main(int argc, char **argv)
{
    struct nginx_bpf *skel;
    int err;
    // long nginx_offset;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    skel = nginx_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // nginx_offset = get_uprobe_offset(&ngx_http_finalize_request);
    //
    // /* Attach tracepoint handler */
    // skel->links.handle_ngx_http_finalize_request = bpf_program__attach_uprobe(skel->progs.handle_ngx_http_finalize_request,
    //                                                     false /* not uretprobe */,
    //                                                     -1 /* self pid */,
    //                                                     "/usr/sbin/nginx",
    //                                                     nginx_offset);
    // if (!skel->links.handle_ngx_http_finalize_request) {
    //         err = -errno;
    //         fprintf(stderr, "Failed to attach uprobe: %d\n", err);
    //         goto cleanup;
    // }

    err = nginx_bpf__attach(skel);
    if (err) {
            fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
            goto cleanup;
    }

    printf("Successfully started!\n");

    for (;;) {
        // trigger our BPF program
        // fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    nginx_bpf__destroy(skel);
    return -err;
}
