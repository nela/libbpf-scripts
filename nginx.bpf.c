#include "ngx_http.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* SEC("uprobe//usr/sbin/nginx:ngx_http_finalize_request")
int BPF_KPROBE(handle_ngx_request, struct pt_regs *ctx, struct ngx_http_request_s *r, ngx_int_t rc)
{

    if (&r->request_line == NULL) return -45;

    err = bpf_probe_read_user(&s_ptr, sizeof(s_ptr), &r->request_line.data);
    if (!s_ptr || err < 0) {
	bpf_printk("Error %d\n", err);
	return -2;
    }

    bpf_probe_read_user_str(str, sizeof(str), &s_ptr);

    bpf_printk("String: %s\n", str);

    return 0;
} */

SEC("uprobe//usr/sbin/nginx:ngx_http_finalize_request")
int BPF_KPROBE(handle_ngx_http_finalize_request,
               struct ngx_http_request_s* r, ngx_int_t rc)
{
    u_char *s_ptr;
    u_char str[128];
    int err;

    /* you can access rc directly now, btw */

    s_ptr = BPF_PROBE_READ_USER(r, request_line.data);
    /* note no dereferencing of s_ptr above */
    bpf_probe_read_user_str(str, sizeof(str), s_ptr);

    bpf_printk("String: %s\n", str);

    return 0;
}

/* SEC("uprobe//usr/sbin/nginx:ngx_http_finalize_request")
int handle_ngx_http_finalize_request(struct ngx_http_request_s* r, ngx_int_t rc)
{
    u_char *s_ptr;
    u_char str[128];
    int err;

    err = bpf_probe_read_user(&s_ptr, sizeof(s_ptr), &r->request_line.data);
    if (!s_ptr || err < 0) {
        bpf_printk("Error %d\n", err);
        return -2;
    }

    bpf_probe_read_user_str(str, sizeof(str), &s_ptr);

    bpf_printk("String: %s\n", str);

    return 0;
} */
