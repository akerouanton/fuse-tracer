//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

char LICENSE[] SEC("license") = "GPL";

#define FUSE_ARG_SZ 128
#define PERF_MAX_STACK_DEPTH 127

#define TRACE_TYPE_REQ  1
#define TRACE_TYPE_RESP 2

volatile const u8 trace_type;

struct fuse_conn_state {
    u16 max_read;
	u16 max_write;
	u16 max_pages;
	u16 max_pages_limit;
	u16 max_background;
	u16 congestion_threshold;
	u16 num_background;
	u8 active_background:1;
	u8 conn_error:1;
	u8 conn_init:1;
	u8 async_read:1;
	u8 abort_err:1;
	u8 atomic_o_trunc:1;
	u8 export_support:1;
	u8 writeback_cache:1;
	u8 parallel_dirops:1;
	u8 handle_killpriv:1;
	u8 cache_symlinks:1;
	u8 legacy_opts_show:1;
	u8 handle_killpriv_v2:1;
	u8 no_open:1;
	u8 no_opendir:1;
	u8 no_fsync:1;
	u8 no_fsyncdir:1;
	u8 no_flush:1;
	u8 no_setxattr:1;
	u8 setxattr_ext:1;
	u8 no_getxattr:1;
	u8 no_listxattr:1;
	u8 no_removexattr:1;
	u8 no_lock:1;
	u8 no_access:1;
	u8 no_create:1;
	u8 no_interrupt:1;
	u8 no_bmap:1;
	u8 no_poll:1;
	u8 big_writes:1;
	u8 dont_mask:1;
	u8 no_flock:1;
	u8 no_fallocate:1;
	u8 no_rename2:1;
	u8 auto_inval_data:1;
	u8 explicit_inval_data:1;
	u8 do_readdirplus:1;
	u8 readdirplus_auto:1;
	u8 async_dio:1;
	u8 no_lseek:1;
	u8 posix_acl:1;
	u8 default_permissions:1;
	u8 allow_other:1;
	u8 no_copy_file_range:1;
	u8 destroy:1;
	u8 delete_stale:1;
	u8 no_control:1;
	u8 no_force_umount:1;
	u8 auto_submounts:1;
	u8 sync_fs:1;
	u8 init_security:1;
	u8 create_supp_group:1;
	u8 inode_dax:1;
	u8 no_tmpfile:1;
	u8 direct_io_allow_mmap:1;
	u8 no_statx:1;
};

struct _fuse_arg {
    u16 size;
    u8 value[FUSE_ARG_SZ];
};

struct fuse_req_evt {
    u64 start_ktime;
    u64 end_ktime;
    struct fuse_in_header in_h;
    u64 flags;
    u64 end_flags;

    u8 in_numargs;
    struct _fuse_arg in_args[3];
    
    u8 out_numargs;
    struct _fuse_arg out_args[3];

    u32 stack_id;
    struct fuse_conn_state conn_state;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct fuse_req_evt);
    __uint(max_entries, 1);
} req_heap SEC(".maps"); // We don't have a heap but we've maps

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, u32);
    __type(value, struct fuse_req_evt);
    __uint(max_entries, 1024);
} inflight_reqs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} fuse_req_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 1024);
} stacktraces SEC(".maps");

static void read_fuse_conn_state(struct fuse_conn *fc, struct fuse_conn_state *conn_state);

static int read_fuse_in_arg(struct _fuse_arg *dst, struct fuse_args *args, int arg_id) {
    struct fuse_in_arg arg = BPF_CORE_READ(args, in_args[arg_id]);
    
    u16 arg_size = arg.size;
    if (arg_size > FUSE_ARG_SZ) {
        arg_size = FUSE_ARG_SZ;
    }
    if (arg_size <= 0) {
        return 0;
    }

    if (bpf_probe_read_kernel(&dst->value, arg_size, arg.value) < 0) {
        return -1;
    }

    // The BPF verifier rejects the program when dst->size is assigned from arg_size.
    // So we've to reimplement the same logic a second time here...
    dst->size = arg.size;
    if (dst->size > FUSE_ARG_SZ) {
        dst->size = FUSE_ARG_SZ;
    } else if (dst->size <= 0) {
        dst->size = 0;
    }

    return 0;
}

static int read_fuse_in_args(struct fuse_req_evt *evt, struct fuse_args *args) {
    evt->in_numargs = BPF_CORE_READ(args, in_numargs);

    for (int i = 0; i < 3 && i < evt->in_numargs; i++) {
        if (read_fuse_in_arg(&evt->in_args[i], args, i) < 0) {
            bpf_printk("couldn't read fuse in_arg%d", i);
        }
    }

    return 0;
}

static int read_fuse_out_arg(struct _fuse_arg *dst, struct fuse_args *args, int arg_id) {
    struct fuse_arg arg = BPF_CORE_READ(args, out_args[arg_id]);
    
    int arg_size = arg.size;
    if (arg_size > FUSE_ARG_SZ) {
        arg_size = FUSE_ARG_SZ;
    }
    if (arg_size <= 0) {
        return 0;
    }

    if (bpf_probe_read_kernel(&dst->value, arg_size, arg.value) < 0) {
        return -1;
    }

    // The BPF verifier rejects the program when dst->size is assigned from arg_size.
    // So we've to reimplement the same logic a second time here...
    dst->size = arg.size;
    if (dst->size > FUSE_ARG_SZ) {
        dst->size = FUSE_ARG_SZ;
    } else if (dst->size <= 0) {
        dst->size = 0;
    }

    return 0;
}

static int read_fuse_out_args(struct fuse_req_evt *evt, struct fuse_args *args) {
    evt->out_numargs = BPF_CORE_READ(args, out_numargs);

    for (int i = 0; i < 3 && i < evt->out_numargs; i++) {
        if (read_fuse_out_arg(&evt->out_args[i], args, i) < 0) {
            bpf_printk("couldn't read fuse out_arg%d", i);
        }
    }

    return 0;
}

static struct fuse_req_evt *new_fuse_req_evt(unsigned long long *ctx, struct fuse_req *req) {
    u32 map_id = 0;
    struct fuse_req_evt *evt = bpf_map_lookup_elem(&req_heap, &map_id);
    if (evt == NULL) {
        return 0;
    }

    struct fuse_args *args = BPF_CORE_READ(req, args);
    if (args != NULL) {
        read_fuse_in_args(evt, args);
    }

    evt->in_h = BPF_CORE_READ(req, in.h);
    evt->flags = BPF_CORE_READ(req, flags);
    evt->stack_id = bpf_get_stackid(ctx, &stacktraces, BPF_F_FAST_STACK_CMP);

    return evt;
}

// fuse_simple_request -> __fuse_request_send -> queue_request_and_unlock
// fuse_simple_background -> fuse_request_queue_background -> flush_bg_queue -> queue_request_and_unlock
// fuse_simple_notify_reply -> queue_request_and_unlock
SEC("fentry/queue_request_and_unlock")
int BPF_PROG(trace_fuse_request, struct fuse_iqueue *fiq, struct fuse_req *req) {
    if ((trace_type & TRACE_TYPE_REQ) != TRACE_TYPE_REQ) {
        return 0;
    }

    if (req->args == NULL) {
        return 0;
    }
    
    struct fuse_req_evt *evt = new_fuse_req_evt(ctx, req);
    if (evt == 0) {
        return 0;
    }
    
    evt->start_ktime = bpf_ktime_get_ns();

    if ((trace_type ^ TRACE_TYPE_REQ) != 0) {
        u64 req_id = evt->in_h.unique;
        bpf_map_update_elem(&inflight_reqs, &req_id, evt, 0);
    } else {
        bpf_ringbuf_output(&fuse_req_events, evt, sizeof(struct fuse_req_evt), 0);
    }

    return 0;
}

static int trace_response(unsigned long long *ctx, struct fuse_req *req) {
    u64 req_id = BPF_CORE_READ(req, in.h.unique);
    if (req_id == 0) {
        return 0;
    }

    struct fuse_req_evt *evt;
    if ((trace_type & TRACE_TYPE_REQ) == TRACE_TYPE_REQ) {
        evt = bpf_map_lookup_elem(&inflight_reqs, &req_id);
        if (evt == NULL) {
            bpf_printk("couldn't find key %d in inflight_reqs", req_id);
        }
    }
    
    if (evt == NULL) {
        evt = new_fuse_req_evt(ctx, req);
        if (evt == 0) {
            return 0;
        }
    }

    evt->end_ktime = bpf_ktime_get_ns();
    evt->end_flags = BPF_CORE_READ(req, flags);
    
    struct fuse_args *args = BPF_CORE_READ(req, args);
    read_fuse_out_args(evt, args);

    struct fuse_conn *fc = BPF_CORE_READ(req, fm, fc);
    read_fuse_conn_state(fc, &evt->conn_state);

    bpf_ringbuf_output(&fuse_req_events, evt, sizeof(struct fuse_req_evt), 0);

    return 0;
}

// fuse_simple_request -> __fuse_request_send -> request_wait_answer
SEC("fentry/request_wait_answer")
int BPF_PROG(trace_request_wait_answer, struct fuse_req *req) {
    return trace_response(ctx, req);
}

// fuse_dev_read | fuse_dev_splice_read -> fuse_dev_do_read -> fuse_request_end
// fuse_dev_write | fuse_dev_splice_write -> fuse_dev_do_write -> fuse_request_end
// end_requests -> fuse_request_end
SEC("fentry/fuse_request_end")
int BPF_PROG(trace_fuse_request_end, struct fuse_req *req) {
    return trace_response(ctx, req);
}

SEC("fentry/filp_close")
int BPF_PROG(trace_filp_close, struct file *filp) {
    /* if (bpf_core_read(&mod_name, sizeof(mod_name), &filp->f_op->flush) < 0) {
        bpf_printk("couldn't read filp->f_op->owner->name");
        return 0;
    } */

    bpf_printk("filp_close - filp->f_op->flush: %d", filp->f_op->flush);
    return 0;
}

SEC("fentry/do_dentry_open")
int BPF_PROG(trace_do_dentry_open, struct file *f, struct inode *inode, int (*open)(struct inode *, struct file *)) {
    const char *name = BPF_CORE_READ(f, f_path.dentry, d_name.name);

    char comm[64];
    bpf_get_current_comm(comm, sizeof(comm));
    if (bpf_strncmp(comm, 10, "containerd") == 0 || bpf_strncmp(comm, 9, "lifecycle") == 0 || bpf_strncmp(comm, 7, "dockerd") == 0 || bpf_strncmp(comm, 4, "runc") == 0) {
        return 0;
    }

    bpf_printk("do_dentry_open: %s - flags: %u", name, f->f_flags);
    return 0;
}

SEC("fentry/vp_vring_interrupt")
int BPF_PROG(trace_vp_vring_interrupt, int irq, void *opaque) {
    bpf_printk("vp_vring_interrupt: %d", irq);
    return 0;
}

#define READ_STATE_BITFIELD(state, field_id) (state >> field_id) & 0x1

static void read_fuse_conn_state(struct fuse_conn *fc, struct fuse_conn_state *conn_state) {
    conn_state->max_read = BPF_CORE_READ(fc, max_read);
	conn_state->max_write = BPF_CORE_READ(fc, max_write);
	conn_state->max_pages = BPF_CORE_READ(fc, max_pages);
	conn_state->max_pages_limit = BPF_CORE_READ(fc, max_pages_limit);
	conn_state->max_background = BPF_CORE_READ(fc, max_background);
	conn_state->congestion_threshold = BPF_CORE_READ(fc, congestion_threshold);
	conn_state->num_background = BPF_CORE_READ(fc, num_background);
	conn_state->active_background = BPF_CORE_READ(fc, active_background);

    u64 state;
    if (bpf_probe_read_kernel(&state, 8, &fc->aborted) < 0) {
        bpf_printk("couldn't read conn_error");
        return;
    }
    state = state >> 8;

    int i = 0;
	conn_state->conn_error = READ_STATE_BITFIELD(state, i++);
	conn_state->conn_init = READ_STATE_BITFIELD(state, i++);
	conn_state->async_read = READ_STATE_BITFIELD(state, i++);
	conn_state->abort_err = READ_STATE_BITFIELD(state, i++);
	conn_state->atomic_o_trunc = READ_STATE_BITFIELD(state, i++);
	conn_state->export_support = READ_STATE_BITFIELD(state, i++);
	conn_state->writeback_cache = READ_STATE_BITFIELD(state, i++);
	conn_state->parallel_dirops = READ_STATE_BITFIELD(state, i++);
    conn_state->handle_killpriv = READ_STATE_BITFIELD(state, i++);
	conn_state->cache_symlinks = READ_STATE_BITFIELD(state, i++);
	conn_state->legacy_opts_show = READ_STATE_BITFIELD(state, i++);
	conn_state->handle_killpriv_v2 = READ_STATE_BITFIELD(state, i++);
	conn_state->no_open = READ_STATE_BITFIELD(state, i++);
	conn_state->no_opendir = READ_STATE_BITFIELD(state, i++);
	conn_state->no_fsync = READ_STATE_BITFIELD(state, i++);
	conn_state->no_fsyncdir = READ_STATE_BITFIELD(state, i++);
    conn_state->no_flush = READ_STATE_BITFIELD(state, i++);
	conn_state->no_setxattr = READ_STATE_BITFIELD(state, i++);
	conn_state->setxattr_ext = READ_STATE_BITFIELD(state, i++);
	conn_state->no_getxattr = READ_STATE_BITFIELD(state, i++);
	conn_state->no_listxattr = READ_STATE_BITFIELD(state, i++);
	conn_state->no_removexattr = READ_STATE_BITFIELD(state, i++);
	conn_state->no_lock = READ_STATE_BITFIELD(state, i++);
	conn_state->no_access = READ_STATE_BITFIELD(state, i++);
    conn_state->no_create = READ_STATE_BITFIELD(state, i++);
	conn_state->no_interrupt = READ_STATE_BITFIELD(state, i++);
	conn_state->no_bmap = READ_STATE_BITFIELD(state, i++);
	conn_state->no_poll = READ_STATE_BITFIELD(state, i++);
	conn_state->big_writes = READ_STATE_BITFIELD(state, i++);
	conn_state->dont_mask = READ_STATE_BITFIELD(state, i++);
	conn_state->no_flock = READ_STATE_BITFIELD(state, i++);
	conn_state->no_fallocate = READ_STATE_BITFIELD(state, i++);
    conn_state->no_rename2 = READ_STATE_BITFIELD(state, i++);
	conn_state->auto_inval_data = READ_STATE_BITFIELD(state, i++);
	conn_state->explicit_inval_data = READ_STATE_BITFIELD(state, i++);
	conn_state->do_readdirplus = READ_STATE_BITFIELD(state, i++);
	conn_state->readdirplus_auto = READ_STATE_BITFIELD(state, i++);
	conn_state->async_dio = READ_STATE_BITFIELD(state, i++);
	conn_state->no_lseek = READ_STATE_BITFIELD(state, i++);
	conn_state->posix_acl = READ_STATE_BITFIELD(state, i++);
    conn_state->default_permissions = READ_STATE_BITFIELD(state, i++);
	conn_state->allow_other = READ_STATE_BITFIELD(state, i++);
	conn_state->no_copy_file_range = READ_STATE_BITFIELD(state, i++);
	conn_state->destroy = READ_STATE_BITFIELD(state, i++);
	conn_state->delete_stale = READ_STATE_BITFIELD(state, i++);
	conn_state->no_control = READ_STATE_BITFIELD(state, i++);
	conn_state->no_force_umount = READ_STATE_BITFIELD(state, i++);
	conn_state->auto_submounts = READ_STATE_BITFIELD(state, i++);
	conn_state->sync_fs = READ_STATE_BITFIELD(state, i++);
	conn_state->init_security = READ_STATE_BITFIELD(state, i++);
	conn_state->create_supp_group = READ_STATE_BITFIELD(state, i++);
	conn_state->inode_dax = READ_STATE_BITFIELD(state, i++);
	conn_state->no_tmpfile = READ_STATE_BITFIELD(state, i++);
	conn_state->direct_io_allow_mmap = READ_STATE_BITFIELD(state, i++);
	conn_state->no_statx = READ_STATE_BITFIELD(state, i++);
}
