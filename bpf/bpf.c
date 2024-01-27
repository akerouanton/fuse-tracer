//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

char LICENSE[] SEC("license") = "GPL";

#define TRACE_FUSE_CONN_STATE 1
#define FUSE_ARG_SZ 128

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

// fuse_simple_request -> __fuse_request_send -> queue_request_and_unlock
// fuse_simple_background -> fuse_request_queue_background -> flush_bg_queue -> queue_request_and_unlock
// fuse_simple_notify_reply -> queue_request_and_unlock
SEC("fentry/queue_request_and_unlock")
int BPF_PROG(trace_fuse_request, struct fuse_iqueue *fiq, struct fuse_req *req) {
    if (req->args == NULL) {
        return 0;
    }

    struct fuse_args *args = BPF_CORE_READ(req, args);

    u32 map_id = 0;
    struct fuse_req_evt *evt = bpf_map_lookup_elem(&req_heap, &map_id);
    if (evt == NULL) {
        return 0;
    }

    evt->start_ktime = bpf_ktime_get_ns();
    evt->in_h = BPF_CORE_READ(req, in.h);
    evt->flags = BPF_CORE_READ(req, flags);

    if (read_fuse_in_args(evt, args) < 0) {
        return 0;
    }
    
    u64 req_id = evt->in_h.unique;
    bpf_map_update_elem(&inflight_reqs, &req_id, evt, 0);

    return 0;
}

static void trace_conn(struct fuse_conn *fc);

// fuse_simple_request -> __fuse_request_send -> request_wait_answer
SEC("fentry/request_wait_answer")
int BPF_PROG(trace_request_wait_answer, struct fuse_req *req) {
    u64 req_id = BPF_CORE_READ(req, in.h.unique);
    if (req_id == 0) {
        return 0;
    }

    struct fuse_req_evt *evt = bpf_map_lookup_elem(&inflight_reqs, &req_id);
    if (evt == NULL) {
        bpf_printk("couldn't find key %d in inflight_reqs", req_id);
        return 0;
    }

    evt->end_ktime = bpf_ktime_get_ns();
    evt->end_flags = BPF_CORE_READ(req, flags);
    
    struct fuse_args *args = BPF_CORE_READ(req, args);
    read_fuse_out_args(evt, args);

    bpf_ringbuf_output(&fuse_req_events, evt, sizeof(struct fuse_req_evt), 0);

#if TRACE_FUSE_CONN_STATE
    struct fuse_conn *fc = BPF_CORE_READ(req, fm, fc);
    trace_conn(fc);
#endif

    return 0;
}

SEC("fentry/fuse_request_end")
int BPF_PROG(trace_fuse_request_end, struct fuse_req *req) {
    u64 req_id = BPF_CORE_READ(req, in.h.unique);
    if (req_id == 0) {
        return 0;
    }

    struct fuse_req_evt *evt = bpf_map_lookup_elem(&inflight_reqs, &req_id);
    if (evt == NULL) {
        bpf_printk("couldn't find key %d in inflight_reqs", req_id);
        return 0;
    }

    evt->end_ktime = bpf_ktime_get_ns();
    evt->end_flags = BPF_CORE_READ(req, flags);
    
    struct fuse_args *args = BPF_CORE_READ(req, args);
    read_fuse_out_args(evt, args);

    bpf_ringbuf_output(&fuse_req_events, evt, sizeof(struct fuse_req_evt), 0);

#if TRACE_FUSE_CONN_STATE
    struct fuse_conn *fc = BPF_CORE_READ(req, fm, fc);
    trace_conn(fc);
#endif

    return 0;
}

// fuse_dev_read | fuse_dev_splice_read -> fuse_dev_do_read -> fuse_request_end
// fuse_dev_write | fuse_dev_splice_write -> fuse_dev_do_write -> fuse_request_end
// end_requests -> fuse_request_end

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct fuse_conn_state);
    __uint(max_entries, 1);
} fc_state_map SEC(".maps");

#define READ_STATE_BITFIELD(state, field_id) (state >> field_id) & 0x1

static void trace_conn(struct fuse_conn *fc) {
    u32 map_id = 0;
    struct fuse_conn_state *fc_state = bpf_map_lookup_elem(&fc_state_map, &map_id);
    if (fc_state == NULL) {
        return;
    }

    fc_state->max_read = BPF_CORE_READ(fc, max_read);
	fc_state->max_write = BPF_CORE_READ(fc, max_write);
	fc_state->max_pages = BPF_CORE_READ(fc, max_pages);
	fc_state->max_pages_limit = BPF_CORE_READ(fc, max_pages_limit);
	fc_state->max_background = BPF_CORE_READ(fc, max_background);
	fc_state->congestion_threshold = BPF_CORE_READ(fc, congestion_threshold);
	fc_state->num_background = BPF_CORE_READ(fc, num_background);
	fc_state->active_background = BPF_CORE_READ(fc, active_background);

    u64 state;
    if (bpf_probe_read_kernel(&state, 8, &fc->aborted) < 0) {
        bpf_printk("couldn't read conn_error");
        return;
    }
    state = state >> 8;

    int i = 0;
	fc_state->conn_error = READ_STATE_BITFIELD(state, i++);
	fc_state->conn_init = READ_STATE_BITFIELD(state, i++);
	fc_state->async_read = READ_STATE_BITFIELD(state, i++);
	fc_state->abort_err = READ_STATE_BITFIELD(state, i++);
	fc_state->atomic_o_trunc = READ_STATE_BITFIELD(state, i++);
	fc_state->export_support = READ_STATE_BITFIELD(state, i++);
	fc_state->writeback_cache = READ_STATE_BITFIELD(state, i++);
	fc_state->parallel_dirops = READ_STATE_BITFIELD(state, i++);
    fc_state->handle_killpriv = READ_STATE_BITFIELD(state, i++);
	fc_state->cache_symlinks = READ_STATE_BITFIELD(state, i++);
	fc_state->legacy_opts_show = READ_STATE_BITFIELD(state, i++);
	fc_state->handle_killpriv_v2 = READ_STATE_BITFIELD(state, i++);
	fc_state->no_open = READ_STATE_BITFIELD(state, i++);
	fc_state->no_opendir = READ_STATE_BITFIELD(state, i++);
	fc_state->no_fsync = READ_STATE_BITFIELD(state, i++);
	fc_state->no_fsyncdir = READ_STATE_BITFIELD(state, i++);
    fc_state->no_flush = READ_STATE_BITFIELD(state, i++);
	fc_state->no_setxattr = READ_STATE_BITFIELD(state, i++);
	fc_state->setxattr_ext = READ_STATE_BITFIELD(state, i++);
	fc_state->no_getxattr = READ_STATE_BITFIELD(state, i++);
	fc_state->no_listxattr = READ_STATE_BITFIELD(state, i++);
	fc_state->no_removexattr = READ_STATE_BITFIELD(state, i++);
	fc_state->no_lock = READ_STATE_BITFIELD(state, i++);
	fc_state->no_access = READ_STATE_BITFIELD(state, i++);
    fc_state->no_create = READ_STATE_BITFIELD(state, i++);
	fc_state->no_interrupt = READ_STATE_BITFIELD(state, i++);
	fc_state->no_bmap = READ_STATE_BITFIELD(state, i++);
	fc_state->no_poll = READ_STATE_BITFIELD(state, i++);
	fc_state->big_writes = READ_STATE_BITFIELD(state, i++);
	fc_state->dont_mask = READ_STATE_BITFIELD(state, i++);
	fc_state->no_flock = READ_STATE_BITFIELD(state, i++);
	fc_state->no_fallocate = READ_STATE_BITFIELD(state, i++);
    fc_state->no_rename2 = READ_STATE_BITFIELD(state, i++);
	fc_state->auto_inval_data = READ_STATE_BITFIELD(state, i++);
	fc_state->explicit_inval_data = READ_STATE_BITFIELD(state, i++);
	fc_state->do_readdirplus = READ_STATE_BITFIELD(state, i++);
	fc_state->readdirplus_auto = READ_STATE_BITFIELD(state, i++);
	fc_state->async_dio = READ_STATE_BITFIELD(state, i++);
	fc_state->no_lseek = READ_STATE_BITFIELD(state, i++);
	fc_state->posix_acl = READ_STATE_BITFIELD(state, i++);
    fc_state->default_permissions = READ_STATE_BITFIELD(state, i++);
	fc_state->allow_other = READ_STATE_BITFIELD(state, i++);
	fc_state->no_copy_file_range = READ_STATE_BITFIELD(state, i++);
	fc_state->destroy = READ_STATE_BITFIELD(state, i++);
	fc_state->delete_stale = READ_STATE_BITFIELD(state, i++);
	fc_state->no_control = READ_STATE_BITFIELD(state, i++);
	fc_state->no_force_umount = READ_STATE_BITFIELD(state, i++);
	fc_state->auto_submounts = READ_STATE_BITFIELD(state, i++);
	fc_state->sync_fs = READ_STATE_BITFIELD(state, i++);
	fc_state->init_security = READ_STATE_BITFIELD(state, i++);
	fc_state->create_supp_group = READ_STATE_BITFIELD(state, i++);
	fc_state->inode_dax = READ_STATE_BITFIELD(state, i++);
	fc_state->no_tmpfile = READ_STATE_BITFIELD(state, i++);
	fc_state->direct_io_allow_mmap = READ_STATE_BITFIELD(state, i++);
	fc_state->no_statx = READ_STATE_BITFIELD(state, i++);

	if (bpf_map_update_elem(&fc_state_map, &map_id, fc_state, 0) < 0) {
		bpf_printk("couldn't update fc_state_map.");
	}
}
