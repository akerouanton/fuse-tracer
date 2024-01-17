//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

char LICENSE[] SEC("license") = "GPL";

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
            return -1;
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
            return -1;
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
    if (read_fuse_out_args(evt, args) < 0) {
        return 0;
    }

    bpf_ringbuf_output(&fuse_req_events, evt, sizeof(struct fuse_req_evt), 0);

    struct fuse_conn *fc = BPF_CORE_READ(req, fm, fc);
    trace_conn(fc);

    return 0;
}

// fuse_dev_read | fuse_dev_splice_read -> fuse_dev_do_read -> fuse_request_end
// fuse_dev_write | fuse_dev_splice_write -> fuse_dev_do_write -> fuse_request_end
// end_requests -> fuse_request_end

struct fuse_conn_state {
    u16 max_read;
	u16 max_write;
	u16 max_pages;
	u16 max_pages_limit;
	u16 max_background;
	u16 congestion_threshold;
	u16 num_background;
	u16 active_background;
	u64 conn_error;
	u64 conn_init;
	u64 async_read;
	u64 abort_err;
	u64 atomic_o_trunc;
	u64 export_support;
	u64 writeback_cache;
	u64 parallel_dirops;
	u64 handle_killpriv;
	u64 cache_symlinks;
	u64 legacy_opts_show;
	u64 handle_killpriv_v2;
	u64 no_open;
	u64 no_opendir;
	u64 no_fsync;
	u64 no_fsyncdir;
	u64 no_flush;
	u64 no_setxattr;
	u64 setxattr_ext;
	u64 no_getxattr;
	u64 no_listxattr;
	u64 no_removexattr;
	u64 no_lock;
	u64 no_access;
	u64 no_create;
	u64 no_interrupt;
	u64 no_bmap;
	u64 no_poll;
	u64 big_writes;
	u64 dont_mask;
	u64 no_flock;
	u64 no_fallocate;
	u64 no_rename2;
	u64 auto_inval_data;
	u64 explicit_inval_data;
	u64 do_readdirplus;
	u64 readdirplus_auto;
	u64 async_dio;
	u64 no_lseek;
	u64 posix_acl;
	u64 default_permissions;
	u64 allow_other;
	u64 no_copy_file_range;
	u64 destroy;
	u64 delete_stale;
	u64 no_control;
	u64 no_force_umount;
	u64 auto_submounts;
	u64 sync_fs;
	u64 init_security;
	u64 create_supp_group;
	u64 inode_dax;
	u64 no_tmpfile;
	u64 direct_io_allow_mmap;
	u64 no_statx;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct fuse_conn_state);
    __uint(max_entries, 1);
} fc_state_map SEC(".maps");

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
	fc_state->conn_error = BPF_CORE_READ_BITFIELD_PROBED(fc, conn_error);
	fc_state->conn_init = BPF_CORE_READ_BITFIELD_PROBED(fc, conn_init);
	fc_state->async_read = BPF_CORE_READ_BITFIELD_PROBED(fc, async_read);
	fc_state->abort_err = BPF_CORE_READ_BITFIELD_PROBED(fc, abort_err);
	fc_state->atomic_o_trunc = BPF_CORE_READ_BITFIELD_PROBED(fc, atomic_o_trunc);
	fc_state->export_support = BPF_CORE_READ_BITFIELD_PROBED(fc, export_support);
	fc_state->writeback_cache = BPF_CORE_READ_BITFIELD_PROBED(fc, writeback_cache);
	fc_state->parallel_dirops = BPF_CORE_READ_BITFIELD_PROBED(fc, parallel_dirops);
	fc_state->handle_killpriv = BPF_CORE_READ_BITFIELD_PROBED(fc, handle_killpriv);
	fc_state->cache_symlinks = BPF_CORE_READ_BITFIELD_PROBED(fc, cache_symlinks);
	fc_state->legacy_opts_show = BPF_CORE_READ_BITFIELD_PROBED(fc, legacy_opts_show);
	fc_state->handle_killpriv_v2 = BPF_CORE_READ_BITFIELD_PROBED(fc, handle_killpriv_v2);
	fc_state->no_open = BPF_CORE_READ_BITFIELD_PROBED(fc, no_open);
	fc_state->no_opendir = BPF_CORE_READ_BITFIELD_PROBED(fc, no_opendir);
	fc_state->no_fsync = BPF_CORE_READ_BITFIELD_PROBED(fc, no_fsync);
	fc_state->no_fsyncdir = BPF_CORE_READ_BITFIELD_PROBED(fc, no_fsyncdir);
	fc_state->no_flush = BPF_CORE_READ_BITFIELD_PROBED(fc, no_flush);
	fc_state->no_setxattr = BPF_CORE_READ_BITFIELD_PROBED(fc, no_setxattr);
	fc_state->setxattr_ext = BPF_CORE_READ_BITFIELD_PROBED(fc, setxattr_ext);
	fc_state->no_getxattr = BPF_CORE_READ_BITFIELD_PROBED(fc, no_getxattr);
	fc_state->no_listxattr = BPF_CORE_READ_BITFIELD_PROBED(fc, no_listxattr);
	fc_state->no_removexattr = BPF_CORE_READ_BITFIELD_PROBED(fc, no_removexattr);
	fc_state->no_lock = BPF_CORE_READ_BITFIELD_PROBED(fc, no_lock);
	fc_state->no_access = BPF_CORE_READ_BITFIELD_PROBED(fc, no_access);
	fc_state->no_create = BPF_CORE_READ_BITFIELD_PROBED(fc, no_create);
	fc_state->no_interrupt = BPF_CORE_READ_BITFIELD_PROBED(fc, no_interrupt);
	fc_state->no_bmap = BPF_CORE_READ_BITFIELD_PROBED(fc, no_bmap);
	fc_state->no_poll = BPF_CORE_READ_BITFIELD_PROBED(fc, no_poll);
	fc_state->big_writes = BPF_CORE_READ_BITFIELD_PROBED(fc, big_writes);
	fc_state->dont_mask = BPF_CORE_READ_BITFIELD_PROBED(fc, dont_mask);
	fc_state->no_flock = BPF_CORE_READ_BITFIELD_PROBED(fc, no_flock);
	fc_state->no_fallocate = BPF_CORE_READ_BITFIELD_PROBED(fc, no_fallocate);
	fc_state->no_rename2 = BPF_CORE_READ_BITFIELD_PROBED(fc, no_rename2);
	fc_state->auto_inval_data = BPF_CORE_READ_BITFIELD_PROBED(fc, auto_inval_data);
	fc_state->explicit_inval_data = BPF_CORE_READ_BITFIELD_PROBED(fc, explicit_inval_data);
	fc_state->do_readdirplus = BPF_CORE_READ_BITFIELD_PROBED(fc, do_readdirplus);
	fc_state->readdirplus_auto = BPF_CORE_READ_BITFIELD_PROBED(fc, readdirplus_auto);
	fc_state->async_dio = BPF_CORE_READ_BITFIELD_PROBED(fc, async_dio);
	fc_state->no_lseek = BPF_CORE_READ_BITFIELD_PROBED(fc, no_lseek);
	fc_state->posix_acl = BPF_CORE_READ_BITFIELD_PROBED(fc, posix_acl);
	fc_state->default_permissions = BPF_CORE_READ_BITFIELD_PROBED(fc, default_permissions);
	fc_state->allow_other = BPF_CORE_READ_BITFIELD_PROBED(fc, allow_other);
	fc_state->no_copy_file_range = BPF_CORE_READ_BITFIELD_PROBED(fc, no_copy_file_range);
	fc_state->destroy = BPF_CORE_READ_BITFIELD_PROBED(fc, destroy);
	fc_state->delete_stale = BPF_CORE_READ_BITFIELD_PROBED(fc, delete_stale);
	fc_state->no_control = BPF_CORE_READ_BITFIELD_PROBED(fc, no_control);
	fc_state->no_force_umount = BPF_CORE_READ_BITFIELD_PROBED(fc, no_force_umount);
	fc_state->auto_submounts = BPF_CORE_READ_BITFIELD_PROBED(fc, auto_submounts);
	fc_state->sync_fs = BPF_CORE_READ_BITFIELD_PROBED(fc, sync_fs);
	fc_state->init_security = BPF_CORE_READ_BITFIELD_PROBED(fc, init_security);
	fc_state->create_supp_group = BPF_CORE_READ_BITFIELD_PROBED(fc, create_supp_group);
	fc_state->inode_dax = BPF_CORE_READ_BITFIELD_PROBED(fc, inode_dax);
	fc_state->no_tmpfile = BPF_CORE_READ_BITFIELD_PROBED(fc, no_tmpfile);
	fc_state->direct_io_allow_mmap = BPF_CORE_READ_BITFIELD_PROBED(fc, direct_io_allow_mmap);
	fc_state->no_statx = BPF_CORE_READ_BITFIELD_PROBED(fc, no_statx);

	if (bpf_map_update_elem(&fc_state_map, &map_id, fc_state, 0) < 0) {
		bpf_printk("couldn't update fc_state_map.");
	}
}
