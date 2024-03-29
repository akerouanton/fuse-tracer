package main

import "fmt"

func fuseOperation(opcode uint32) string {
	switch opcode {
	case 1:
		return "FUSE_LOOKUP"
	case 2:
		return "FUSE_FORGET"
	case 3:
		return "FUSE_GETATTR"
	case 4:
		return "FUSE_SETATTR"
	case 5:
		return "FUSE_READLINK"
	case 6:
		return "FUSE_SYMLINK"
	case 8:
		return "FUSE_MKNOD"
	case 9:
		return "FUSE_MKDIR"
	case 10:
		return "FUSE_UNLINK"
	case 11:
		return "FUSE_RMDIR"
	case 12:
		return "FUSE_RENAME"
	case 13:
		return "FUSE_LINK"
	case 14:
		return "FUSE_OPEN"
	case 15:
		return "FUSE_READ"
	case 16:
		return "FUSE_WRITE"
	case 17:
		return "FUSE_STATFS"
	case 18:
		return "FUSE_RELEASE"
	case 20:
		return "FUSE_FSYNC"
	case 21:
		return "FUSE_SETXATTR"
	case 22:
		return "FUSE_GETXATTR"
	case 23:
		return "FUSE_LISTXATTR"
	case 24:
		return "FUSE_REMOVEXATTR"
	case 25:
		return "FUSE_FLUSH"
	case 26:
		return "FUSE_INIT"
	case 27:
		return "FUSE_OPENDIR"
	case 28:
		return "FUSE_READDIR"
	case 29:
		return "FUSE_RELEASEDIR"
	case 30:
		return "FUSE_FSYNCDIR"
	case 31:
		return "FUSE_GETLK"
	case 32:
		return "FUSE_SETLK"
	case 33:
		return "FUSE_SETLKW"
	case 34:
		return "FUSE_ACCESS"
	case 35:
		return "FUSE_CREATE"
	case 36:
		return "FUSE_INTERRUPT"
	case 37:
		return "FUSE_BMAP"
	case 38:
		return "FUSE_DESTROY"
	case 39:
		return "FUSE_IOCTL"
	case 40:
		return "FUSE_POLL"
	case 41:
		return "FUSE_NOTIFY_REPLY"
	case 42:
		return "FUSE_BATCH_FORGET"
	case 43:
		return "FUSE_FALLOCATE"
	case 44:
		return "FUSE_READDIRPLUS"
	case 45:
		return "FUSE_RENAME2"
	case 46:
		return "FUSE_LSEEK"
	case 47:
		return "FUSE_COPY_FILE_RANGE"
	case 48:
		return "FUSE_SETUPMAPPING"
	case 49:
		return "FUSE_REMOVEMAPPING"
	case 50:
		return "FUSE_SYNCFS"
	case 51:
		return "FUSE_TMPFILE"
	default:
		return fmt.Sprintf("unknown opcode %d", opcode)
	}
}
