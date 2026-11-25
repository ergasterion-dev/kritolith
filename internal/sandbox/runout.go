package sandbox

// The run phase's /out is the one writable host directory a PoC can
// write to (the coverage profile goes there). RLIMIT_FSIZE bounds each
// file, not their number, so without a cap a PoC could fill the host
// disk with 256 MiB files for the whole run timeout. Before the run
// container starts, the Runner mounts a small tmpfs on the host
// directory (size and inode capped, nosuid,nodev,noexec, owned by the
// container user) and unmounts it right after the run, once the
// coverage profile is read. The startup sweep unmounts any left by a
// crash. Without the mount the run does not start: INCONCLUSIVE.
const (
	// runOutBytes caps the run phase's /out. A coverage profile larger
	// than maxScanBytes is not read anyway.
	runOutBytes = 8 << 20
	// runOutInodes caps the number of files in /out (tmpfs inodes cost
	// kernel memory that the size cap does not count).
	runOutInodes = 1024
	// runOutDirName is the scratch subdirectory the cap is mounted on.
	runOutDirName = "runout"
)

// outMounter mounts the size-capped /out of a run phase.
type outMounter interface {
	// Mount mounts a tmpfs of at most size bytes and inodes files on
	// dir, owned by uid:gid; release unmounts it.
	Mount(dir string, size int64, inodes, uid, gid int) (release func() error, err error)
}
