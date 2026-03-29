# Adapting jai to macOS: A Design Analysis

This document analyzes whether jai's design could be adapted to macOS,
what building blocks Apple provides, and what trade‑offs a macOS port
would have to accept.

## 1. How jai works on Linux (recap)

jai is a small setuid‑root C++ program that constructs an ad‑hoc
sandbox around a single command.  The user‑visible policy is:

  * Full read/write access to the current working directory (and any
    extra directories granted with `-d`).
  * A copy‑on‑write view of `$HOME` (casual mode) or an empty private
    `$HOME` (bare/strict mode).
  * Private `/tmp`, `/var/tmp`, and `$XDG_RUNTIME_DIR`.
  * Everything else read‑only.
  * A private PID namespace so the jailed process cannot signal or
    ptrace anything outside.

The implementation is a thin veneer over a handful of modern Linux
kernel features (kernel ≥ 6.13):

| jai feature                | Linux primitive                                                                   |
| -------------------------- | --------------------------------------------------------------------------------- |
| Per‑jail filesystem view   | `unshare(CLONE_NEWNS)` mount namespace                                            |
| Read‑only root             | `mount_setattr(..., MOUNT_ATTR_RDONLY, AT_RECURSIVE)`                             |
| CoW `$HOME`                | `overlayfs` via the new fd‑based mount API (`fsopen`/`fsconfig`/`fsmount`)        |
| Granting a directory       | `open_tree` + `move_mount` (fd‑addressed bind mounts)                             |
| `--mask` hidden files      | overlayfs whiteout entries (`mknod c 0 0`)                                        |
| Private `/tmp`             | `tmpfs` mounted via `fsopen("tmpfs")`                                             |
| UID swap in strict mode    | `CLONE_NEWUSER` + writing `/proc/<pid>/uid_map` and `gid_map`                     |
| ID‑mapped grants           | `MOUNT_ATTR_IDMAP` with a `userns_fd` so the `jai` user appears as the real owner |
| Process isolation          | `CLONE_NEWPID` + `CLONE_NEWIPC` + a fresh `/proc` mount                           |
| Job control plumbing       | `signalfd`, a pipe from the pid‑1 shim back to the outer process, `PR_SET_PDEATSIG` |
| TOCTTOU resistance         | Everything is `openat`/`O_PATH` and fd‑relative; mounts are moved by fd, not path |

The whole tool is roughly: open some fds → build a mount namespace
entirely through fd‑based syscalls → fork into a new PID namespace →
drop privilege → `execve` through bash.

## 2. What macOS does and does not have

macOS (Darwin / XNU) has a very different kernel lineage.  It inherits
a little bit of Mach, a little bit of BSD, and a lot of Apple‑specific
security machinery.  The short version:

  * There is **no mount namespace** abstraction.  The mount table is
    global.  `chroot` exists but is a blunt instrument, requires root,
    and is defeated by the system volume being read‑only and
    firmlinked.
  * There is **no overlayfs**.  `mount_union` existed historically but
    has been disabled since 10.6.  APFS has per‑file copy‑on‑write
    (`clonefile(2)`) and volume‑level snapshots, but nothing that lets
    you overlay one directory on another at mount time.
  * There are **no user namespaces** and no ID‑mapped mounts.
    Changing UID requires real privilege and is all‑or‑nothing.
  * There is **no PID namespace**.  You cannot hide the host process
    tree.
  * The fd‑based mount API (`fsopen`/`open_tree`/`move_mount`) does
    not exist; the classic `mount(2)` is path‑based and heavily gated
    by the kernel's System Integrity Protection.

So a line‑for‑line port is impossible.  The question becomes: can we
reproduce the *policy* with different primitives?

### What macOS *does* offer

1. **Seatbelt / `sandbox-exec` / `sandbox_init(3)`** — a kernel‑level
   MAC framework driven by a small Scheme‑flavoured policy language
   (SBPL).  Every App Store app runs under it; the `sandbox-exec`
   CLI is "deprecated" but still ships and still works.  Policies can
   `allow`/`deny` any of several dozen operation classes, most
   importantly `file-read*` and `file-write*`, filtered by `literal`,
   `subpath`, or `regex` path patterns.  Enforcement happens in the
   kernel and is inherited across `exec`.

2. **APFS `clonefile(2)` / `copyfile(..., COPYFILE_CLONE)`** —
   constant‑time, space‑sharing copies of files or directory trees.
   A clone of `$HOME` costs essentially nothing until you write to
   it.

3. **`/etc/synthetic.conf` + APFS volumes** — lets you create
   root‑level synthetic mount points and separate writable volumes.
   Heavyweight (requires a reboot or `apfs.util -t`) but gives you a
   genuine per‑jail writable area that is easy to snapshot and
   destroy.

4. **Endpoint Security framework** — a modern,
   supported kext‑replacement API that delivers `AUTH` events (open,
   exec, rename, …) to a user‑space daemon, which can allow or deny
   each one.  This is what EDR vendors use.  It requires a
   provisioning profile with the
   `com.apple.developer.endpoint-security.client` entitlement.

5. **Virtualization.framework** — lightweight Apple‑signed
   hypervisor.  Spinning up a minimal Linux VM is fast (hundreds of
   milliseconds with a pre‑booted image) and gives you real
   namespaces again, at the cost of no longer being "the same
   machine".

6. **`setuid` still works** — a small setuid helper can `seteuid` to a
   dedicated unprivileged user exactly as jai does on Linux.

## 3. Three plausible macOS designs

### 3.1  Seatbelt‑only (`jai` as an SBPL generator) — *recommended*

This is the closest in spirit: a tiny binary that writes a policy and
execs the target.  No root required.

  * **Root filesystem read‑only**: `(deny file-write* (subpath "/"))`
    as a blanket rule.
  * **Grant CWD / `-d` directories**:
    `(allow file* (subpath "/Users/alice/project"))` for each grant.
    `-r` (read‑only grant) becomes `allow file-read*` without
    `file-write*`.
  * **Private `/tmp`**: point `TMPDIR` at a fresh directory inside
    the jail's storage area and deny writes to `/private/tmp`.  (Most
    well‑behaved macOS software honours `TMPDIR`; Seatbelt can deny
    the rest.)
  * **Casual CoW `$HOME`**: before entering the sandbox,
    `clonefile($HOME, $HOME/.jai/<name>.home)` (or clone only on
    first use).  Deny writes to the real `$HOME`, allow all
    operations under the clone, and set `HOME` to the clone.  The
    clone shares storage until modified, giving the same "changes
    directory" ergonomics as overlayfs.
  * **Bare / strict `$HOME`**: just set `HOME` to an empty directory
    and deny reads of the real one with
    `(deny file-read* (subpath "/Users/alice"))` plus targeted
    `allow` rules for the grants.
  * **`--mask`**: since casual mode uses a clone rather than an
    overlay, masking is simply `rm` inside the clone — even simpler
    than whiteouts.
  * **Environment scrubbing**: identical code — walk `environ`, drop
    anything matching the deny‑patterns.
  * **Process isolation**: Seatbelt can
    `(deny process-info*) (deny signal (target others))`, which
    blocks ptrace/kill of processes outside the sandbox.  It is not a
    namespace — host PIDs are still *visible* in `/proc`‑less macOS
    via `sysctl` — but the jailed process cannot act on them.
  * **Network**: Seatbelt can optionally `(deny network*)`, something
    Linux jai does not currently do but would be a natural extension.

What you lose relative to Linux jai:

  * No *view* remapping — the jailed process still sees paths where
    they really live.  `$HOME` is a different path, not a mount over
    the original.  This is usually fine (AI CLIs respect `$HOME`) but
    software that hard‑codes `/Users/<name>` will notice.
  * `clonefile` of a large `$HOME` with millions of inodes is still
    O(inodes) in directory‑entry creation, whereas overlayfs is O(1).
    Partial mitigation: clone only the dot‑dirs the agent actually
    needs, or make casual mode opt‑in per subtree.
  * No ID‑mapped mounts, so strict mode cannot transparently give the
    jailed UID write access to the user's files.  The grant
    directories would need a `chmod`/ACL pass or simply run in bare
    mode (same UID, empty `$HOME`).  In practice bare mode is what
    most macOS users would want anyway, because Seatbelt already
    handles the confidentiality that strict mode's UID swap provides
    on Linux.
  * `sandbox-exec` is officially deprecated.  It has shipped unchanged
    for a decade and Apple's own daemons depend on the same kernel
    machinery, so it is unlikely to disappear, but a production tool
    should call `sandbox_init_with_parameters(3)` directly rather
    than shelling out.

Implementation sketch:

```c
// pseudo-code
std::string profile = R"((version 1)
(deny default)
(import "system.sb")           ; Apple's base allow-list
(allow process-exec)
(allow file-read* (subpath "/"))
(deny  file-write* (subpath "/"))
)";
for (auto &g : grants)
    profile += std::format("(allow file* (subpath \"{}\"))\n", g);
profile += std::format("(deny file* (subpath \"{}\"))\n", real_home);
profile += std::format("(allow file* (subpath \"{}\"))\n", jail_home);

char *err;
sandbox_init_with_parameters(profile.c_str(),
                             SANDBOX_NAMED_EXTERNAL, nullptr, &err);
setenv("HOME", jail_home, 1);
setenv("TMPDIR", jail_tmp, 1);
execvp(argv[0], argv);
```

This is a few hundred lines — roughly the same order of magnitude as
jai itself.

### 3.2  Endpoint Security interposer

Instead of a static policy, run a tiny ES client that subscribes to
`ES_EVENT_TYPE_AUTH_OPEN`, `AUTH_RENAME`, `AUTH_UNLINK`, etc., tags
the jailed process tree via its audit token, and vetoes any write
outside the grant set.  This can also *redirect*: deny a write to
`$HOME/.config/foo` and simultaneously copy the file into the clone
so the next open succeeds there — an overlayfs emulation in
user‑space.

Pros: dynamic, can implement true path remapping, supported API.
Cons: needs an Apple‑issued ES entitlement (not available to ad‑hoc
tools), adds a persistent daemon, adds latency to every filesystem
syscall in the jailed tree.  Probably overkill for jai's "run this
one command a bit more safely" use case, but it is the right answer
if someone wants to ship this as a signed product.

### 3.3  Virtualization.framework micro‑VM

Boot a tiny Linux image under Virtualization.framework, virtiofs‑share
the grant directories into it, and run the command there.  You get the
exact Linux jai semantics (you can literally run jai inside the
guest), perfect isolation, and Apple‑blessed APIs.

Pros: strongest isolation by far; no policy language to reason about.
Cons: no longer "the same machine" — host binaries don't run, host
GPU/devices need explicit plumbing, and startup is hundreds of
milliseconds rather than single‑digit.  This is closer to Docker than
to jai.

## 4. Feature‑by‑feature mapping

| jai feature              | Linux impl                         | macOS Seatbelt design                                          | Fidelity |
| ------------------------ | ---------------------------------- | -------------------------------------------------------------- | -------- |
| Read‑only `/`            | `mount_setattr RDONLY`             | `(deny file-write* (subpath "/"))`                             | exact    |
| CoW `$HOME` (casual)     | overlayfs                          | `clonefile` + `HOME=` + deny writes to real home               | good¹    |
| Empty `$HOME` (bare)     | bind empty dir over `$HOME`        | `HOME=` + `(deny file* (subpath "<real home>"))`               | exact    |
| UID swap (strict)        | userns + idmapped mounts           | setuid helper → `seteuid(jai)`; grants need ACL or fall back to bare | partial² |
| Grant `-d` dir           | `open_tree` + `move_mount`         | `(allow file* (subpath "<dir>"))`                              | exact    |
| Grant `-r` (ro) dir      | bind + `MOUNT_ATTR_RDONLY`         | `(allow file-read* (subpath "<dir>"))`                         | exact    |
| `--mask` hide file       | overlayfs whiteout                 | delete from the `clonefile`'d `$HOME`                          | exact    |
| Private `/tmp`           | tmpfs bind                         | `TMPDIR=` + deny `/private/tmp` writes                         | good³    |
| Private `$XDG_RUNTIME_DIR` | tmpfs bind                       | deny Unix sockets in `~/Library/Application Support`, `/var/run` | good     |
| PID hiding               | `CLONE_NEWPID`                     | `(deny process-info*) (deny signal (target others))`           | partial⁴ |
| `jai -u` teardown        | recursive `umount2`                | `rm -rf` the clone / private tmp                               | exact    |
| Env var scrubbing        | walk `environ`                     | identical code                                                 | exact    |
| Job‑control passthrough  | signalfd + pipe from pid‑1         | direct `fork`/`exec`, no pid‑1 shim needed                     | simpler  |
| TOCTTOU safety           | fd‑based mounts                    | Seatbelt resolves paths in‑kernel at check time                | exact    |

¹ Paths differ; software that ignores `$HOME` and hard‑codes
  `/Users/<name>` sees the denied real home.
² Without idmapped mounts, strict mode can either use POSIX ACLs on
  grant directories or simply degrade to bare mode (which on macOS is
  arguably *sufficient*, because Seatbelt's deny‑read on the real home
  already provides the confidentiality that the UID swap buys on
  Linux).
³ Software that ignores `$TMPDIR` and opens `/tmp/...` directly is
  blocked rather than silently redirected.  Add a targeted
  `(allow file* (subpath "<jail>/tmp"))` and symlink `/tmp` inside the
  clone if needed.
⁴ The jailed process can still *enumerate* host PIDs via
  `sysctl(KERN_PROC)`; it just cannot signal or ptrace them.

## 5. Recommendation

A macOS jai should be built on **Seatbelt + clonefile** (design 3.1).
It preserves the two properties that make jai attractive on Linux —
zero‑configuration invocation and trivially small trusted codebase —
while accepting that "casual" means *deny‑write* rather than
*remap‑write*.  The existing option parser, configuration file
machinery, environment scrubber, and `--mask` defaults carry over
unchanged; only `fs.cc` and the namespace‑setup half of `jai.cc` need
a new backend.

A reasonable split would be:

  * `fs_linux.cc` — the current `fsopen`/`move_mount` code.
  * `fs_darwin.cc` — `clonefile`, SBPL emission,
    `sandbox_init_with_parameters`.
  * Shared: `options.*`, `cred.*`, `default_conf.cc`, the
    `parent_loop` job‑control shim (minus the pid‑1 dance, which is
    unnecessary without a PID namespace).

Strict mode should probably collapse into bare mode on macOS and rely
on Seatbelt's `deny file-read*` rules for confidentiality, sidestepping
the ID‑mapped‑mount gap entirely.

## Appendix: plumbing substitutions

Beyond the big architectural pieces, a handful of smaller Linux‑isms
in the current source need Darwin equivalents:

| Linux                                  | macOS                                             |
| -------------------------------------- | ------------------------------------------------- |
| `signalfd` + `poll`                    | `kqueue` + `EVFILT_SIGNAL`                        |
| `prctl(PR_SET_PDEATHSIG)`              | `kqueue` + `EVFILT_PROC`/`NOTE_EXIT` on parent pid |
| `O_TMPFILE` + `linkat(AT_EMPTY_PATH)`  | `mkstemp` + `rename`                              |
| `readlink("/proc/self/fd/N")`          | `fcntl(fd, F_GETPATH)`                            |
| parse `/proc/self/mountinfo`           | `getfsstat(2)` / `getmntinfo(3)`                  |
| `statx(STATX_ATTR_MOUNT_ROOT)`         | compare `st_dev` of path vs. parent               |
| `clone3` with namespace flags          | plain `fork` (no namespaces to create)            |
| `pipe2(O_CLOEXEC)`                     | `pipe` + `fcntl(FD_CLOEXEC)`                      |
| POSIX ACLs via `acl_set_file`          | same API, different text format (`chmod +a`)      |

The pid‑1 / `parent_loop` dance (jai.cc:783‑950) exists solely to work
around PID‑namespace signal semantics.  With no PID namespace on
macOS, all of that collapses to a straight `fork`/`waitpid` and the
shell's ordinary job control just works.

Also worth noting: Linux jai does **not** isolate the network
(`CLONE_NEWNET` is never set), so the absence of network namespaces on
macOS is not a regression.  A Seatbelt backend could optionally go
further with `(deny network*)` as an opt‑in tightening.
