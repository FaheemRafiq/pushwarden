"""Real-time file-system watching with no third-party dependencies.

Backends (chosen automatically):
  Linux    inotify via ctypes (one watch per directory, new dirs added on the fly)
  macOS    kqueue on directories (stdlib select) + fast stat poll of tracked files
  Windows  ReadDirectoryChangesW via ctypes (recursive, one handle per root)
  any      polling fallback (mtime walk) when a native backend is unavailable
           or the tree is too large for it.

Usage:
    w = Watcher(roots, skip=skip_dir_predicate, on_events=callback)
    w.start()         # background thread; callback(set_of_paths) after a 0.5 s debounce
    w.stop()
"""

import os
import select
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set

DEBOUNCE = 0.5


class Watcher:
    def __init__(self, roots: Iterable[Path], skip: Callable[[str], bool], on_events: Callable[[Set[Path]], None],
                 poll_interval: float = 3.0, log=None):
        self.roots = [Path(r) for r in roots if Path(r).is_dir()]
        self.skip = skip
        self.on_events = on_events
        self.poll_interval = poll_interval
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self._pending: Set[Path] = set()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self.backend = "none"

    # ── public ───────────────────────────────────────────────────────────────
    def start(self):
        self._thread = threading.Thread(target=self._run, name="threatscan-watch", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ── dispatch ─────────────────────────────────────────────────────────────
    def _run(self):
        try:
            if sys.platform.startswith("linux"):
                self.backend = "inotify"
                self._run_inotify()
                return
            if sys.platform == "darwin":
                self.backend = "kqueue"
                self._run_kqueue()
                return
            if sys.platform.startswith("win"):
                self.backend = "rdcw"
                self._run_windows()
                return
        except Exception as e:  # native backend failed: degrade gracefully
            self.log(f"realtime backend {self.backend} failed ({e}); falling back to polling")
        self.backend = "poll"
        self._run_poll()

    def _emit(self, paths: Iterable[Path]):
        with self._lock:
            self._pending.update(paths)

    def _flush_loop_tick(self, last_flush: float) -> float:
        now = time.time()
        if now - last_flush < DEBOUNCE:
            return last_flush
        with self._lock:
            batch, self._pending = self._pending, set()
        if batch:
            try:
                self.on_events(batch)
            except Exception as e:
                self.log(f"realtime handler error: {e}")
        return now

    def _walk_dirs(self) -> List[Path]:
        out = []
        for root in self.roots:
            for dirpath, dirs, _ in os.walk(root):
                dirs[:] = [d for d in dirs if not self.skip(d)]
                out.append(Path(dirpath))
        return out

    # ── Linux: inotify ───────────────────────────────────────────────────────
    def _run_inotify(self):
        import ctypes
        import ctypes.util
        import struct
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE = 0x2, 0x4, 0x8
        IN_MOVED_TO, IN_CREATE, IN_DELETE_SELF = 0x80, 0x100, 0x400
        IN_ISDIR, IN_Q_OVERFLOW = 0x40000000, 0x4000
        MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_ATTRIB | IN_DELETE_SELF
        IN_NONBLOCK = 0o4000
        fd = libc.inotify_init1(IN_NONBLOCK)
        if fd < 0:
            raise OSError("inotify_init1 failed")
        try:
            limit = int(Path("/proc/sys/fs/inotify/max_user_watches").read_text())
        except Exception:
            limit = 8192
        wds = {}

        def add(d: Path):
            wd = libc.inotify_add_watch(fd, str(d).encode(), MASK)
            if wd >= 0:
                wds[wd] = d
            return wd

        dirs = self._walk_dirs()
        if len(dirs) > limit - 256:
            os.close(fd)
            raise OSError(f"{len(dirs)} directories exceed inotify limit {limit}; "
                          "raise fs.inotify.max_user_watches or use polling")
        for d in dirs:
            add(d)
        self.log(f"realtime: inotify watching {len(wds)} directories under {len(self.roots)} roots")
        last = time.time()
        buf = ctypes.create_string_buffer(64 * 1024)
        while not self._stop.is_set():
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                n = libc.read(fd, buf, len(buf))
                if n > 0:
                    data = buf.raw[:n]
                    off = 0
                    while off + 16 <= n:
                        wd, mask, cookie, ln = struct.unpack_from("iIII", data, off)
                        name = data[off + 16: off + 16 + ln].split(b"\0", 1)[0].decode("utf-8", "surrogateescape")
                        off += 16 + ln
                        if mask & IN_Q_OVERFLOW:
                            self._emit(self.roots)   # rescan everything
                            continue
                        base = wds.get(wd)
                        if base is None:
                            continue
                        if mask & IN_DELETE_SELF:
                            wds.pop(wd, None)
                            continue
                        p = base / name if name else base
                        if mask & IN_ISDIR:
                            if mask & (IN_CREATE | IN_MOVED_TO) and not self.skip(name):
                                for sub in [p] + [Path(dp) for dp, ds, _ in os.walk(p)
                                                  for _ in [ds.__setitem__(slice(None), [d for d in ds if not self.skip(d)])]]:
                                    add(sub)
                                # files that arrived with the directory (git checkout, unzip)
                                self._emit(Path(dp) / f for dp, ds, fs in os.walk(p) for f in fs)
                            continue
                        self._emit([p])
            last = self._flush_loop_tick(last)
        os.close(fd)

    # ── macOS: kqueue on directories + stat poll ─────────────────────────────
    def _run_kqueue(self):
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65536), hard))
        except Exception:
            pass
        dirs = self._walk_dirs()
        if len(dirs) > 20000:
            raise OSError(f"{len(dirs)} directories is too many for kqueue")
        kq = select.kqueue()
        fds = {}
        flags = select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_RENAME | select.KQ_NOTE_DELETE
        for d in dirs:
            try:
                fd = os.open(str(d), os.O_RDONLY)
            except OSError:
                continue
            fds[fd] = d
            kq.control([select.kevent(fd, select.KQ_FILTER_VNODE, select.KQ_EV_ADD | select.KQ_EV_CLEAR, flags)], 0)
        self.log(f"realtime: kqueue watching {len(fds)} directories")
        snap = {}
        for d in fds.values():
            snap[d] = self._dir_snapshot(d)
        last = time.time()
        last_poll = time.time()
        while not self._stop.is_set():
            events = kq.control(None, 64, 0.5)
            changed_dirs = {fds[e.ident] for e in events if e.ident in fds}
            for d in changed_dirs:
                new = self._dir_snapshot(d)
                old = snap.get(d, {})
                self._emit(d / name for name, m in new.items() if old.get(name) != m)
                snap[d] = new
                for name in new:
                    sub = d / name
                    if sub.is_dir() and not self.skip(name) and not any(v == sub for v in fds.values()):
                        try:
                            fd = os.open(str(sub), os.O_RDONLY)
                            fds[fd] = sub
                            kq.control([select.kevent(fd, select.KQ_FILTER_VNODE, select.KQ_EV_ADD | select.KQ_EV_CLEAR, flags)], 0)
                            snap[sub] = {}
                            self._emit(Path(dp) / f for dp, _, fs in os.walk(sub) for f in fs)
                        except OSError:
                            pass
            # in-place rewrites of existing files do not change the directory
            # entry, so also poll mtimes of files in all watched dirs (cheap)
            if time.time() - last_poll >= self.poll_interval:
                for d in list(fds.values()):
                    new = self._dir_snapshot(d)
                    old = snap.get(d, {})
                    self._emit(d / name for name, m in new.items() if old.get(name) != m)
                    snap[d] = new
                last_poll = time.time()
            last = self._flush_loop_tick(last)
        for fd in fds:
            os.close(fd)

    @staticmethod
    def _dir_snapshot(d: Path) -> dict:
        out = {}
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                        out[e.name] = (st.st_mtime_ns, st.st_size)
                    except OSError:
                        pass
        except OSError:
            pass
        return out

    # ── Windows: ReadDirectoryChangesW ───────────────────────────────────────
    def _run_windows(self):
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        FILE_LIST_DIRECTORY = 0x0001
        FILE_SHARE_ALL = 0x7
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        NOTIFY = 0x1 | 0x2 | 0x8 | 0x10 | 0x100   # FILE_NAME, DIR_NAME, SIZE, LAST_WRITE, CREATION
        handles = []
        for root in self.roots:
            h = k32.CreateFileW(str(root), FILE_LIST_DIRECTORY, FILE_SHARE_ALL, None, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, None)
            if h and h != wintypes.HANDLE(-1).value:
                handles.append((h, root))
        if not handles:
            raise OSError("CreateFileW failed for all roots")
        self.log(f"realtime: ReadDirectoryChangesW on {len(handles)} roots")

        def reader(h, root):
            buf = ctypes.create_string_buffer(64 * 1024)
            ret = wintypes.DWORD()
            while not self._stop.is_set():
                ok = k32.ReadDirectoryChangesW(h, buf, len(buf), True, NOTIFY, ctypes.byref(ret), None, None)
                if not ok:
                    time.sleep(1)
                    continue
                off = 0
                paths = []
                while off < ret.value:
                    next_off, action, ln = ctypes.c_uint32.from_buffer(buf, off).value, \
                        ctypes.c_uint32.from_buffer(buf, off + 4).value, ctypes.c_uint32.from_buffer(buf, off + 8).value
                    name = ctypes.wstring_at(ctypes.addressof(buf) + off + 12, ln // 2)
                    p = root / name
                    if not any(self.skip(part) for part in Path(name).parts[:-1]):
                        paths.append(p)
                    if not next_off:
                        break
                    off += next_off
                self._emit(paths)

        for h, root in handles:
            threading.Thread(target=reader, args=(h, root), daemon=True).start()
        last = time.time()
        while not self._stop.is_set():
            time.sleep(0.25)
            last = self._flush_loop_tick(last)
        for h, _ in handles:
            k32.CancelIoEx(h, None)
            k32.CloseHandle(h)

    # ── fallback: polling ────────────────────────────────────────────────────
    def _run_poll(self):
        self.log(f"realtime: polling every {self.poll_interval}s")
        snap = self._full_snapshot()
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval)
            new = self._full_snapshot()
            changed = [Path(p) for p, m in new.items() if snap.get(p) != m]
            snap = new
            if changed:
                self._emit(changed)
            self._flush_loop_tick(0)

    def _full_snapshot(self) -> dict:
        out = {}
        for root in self.roots:
            for dirpath, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if not self.skip(d)]
                for fn in files:
                    p = os.path.join(dirpath, fn)
                    try:
                        st = os.stat(p)
                        out[p] = (st.st_mtime_ns, st.st_size)
                    except OSError:
                        pass
        return out
