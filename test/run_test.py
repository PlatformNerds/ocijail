#! /usr/bin/env python

import array
import io
import json
import os
import os.path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

def racct_enabled():
    try:
        out = subprocess.run(["sysctl", "-n", "kern.racct.enable"],
                             capture_output=True, text=True)
        return out.stdout.strip() == "1"
    except OSError:
        return False

def rctl_rules(subject):
    out = subprocess.run(["rctl", subject], capture_output=True, text=True)
    return sorted(line for line in out.stdout.splitlines() if line)

cmd = "ocijail/ocijail"

def recv_fds(sock, msglen, maxfds):
    fds = array.array("i")   # Array of ints
    msg, ancdata, flags, addr = sock.recvmsg(msglen, socket.CMSG_LEN(maxfds * fds.itemsize))
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            # Append data, ignoring any truncated integers at the end.
            fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
    return msg, list(fds)

class test_run(unittest.TestCase):
    "End-to-end tests for running containers"

    count = 1

    def setUp(self):
        self.container_id = f"ocijail_test_{os.getpid()}_{test_run.count}"
        test_run.count += 1

    def tearDown(self):
        self.delete(False)

    def config(self):
        return {
            "ociVersion": "1.0.2",
            "process": {
                "cwd": "/",
                "env": [
                    "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
                ],
            },
            "root": {
                "path": "/"
            }
        }

    def create(self, bundle_dir, terminal=False, expected_ret=0):
        pid_file = os.path.join(bundle_dir, "pid")
        args = [
            cmd,
            "create",
            "--pid-file", pid_file,
            "--bundle", bundle_dir,
        ]
        if terminal:
            console_socket = os.path.join(bundle_dir, "sock")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(console_socket)
            sock.listen()
            args += ["--console-socket", console_socket]
        args.append(self.container_id)
        with subprocess.Popen(
            args=args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        ) as proc:
            if terminal:
                conn, _ = sock.accept()
                msg, fds = recv_fds(conn, 512, 10)
                conn.close()
                sock.close()
                proc.wait()
                self.assertEqual(len(fds), 1)
                stdout = io.FileIO(fds[0], "w+")
                stderr = io.FileIO(os.dup(fds[0]), "w+")
            else:
                # Steal the pipes so that they don't get closed during
                # the call to proc.wait()
                stdout = proc.stdout
                stderr = proc.stderr
                proc.stdout = None
                proc.stderr = None
            ret = proc.wait()
            if ret != 0:
                out = stderr.read().decode("utf-8")
                print(f"failed with stderr: {out}")
                self.assertTrue(ret == expected_ret)
                return -1, stdout, stderr
        with open(pid_file, "r") as f:
            pid = int(f.read())
        return pid, stdout, stderr

    def start(self):
        args = [cmd, "start", self.container_id]
        ret = subprocess.run(args=args)
        self.assertTrue(ret.returncode == 0)

    def delete(self, check_returncode=True):
        args = [cmd, "delete", self.container_id]
        ret = subprocess.run(args=args)
        if check_returncode:
            self.assertTrue(ret.returncode == 0)

    def run_with_config(self, c, expected_ret=0):
        with tempfile.TemporaryDirectory() as bundle_dir:
            with open(os.path.join(bundle_dir, "config.json"), "w") as f:
                json.dump(c, f)
            with open(os.path.join("/tmp", "config.json"), "w") as f:
                json.dump(c, f)
            if "terminal" in c["process"]:
                terminal = c["process"]["terminal"]
            else:
                terminal = False
            pid, stdout, stderr = self.create(bundle_dir, terminal=terminal, expected_ret=expected_ret)
            if pid == -1:
                stdout.close()
                stderr.close()
                return 1, "", ""
            self.start()
            out = stdout.read().decode("utf-8")
            err = stderr.read().decode("utf-8")
            stdout.close()
            stderr.close()
            pid2, status = os.waitpid(pid, os.WEXITED)
            self.assertTrue(pid == pid2)
            self.assertEqual(status & 0xff, 0)
            return status >> 8, out, err

    def test_exit_code(self):
        c = self.config()
        c["process"]["args"] = ["sh", "-c", "exit 42"]
        ret, _, _ = self.run_with_config(c)
        self.assertEqual(ret, 42)

    @unittest.skipUnless(racct_enabled(), "needs kern.racct.enable=1")
    def test_resources_rctl_rules(self):
        # OCI linux.resources become rctl rules on the container's jail,
        # and are removed again by delete.
        c = self.config()
        c["process"]["args"] = ["sh", "-c", "exit 0"]
        c["linux"] = {"resources": {
            "memory": {"limit": 64 << 20},
            "cpu": {"quota": 50000, "period": 100000, "shares": 512},
            "pids": {"limit": 100},
        }}
        subject = f"jail:{self.container_id}"
        with tempfile.TemporaryDirectory() as bundle_dir:
            with open(os.path.join(bundle_dir, "config.json"), "w") as f:
                json.dump(c, f)
            pid, stdout, stderr = self.create(bundle_dir)
            self.assertEqual(rctl_rules(subject), sorted([
                f"{subject}:maxproc:deny=100",
                f"{subject}:memoryuse:sigkill=67108864",
                f"{subject}:pcpu:deny=50",
            ]))
            self.start()
            os.waitpid(pid, os.WEXITED)
            stdout.close()
            stderr.close()
            self.delete()
        self.assertEqual(rctl_rules(subject), [])

    def update(self, resources):
        return subprocess.run([cmd, "update", "--resources", "-", self.container_id],
                              input=json.dumps(resources), text=True,
                              capture_output=True)

    @unittest.skipUnless(racct_enabled(), "needs kern.racct.enable=1")
    def test_update_resources(self):
        # update --resources (CRI UpdateContainerResources, i.e. in-place
        # pod resize) replaces the jail's rctl rules; partial updates keep
        # the other limits; a memory limit below current usage is refused.
        c = self.config()
        c["process"]["args"] = ["sh", "-c", "exit 0"]
        c["linux"] = {"resources": {
            "memory": {"limit": 64 << 20},
            "cpu": {"quota": 50000, "period": 100000, "shares": 512},
            "pids": {"limit": 100},
        }}
        subject = f"jail:{self.container_id}"
        with tempfile.TemporaryDirectory() as bundle_dir:
            with open(os.path.join(bundle_dir, "config.json"), "w") as f:
                json.dump(c, f)
            pid, stdout, stderr = self.create(bundle_dir)
            # what CRI-O sends for a memory-only resize
            ret = self.update({"cpu": {}, "memory": {"limit": 128 << 20}})
            self.assertEqual(ret.returncode, 0, ret.stderr)
            self.assertEqual(rctl_rules(subject), sorted([
                f"{subject}:maxproc:deny=100",
                f"{subject}:memoryuse:sigkill=134217728",
                f"{subject}:pcpu:deny=50",
            ]))
            # cpu-only resize; the memory change above was persisted
            ret = self.update({"cpu": {"quota": 150000, "period": 100000}, "memory": {}})
            self.assertEqual(ret.returncode, 0, ret.stderr)
            self.assertEqual(rctl_rules(subject), sorted([
                f"{subject}:maxproc:deny=100",
                f"{subject}:memoryuse:sigkill=134217728",
                f"{subject}:pcpu:deny=150",
            ]))
            # below current usage: refused, rules unchanged (racctd samples
            # memoryuse once per second, so wait for a sample first)
            time.sleep(1.5)
            ret = self.update({"memory": {"limit": 4096}})
            self.assertNotEqual(ret.returncode, 0, rctl_rules(subject))
            self.assertIn("below the container's current usage", ret.stderr)
            self.assertIn(f"{subject}:memoryuse:sigkill=134217728", rctl_rules(subject))
            self.start()
            os.waitpid(pid, os.WEXITED)
            stdout.close()
            stderr.close()
            # stopped containers can't be updated
            ret = self.update({"memory": {"limit": 256 << 20}})
            self.assertNotEqual(ret.returncode, 0)
            self.delete()
        self.assertEqual(rctl_rules(subject), [])

    @unittest.skipUnless(racct_enabled(), "needs kern.racct.enable=1")
    def test_resources_memory_kill(self):
        # A container whose resident memory exceeds memory.limit is killed
        # (racctd checks once per second, hence the sleep).
        c = self.config()
        c["process"]["args"] = [
            sys.executable, "-c",
            "import time; b = bytearray(256 << 20); time.sleep(10)",
        ]
        c["linux"] = {"resources": {"memory": {"limit": 64 << 20}}}
        with tempfile.TemporaryDirectory() as bundle_dir:
            with open(os.path.join(bundle_dir, "config.json"), "w") as f:
                json.dump(c, f)
            pid, stdout, stderr = self.create(bundle_dir)
            self.start()
            _, status = os.waitpid(pid, os.WEXITED)
            stdout.close()
            stderr.close()
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(os.WTERMSIG(status), 9)

    @unittest.skipUnless(racct_enabled(), "needs kern.racct.enable=1")
    def test_resources_stale_rules(self):
        # rctl rules are keyed by jail name and outlive the jail; create must
        # not let a new container inherit rules left under its name.
        subject = f"jail:{self.container_id}"
        subprocess.run(["rctl", "-a", f"{subject}:openfiles:deny=1000"],
                       check=True)
        try:
            c = self.config()
            c["process"]["args"] = ["sh", "-c", "exit 0"]
            ret, _, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            self.assertEqual(rctl_rules(subject), [])
        finally:
            subprocess.run(["rctl", "-r", subject], capture_output=True)
    def test_parent_jail(self):
        # Containers created inside a parent jail (as CRI-O does for every
        # pod container via org.freebsd.parentJail) read and update the
        # parent's parameters with jail::get/jail::set.
        # The parent must allow what ocijail sets on its children
        # (enforce_statfs=1, allow.raw_sockets), as a pod sandbox jail
        # created by ocijail does.
        parent = f"{self.container_id}_parent"
        subprocess.run(["jail", "-c", f"name={parent}", "path=/", "persist",
                        "enforce_statfs=1", "allow.raw_sockets",
                        "allow.chflags"],
                       check=True)
        try:
            c = self.config()
            c["annotations"] = {"org.freebsd.parentJail": parent}
            c["process"]["args"] = ["sh", "-c", "exit 42"]
            ret, _, _ = self.run_with_config(c)
            self.assertEqual(ret, 42)
        finally:
            self.delete(False)
            subprocess.run(["jail", "-r", parent])
    def suid_scratch(self):
        # A scratch directory on a filesystem that honours setuid bits (/tmp
        # is often nosuid, e.g. in the default ZFS layout).
        scratch = tempfile.TemporaryDirectory(dir=os.path.dirname(os.path.abspath(__file__)))
        if os.statvfs(scratch.name).f_flag & os.ST_NOSUID:
            scratch.cleanup()
            self.skipTest("test directory is on a nosuid filesystem")
        return scratch

    def setuid_id(self, scratch):
        # A setuid-root copy of id(1): run as nobody, it reports euid 0
        # unless no_new_privs is in effect.
        path = os.path.join(scratch, "id")
        shutil.copy("/usr/bin/id", path)
        os.chown(path, 0, 0)
        os.chmod(path, 0o4755)
        os.chmod(scratch, 0o755)
        return path

    def test_no_new_privs(self):
        with self.suid_scratch() as scratch:
            c = self.config()
            c["process"]["user"] = {"uid": 65534, "gid": 65534}
            c["process"]["noNewPrivileges"] = True
            c["process"]["args"] = [self.setuid_id(scratch), "-u"]
            ret, out, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            self.assertEqual(out.strip(), "65534")

    def test_no_new_privs_unset(self):
        with self.suid_scratch() as scratch:
            c = self.config()
            c["process"]["user"] = {"uid": 65534, "gid": 65534}
            c["process"]["args"] = [self.setuid_id(scratch), "-u"]
            ret, out, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            self.assertEqual(out.strip(), "0")

    def test_stdout(self):
        c = self.config()
        c["process"]["args"] = ["echo", "Hello", "World"]
        ret, out, _ = self.run_with_config(c)
        self.assertEqual(ret, 0)
        self.assertEqual(out, "Hello World\n")

    def test_stdout_tty(self):
        c = self.config()
        c["process"]["args"] = ["echo", "Hello", "World"]
        c["process"]["terminal"] = True
        ret, out, _ = self.run_with_config(c)
        self.assertEqual(ret, 0)
        self.assertEqual(out, "Hello World\r\n")

    def test_chroot(self):
        with tempfile.TemporaryDirectory() as root_dir:
            shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
            c = self.config()
            c["root"]["path"] = root_dir
            c["process"]["args"] = ["sh", "-c", "echo Hello World > /file"]
            c["process"]["env"] = ["PATH=/rescue"]
            ret, _, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            with open(os.path.join(root_dir, "file"), "r") as f:
                self.assertEqual(f.read(), "Hello World\n")

    def test_devfs_file_mount(self):
        # A file bind-mounted below a devfs mount, like Kubernetes'
        # terminationMessagePath: /dev/termination-custom-log. devfs cannot
        # hold the regular file a mount point needs, so ocijail mounts it
        # elsewhere and links it into /dev; writes must reach the host file.
        with tempfile.TemporaryDirectory() as root_dir, \
             tempfile.NamedTemporaryFile(mode="r") as msg:
            shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
            os.mkdir(os.path.join(root_dir, "dev"))
            c = self.config()
            c["root"]["path"] = root_dir
            c["mounts"] = [
                # ruleset 4 (devfsrules_jail) hides everything not
                # unhidden, as CRI-O and podman use for containers
                {"destination": "/dev", "type": "devfs", "source": "devfs",
                 "options": ["ruleset=4"]},
                {"destination": "/dev/termination-custom-log",
                 "type": "nullfs", "source": msg.name},
            ]
            c["process"]["args"] = [
                "sh", "-c", "echo -n DONE > /dev/termination-custom-log"]
            c["process"]["env"] = ["PATH=/rescue"]
            try:
                ret, _, _ = self.run_with_config(c)
                self.assertEqual(ret, 0)
                self.assertEqual(msg.read(), "DONE")
            finally:
                # unmount (devfs, file mount) before root_dir is removed
                self.delete(False)
            # nothing left behind in the container root
            self.assertFalse(
                os.path.exists(os.path.join(root_dir, ".ocijail-devfiles")))

    def test_socket_mount(self):
        # A unix(4) socket bind-mounted into the container, like a
        # Kubernetes hostPath to a daemon's socket: ocijail creates a socket
        # node to mount over, and connections reach the host listener.
        import threading
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            src = os.path.join(d, "s")
            dst = os.path.join(d, "in", "agent.sock")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(src)
            srv.listen(1)
            srv.settimeout(20)

            def serve():
                try:
                    conn, _ = srv.accept()
                    conn.sendall(b"hello")
                    conn.close()
                except OSError:
                    pass
            # Skip where nullfs can't mount sockets (FreeBSD before
            # 2c68ad49f13d): probe with mount_nullfs(8) on a socket node.
            probe = os.path.join(d, "probe")
            p = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            p.bind(probe)
            p.close()
            if subprocess.run(["mount_nullfs", src, probe],
                              capture_output=True).returncode != 0:
                srv.close()
                self.skipTest("nullfs cannot mount unix sockets here")
            subprocess.run(["umount", probe], check=True)
            t = threading.Thread(target=serve)
            t.start()
            c = self.config()
            c["mounts"] = [
                {"destination": dst, "type": "nullfs", "source": src},
            ]
            c["process"]["args"] = ["/usr/bin/nc", "-U", dst]
            try:
                ret, out, err = self.run_with_config(c)
                self.assertEqual(ret, 0, err)
                self.assertEqual(out, "hello")
            finally:
                self.delete(False)
                srv.close()
                t.join()
            # the socket node ocijail created is gone
            self.assertFalse(os.path.exists(dst))

    def test_device_node_mount(self):
        # A device node made with mknod(2) outside devfs, like the Kubernetes
        # HostPathType CharDevice/BlockDevice tests use. nullfs can't mount
        # it, so ocijail gives the container a node of the same type,
        # number, mode and owner, and removes it (restoring what was there)
        # on delete.
        with tempfile.TemporaryDirectory() as root_dir, \
             tempfile.TemporaryDirectory(dir="/tmp") as d:
            shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
            os.makedirs(os.path.join(root_dir, "etc"))
            kept = os.path.join(root_dir, "etc", "kept")
            with open(kept, "w") as f:
                f.write("image file")
            chardev = os.path.join(d, "achardev")
            blkdev = os.path.join(d, "ablkdev")
            os.mknod(chardev, 0o640 | 0o020000, os.makedev(89, 1))
            os.chown(chardev, 0, 5)
            os.mknod(blkdev, 0o600 | 0o060000, os.makedev(89, 2))
            c = self.config()
            c["root"]["path"] = root_dir
            c["mounts"] = [
                {"destination": "/mnt/test/c", "type": "nullfs",
                 "source": chardev},
                {"destination": "/etc/kept", "type": "nullfs",
                 "source": blkdev},
            ]
            c["process"]["args"] = [
                "sh", "-c", "ls -ln /mnt/test/c /etc/kept"]
            c["process"]["env"] = ["PATH=/rescue"]
            try:
                ret, out, err = self.run_with_config(c)
                self.assertEqual(ret, 0, err)
                lines = out.splitlines()
                self.assertRegex(lines[0], r"^brw------- +1 0 +0 +0x5902 ")
                self.assertRegex(lines[1], r"^crw-r----- +1 0 +5 +0x5901 ")
            finally:
                self.delete(False)
            # the copy and the directories made for it are gone, and the
            # image's file is back
            self.assertFalse(os.path.exists(os.path.join(root_dir, "mnt")))
            with open(kept) as f:
                self.assertEqual(f.read(), "image file")

            # A devfs device is refused: a copy would be inert, not the
            # device.
            c["mounts"] = [
                {"destination": "/mnt/null", "type": "nullfs",
                 "source": "/dev/null"},
            ]
            c["process"]["args"] = ["true"]
            ret, _, _ = self.run_with_config(c, expected_ret=1)
            self.assertEqual(ret, 1)
            self.delete(False)
            self.assertFalse(os.path.exists(os.path.join(root_dir, "mnt")))

    def test_process_user_umask(self):
        c = self.config()
        # If process.user.umask is set, this should be the value of umask inside
        # the container
        c["process"]["user"] = {"uid": 0, "gid": 0}
        c["process"]["user"]["umask"] = 0o022
        c["process"]["args"] = ["umask"]
        ret, out, _ = self.run_with_config(c)
        self.assertEqual(ret, 0)
        self.assertEqual(out.strip(), "0022")

    def test_propagate_umask(self):
        c = self.config()
        # If process.user.umask is not set, the caller's umask should be
        # propagated to the container
        old_umask = os.umask(0o011)
        c["process"]["args"] = ["umask"]
        ret, out, _ = self.run_with_config(c)
        self.assertEqual(ret, 0)
        self.assertEqual(out.strip(), "0011")
        os.umask(old_umask)

    def test_hook_create_runtme(self):
        with tempfile.TemporaryDirectory() as scratch:
            c = self.config()
            c["process"]["args"] = ["sh", "-c", f"exit $(cat {scratch}/file)"]
            c["hooks"] = {
                "createRuntime": [
                    {
                        "path": "/bin/sh",
                        "env": [
                            "foo=99"
                        ],
                        "args": [
                            "-c",
                            f"echo $foo > {scratch}/file"
                        ]
                    }
                ]
            }
            ret, _, _ = self.run_with_config(c)
            self.assertEqual(ret, 99)

    def test_hook_prestart(self):
        with tempfile.TemporaryDirectory() as scratch:
            c = self.config()
            c["process"]["args"] = ["sh", "-c", f"exit $(cat {scratch}/file)"]
            c["hooks"] = {
                "prestart": [
                    {
                        "path": "/bin/sh",
                        "args": [
                            "-c",
                            f"echo 99 > {scratch}/file"
                        ]
                    }
                ]
            }
            ret, _, _ = self.run_with_config(c)
            self.assertEqual(ret, 99)

    def test_hook_create_container(self):
        with tempfile.TemporaryDirectory() as root_dir:
            shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
            c = self.config()
            c["root"]["path"] = root_dir
            c["process"]["args"] = ["sh", "-c", "exit $(cat /file)"]
            c["process"]["env"] = ["PATH=/rescue"]
            c["hooks"] = {
                "createContainer": [
                    {
                        "path": "/rescue/sh",
                        "args": [
                            "-c",
                            "echo 42 > file"
                        ]
                    }
                ]
            }
            ret, _, _ = self.run_with_config(c)
            self.assertEqual(ret, 42)

    def test_hook_start_container(self):
        with tempfile.TemporaryDirectory() as root_dir:
            shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
            c = self.config()
            c["root"]["path"] = root_dir
            c["process"]["args"] = ["sh", "-c", "exit $(cat /file)"]
            c["process"]["env"] = ["PATH=/rescue"]
            c["hooks"] = {
                "startContainer": [
                    {
                        "path": "/rescue/sh",
                        "args": [
                            "-c",
                            "echo 42 > /file"
                        ]
                    }
                ]
            }
            ret, _, _ = self.run_with_config(c)
            self.assertEqual(ret, 42)

    def test_hook_poststop(self):
        with tempfile.TemporaryDirectory() as scratch:
            c = self.config()
            c["process"]["args"] = ["sh", "-c", f"exit $(cat {scratch}/file)"]
            c["hooks"] = {
                "createRuntime": [
                    {
                        "path": "/bin/sh",
                        "env": [
                            "foo=123"
                        ],
                        "args": [
                            "-c",
                            f"echo $foo > {scratch}/file"
                        ]
                    }
                ],
                "poststop": [
                    {
                        "path": "/bin/rm",
                        "args": [
                            f"{scratch}/file"
                        ]
                    }
                ]
            }
            ret, _, _ = self.run_with_config(c)
            self.assertEqual(ret, 123)
            self.assertTrue(os.path.exists(f"{scratch}/file"))
            self.delete()
            self.assertFalse(os.path.exists(f"{scratch}/file"))

    def test_validate_command_path(self):
        with tempfile.TemporaryDirectory() as root_dir:
            random_dir = secrets.token_urlsafe(8)
            shutil.copytree("/rescue", os.path.join(root_dir, random_dir))
            c = self.config()
            c["root"]["path"] = root_dir
            c["process"]["args"] = ["echo", "Hello World"]
            c["process"]["env"] = [f"PATH=/{random_dir}"]
            ret, out, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            self.assertEqual(out, "Hello World\n")

    def test_validate_command_duplicate_path(self):
        # CRI-O (via runtime-tools) can emit PATH twice: its default
        # first, then the image's. Like runc, the last entry must win.
        with tempfile.TemporaryDirectory() as root_dir:
            random_dir = secrets.token_urlsafe(8)
            shutil.copytree("/rescue", os.path.join(root_dir, random_dir))
            c = self.config()
            c["root"]["path"] = root_dir
            c["process"]["args"] = ["echo", "Hello World"]
            c["process"]["env"] = ["PATH=/nonexistent", "FOO=1", f"PATH=/{random_dir}"]
            ret, out, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            self.assertEqual(out, "Hello World\n")

    def test_validate_command_abs(self):
        with tempfile.TemporaryDirectory() as root_dir:
            random_dir = secrets.token_urlsafe(8)
            shutil.copytree("/rescue", os.path.join(root_dir, random_dir))
            c = self.config()
            c["root"]["path"] = root_dir
            c["process"]["args"] = [f"/{random_dir}/echo", "Hello World"]
            ret, out, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            self.assertEqual(out, "Hello World\n")

    def test_tmpcopyup(self):
        # Running the container should copy the contents of /tmpdir to a
        # tmpfs which is mounted over it
        with tempfile.TemporaryDirectory() as root_dir:
            shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
            c = self.config()
            c["root"]["path"] = root_dir
            c["process"]["args"] = ["cat", "/tmpdir/file"]
            c["process"]["env"] = ["PATH=/rescue"]
            c["mounts"] = [
                {
                    "type": "tmpfs",
                    "destination": "/tmpdir",
                    "options": ["tmpcopyup"],
                },
            ]
            os.mkdir(os.path.join(root_dir, "tmpdir"))
            with open(os.path.join(root_dir, "tmpdir", "file"), "w") as f:
                f.write("Hello World\n")
            ret, out, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            self.assertEqual(out, "Hello World\n")
            # Delete the container so that the tmpfs is unmounted
            # before we delete root_dir
            self.delete()

    def test_cleanup_mounts(self):
        # Verify that /foo is removed strictly after /foo/dir1 and /foo/dir2
        with tempfile.TemporaryDirectory() as root_dir:
            shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
            c = self.config()
            c["root"]["path"] = root_dir
            c["process"]["args"] = ["sh", "-c", "exit 0"]
            c["process"]["env"] = ["PATH=/rescue"]
            c["mounts"] = [
                {
                    "type": "tmpfs",
                    "destination": "/foo/dir1",
                },
                {
                    "type": "tmpfs",
                    "destination": "/foo/dir2",
                },
            ]
            ret, out, _ = self.run_with_config(c)
            self.assertEqual(ret, 0)
            # Delete the container so that the tmpfs is unmounted
            # before we delete root_dir
            self.delete()

    def test_readonly_root(self):
        # Running the container should not modify the root
        with tempfile.TemporaryDirectory() as root_dir:
            shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
            c = self.config()
            c["root"]["path"] = root_dir
            c["root"]["readonly"] = True
            c["process"]["args"] = ["sh", "-c", "echo world > /hello; exit 0"]
            c["process"]["env"] = ["PATH=/rescue"]
            c["mounts"] = [
                {
                    "type": "tmpfs",
                    "destination": "/tmpdir",
                },
            ]
            ret, out, err = self.run_with_config(c)
            self.assertEqual(err.count("Read-only file system"), 1)
            self.assertFalse(os.path.exists(os.path.join(root_dir, "hello")))
            self.assertEqual(ret, 0)
            # Delete the container so that the tmpfs is unmounted
            # before we delete root_dir
            self.delete()

    # setup is a function which is called to initialise the root, destination is
    # the path inside the root for our mount and real_destination is the path
    # inside the root after resolving symlinks
    def symlink_test_helper(self, setup, destination, real_destination, expected_ret=0):
        # Test mounting to a path which goes via a symbolic link
        with tempfile.TemporaryDirectory() as root_dir:
            with tempfile.NamedTemporaryFile(mode="wb", buffering=0) as file_to_mount:
                shutil.copytree("/rescue", os.path.join(root_dir, "rescue"))
                file_to_mount.write(b"Hello World\n")
                setup(root_dir)

                c = self.config()
                c["root"]["path"] = root_dir
                c["process"]["args"] = ["cat", real_destination]
                c["process"]["env"] = ["PATH=/rescue"]
                c["mounts"] = [
                    {
                        "type": "nullfs",
                        "destination": destination,
                        "source": file_to_mount.name,
                    },
                ]
                ret, out, _ = self.run_with_config(c, expected_ret)
                self.assertEqual(ret, expected_ret)
                if ret == 0:
                    self.assertEqual(out, "Hello World\n")
                # Delete the container so that the file mount is unmounted
                # before we delete root_dir
                self.delete()

    def test_mount_absolute_symlink(self):
        def setup(root_dir):
            # If mounting to /var/run/foo and /var/run is a symlink to /run, the
            # mount should target {root_dir}/run/foo
            os.mkdir(os.path.join(root_dir, "run"))
            os.mkdir(os.path.join(root_dir, "var"))
            os.symlink("/run", os.path.join(root_dir, "var/run"))
        self.symlink_test_helper(setup, "/var/run/foo", "/run/foo")

    def test_mount_relative_symlink(self):
        def setup(root_dir):
            # If mounting to /var/run/foo and /var/run is a symlink to somedir, the
            # mount should target {root_dir}/var/somedir/foo
            os.mkdir(os.path.join(root_dir, "var"))
            os.symlink("somedir", os.path.join(root_dir, "var/run"))
        self.symlink_test_helper(setup, "/var/run/foo", "/var/somedir/foo")

    def test_mount_symlink_parent(self):
        def setup(root_dir):
            # If mounting to /var/run/foo and /var/run is a symlink to "../somedir", the
            # mount should target {root_dir}/somedir/foo
            # 
            os.mkdir(os.path.join(root_dir, "somedir"))
            os.mkdir(os.path.join(root_dir, "var"))
            os.symlink("../somedir", os.path.join(root_dir, "var/run"))
        self.symlink_test_helper(setup, "/var/run/foo", "/somedir/foo")

    def test_mount_symlink_root_escape(self):
        def setup(root_dir):
            # Verify that its not possible for a mount to escape above the root
            # directory using ".."
            # 
            os.mkdir(os.path.join(root_dir, "somedir"))
            os.mkdir(os.path.join(root_dir, "var"))
            os.symlink("../../somedir", os.path.join(root_dir, "var/run"))
        self.symlink_test_helper(setup, "/var/run/foo", "/somedir/foo")

    def test_mount_recursive_symlink(self):
        def setup(root_dir):
            # Make sure that symlinks to symlinks are resolve correctly
            #
            os.mkdir(os.path.join(root_dir, "var"))
            os.symlink("somelink", os.path.join(root_dir, "var/run"))
            os.symlink("somedir", os.path.join(root_dir, "var/somelink"))
        self.symlink_test_helper(setup, "/var/run/foo", "/var/somedir/foo")

    def test_mount_symlink_loop(self):
        def setup(root_dir):
            # Symlink loops should cause an error
            #
            os.mkdir(os.path.join(root_dir, "var"))
            os.symlink("somelink", os.path.join(root_dir, "var/run"))
            os.symlink("somelink", os.path.join(root_dir, "var/somelink"))
        self.symlink_test_helper(setup, "/var/run/foo", "/var/somedir/foo", expected_ret=1)

if __name__ == "__main__":
    if os.getenv("OCIJAIL_PATH"):
        cmd = os.getenv("OCIJAIL_PATH")
    unittest.main()

