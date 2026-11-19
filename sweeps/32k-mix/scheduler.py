#!/usr/bin/env python3
"""Run the jobs in queue.txt on a shared machine without exceeding a memory budget.

Every job runs `uv run shadow-sim.py jobs/<name>.toml --clean` in its own
systemd user scope inside leansim.slice, whose unit file caps the memory of all
jobs together (MemoryHigh/MemoryMax, no swap). On top of that hard cap the
scheduler admits a new job only when

  - the jobs' projected memory (each running job at least the per-job estimate)
    plus one more job stays under budget_gib, and
  - the machine's MemAvailable minus one job stays above host_reserve_gib,

so the jobs never come near the cap and other users keep their memory. The
per-job estimate starts at estimate_gib and becomes the largest peak measured so
far (times estimate_margin) once a job has finished. Memory is counted without
reclaimable page cache: anon + shmem + kernel.

settings.json and queue.txt are re-read every loop, so limits can be changed
while it runs. A job runs while any process has its job file on the command line;
it is done once none has, and succeeded if its log has the launcher's summary
line. Its raw Shadow logs (shadow.data) are then deleted, keeping the metrics.
Touch PAUSE to stop admitting jobs. Running jobs are independent of this process:
restart it and it picks them up again, wherever their processes are.

Jobs call uv through bin/uv, the binary inside the snap: /snap/bin/uv goes
through snap's launcher, which moves the process out of its scope and so out
of the memory cap.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
UID = os.getuid()
SLICE = Path(f"/sys/fs/cgroup/user.slice/user-{UID}.slice/user@{UID}.service/leansim.slice")
GIB = 1024**3
ENV = {**os.environ, "XDG_RUNTIME_DIR": f"/run/user/{UID}",
       "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{UID}/bus",
       "PATH": f"{HERE / 'bin'}:{os.environ.get('PATH', '')}"}
LAUNCHERS = {"python3", "python", "uv", "taskset", "systemd-run"}


def settings():
    defaults = {"max_jobs": 4, "budget_gib": 280, "host_reserve_gib": 165, "estimate_gib": 150,
                "estimate_margin": 1.15, "cpus": "0-47", "poll_s": 15, "retry": [], "total_cap_gib": 330}
    path = HERE / "settings.json"
    if path.exists():
        defaults.update(json.loads(path.read_text()))
    return defaults


def unit(name):
    return f"lsim-{name}"


def used_bytes(cgroup):
    """Memory that cannot simply be dropped: everything but non-shmem page cache."""
    try:
        current = int((cgroup / "memory.current").read_text())
        stat = dict(line.split() for line in (cgroup / "memory.stat").read_text().splitlines())
    except (OSError, ValueError):
        return None
    return current - int(stat.get("file", 0)) + int(stat.get("shmem", 0))


def mem_available():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return 0


def output_dir(name):
    config = tomllib.loads((HERE / "jobs" / f"{name}.toml").read_text())
    return Path(config["output"]["dir"])


def log_path(name):
    return HERE / "logs" / f"{name}.log"


def finished_ok(name):
    try:
        text = log_path(name).read_text(errors="replace")
    except OSError:
        return False
    return "[shadow-sim] summary:" in text and (output_dir(name) / "runs-history.json").exists()


def progress(name):
    try:
        with open(log_path(name), "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - 8192))
            tail = handle.read().decode(errors="replace")
    except OSError:
        return "-"
    if "writing interactive summary" in tail:
        return "report"
    if "Shadow completed successfully" in tail:
        return "analysis"
    found = re.findall(r"Progress: (\d+)% — simulated: ([\d:.]+)", tail)
    if not found:
        return "sim starting" if "running Shadow" in tail else "setup"
    percent, simulated = found[-1]
    # Shadow is done at 100%; the launcher then analyzes the logs.
    return "analysis" if percent == "100" else f"sim {percent}% (simulated {simulated[3:]})"


def read_status():
    """Last status row per job, and how many times each job failed."""
    rows, failures = {}, {}
    path = HERE / "status.tsv"
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                rows[parts[0]] = parts
                if parts[1] == "FAILED":
                    failures[parts[0]] = failures.get(parts[0], 0) + 1
    return rows, failures


def set_slice_cap(cap_gib, last):
    """Cap the slice so that capped and uncapped jobs together stay under the total."""
    cap_gib = max(16, int(cap_gib))
    if last is not None and abs(cap_gib - last) < 2:
        return last
    subprocess.run(["systemctl", "--user", "set-property", "--runtime", "leansim.slice",
                    f"MemoryMax={cap_gib}G", f"MemoryHigh={max(8, cap_gib - 15)}G"], env=ENV, check=False)
    return cap_gib


def write_status(row):
    with open(HERE / "status.tsv", "a") as handle:
        handle.write("\t".join(str(field) for field in row) + "\n")


def running_jobs():
    """Job name -> (cgroup of its processes, process start in seconds since boot),
    for every job with a live process that has its job file on the command line."""
    jobs_dir = str(HERE / "jobs") + "/"
    found = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != UID:
                continue
            with open(f"/proc/{entry.name}/comm") as handle:
                comm = handle.read().strip()
            if comm not in LAUNCHERS:
                continue
            with open(f"/proc/{entry.name}/cmdline", "rb") as handle:
                args = handle.read().decode(errors="replace").split("\0")
            job = next((arg for arg in args if arg.startswith(jobs_dir) and arg.endswith(".toml")), None)
            if job is None:
                continue
            with open(f"/proc/{entry.name}/cgroup") as handle:
                cgroup = Path("/sys/fs/cgroup" + handle.read().strip().split("::", 1)[1])
        except (OSError, IndexError):
            continue
        name = Path(job).stem
        # The launcher's own Python process is inside the scope that holds the whole
        # job; systemd-run stays in the caller's cgroup.
        rank = 2 if comm.startswith("python") and any(arg.endswith("shadow-sim.py") for arg in args) else 1
        if name not in found or rank > found[name][1]:
            found[name] = (cgroup, rank)
    return {name: cgroup for name, (cgroup, _) in found.items()}


def launch(name, cpus):
    # A scope left over from a killed run would block the new one's unit name.
    for action in ("stop", "reset-failed"):
        subprocess.run(["systemctl", "--user", action, f"{unit(name)}.scope"], env=ENV,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    log = open(log_path(name), "w")
    command = ["systemd-run", "--user", "--scope", "--quiet", "--slice=leansim.slice",
               f"--unit={unit(name)}", "-p", "MemorySwapMax=0",
               "taskset", "-c", cpus, "uv", "run", "shadow-sim.py", str(HERE / "jobs" / f"{name}.toml"), "--clean"]
    return subprocess.Popen(command, cwd=REPO, env=ENV, stdout=log, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)


def main():
    (HERE / "logs").mkdir(exist_ok=True)
    children = {}
    started = {}
    peaks = {}
    cgroups = {}
    grace = {}
    slice_cap = None
    for name in running_jobs():
        started[name] = time.time()
        print(f"adopted running job {name}")
    while True:
        config = settings()
        queue = [line.strip() for line in (HERE / "queue.txt").read_text().splitlines() if line.strip()]
        status, failures = read_status()
        for child in list(children.values()):
            child.poll()
        active = running_jobs()
        cgroups.update(active)
        for name in list(started):
            usage = used_bytes(cgroups[name]) if name in cgroups else None
            if usage is not None:
                peaks[name] = max(peaks.get(name, 0), usage)
            if name in active:
                continue
            # A just-launched job may not have its processes up yet.
            if time.time() - grace.get(name, 0) < 60:
                continue
            # No process of the job is left: it finished one way or the other.
            child = children.pop(name, None)
            if child is not None and child.poll() is None:
                continue
            cgroups.pop(name, None)
            ok = finished_ok(name)
            wall = (time.time() - started.pop(name)) / 60
            peak = peaks.get(name, 0) / GIB
            if ok:
                shutil.rmtree(output_dir(name) / "shadow.data", ignore_errors=True)
            write_status([name, "ok" if ok else "FAILED", time.strftime("%H:%M"), f"{wall:.1f}", f"{peak:.1f}",
                          child.returncode if child is not None else "?"])
            status, failures = read_status()

        # Jobs outside the slice (started before the uv fix) are not capped by it,
        # so the slice gets what is left of the total.
        outside = sum(used_bytes(cgroup) or 0 for cgroup in cgroups.values() if SLICE not in cgroup.parents)
        slice_cap = set_slice_cap(config["total_cap_gib"] - outside / GIB, slice_cap)

        measured = [float(row[4]) for row in status.values() if row[1] == "ok" and float(row[4]) > 0]
        estimate = max(measured) * config["estimate_margin"] if measured else config["estimate_gib"]
        estimate_bytes = estimate * GIB
        slice_used = used_bytes(SLICE) or 0
        projected = sum(max((used_bytes(cgroups[name]) if name in cgroups else 0) or 0, estimate_bytes)
                        for name in started)
        # A failed job gets one automatic retry, after the rest of the queue.
        pending = [name for name in queue if name not in started and name not in status]
        pending += [name for name in queue if name not in started and name in status and status[name][1] == "FAILED"
                    and (failures.get(name, 0) < 2 or name in config["retry"])]
        paused = (HERE / "PAUSE").exists()
        launched_now = None
        if (pending and not paused and len(started) < config["max_jobs"]
                and projected + estimate_bytes <= config["budget_gib"] * GIB
                and mem_available() - estimate_bytes >= config["host_reserve_gib"] * GIB):
            name = pending[0]
            if name in config["retry"] and name in status:
                config["retry"].remove(name)
            children[name] = launch(name, config["cpus"])
            started[name] = grace[name] = time.time()
            peaks[name] = 0
            launched_now = name
            pending.remove(name)

        done = sum(1 for row in status.values() if row[1] == "ok")
        failed = [row[0] for row in status.values() if row[1] == "FAILED"]
        lines = [
            time.strftime("%Y-%m-%d %H:%M:%S") + f"  jobs {done} done, {len(started)} running, {len(pending)} queued"
            + (f", {len(failed)} FAILED" if failed else "") + ("  [PAUSED]" if paused else ""),
            f"memory: jobs {sum((used_bytes(c) or 0) for c in cgroups.values()) / GIB:.0f} GiB now (capped slice "
            f"{slice_used / GIB:.0f}; projected {projected / GIB:.0f}, budget "
            f"{config['budget_gib']}), machine available {mem_available() / GIB:.0f} GiB (reserve "
            f"{config['host_reserve_gib']}), per-job estimate {estimate:.0f} GiB, slice cap {slice_cap} GiB",
            "",
            f"{'running':<26} {'minutes':>8} {'mem GiB':>8} {'peak':>6}  progress",
        ]
        for name in sorted(started, key=started.get):
            usage = ((used_bytes(cgroups[name]) if name in cgroups else 0) or 0) / GIB
            capped = "" if name not in cgroups or SLICE in cgroups[name].parents else "  (outside the cap)"
            lines.append(f"{name:<26} {(time.time() - started[name]) / 60:>8.1f} {usage:>8.1f} "
                         f"{peaks.get(name, 0) / GIB:>6.1f}  {progress(name)}{capped}")
        if launched_now:
            lines.append(f"(started {launched_now})")
        lines += ["", f"{'finished':<26} {'state':>6} {'at':>6} {'minutes':>8} {'peak GiB':>9}"]
        for row in list(status.values())[-12:]:
            lines.append(f"{row[0]:<26} {row[1]:>6} {row[2]:>6} {row[3]:>8} {row[4]:>9}")
        if failed:
            lines.append("FAILED: " + ", ".join(failed) + "  (see logs/; add to settings.json 'retry' to rerun)")
        text = "\n".join(lines) + "\n"
        (HERE / "dashboard.txt").write_text(text)
        sys.stdout.write("\033[2J\033[H" + text)
        sys.stdout.flush()
        if not started and not pending:
            print("all jobs finished")
            return
        time.sleep(5 if launched_now else config["poll_s"])


if __name__ == "__main__":
    main()
