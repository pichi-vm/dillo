# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Diagnostic stack sampling of this benchmark's own process tree only."""

import subprocess
import time


class Profiles:
    def __init__(self, directory):
        self.directory = directory
        self.children = []
        self.records = []
        self.started = False

    def start(self, processes, elapsed):
        self.started = True
        for process in processes:
            report = self.directory / f"sample-{process.pid}.txt"
            record = {"pid": process.pid, "created": process.create_time(),
                      "started_elapsed_s": elapsed, "report": report.name}
            command = ["/usr/bin/sample", str(process.pid), "3", "1",
                       "-mayDie", "-file", str(report)]
            record["command"] = command
            log = report.with_suffix('.log.txt').open('wb')
            try:
                child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                self.children.append((child, log, record))
            except OSError as error:
                log.close()
                record["error"] = str(error)
            self.records.append(record)

    def finish(self, started):
        for child, log, record in self.children:
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                record["error"] = "sample did not finish before its cleanup deadline"
            finally:
                log.close()
            record["returncode"] = child.returncode
            record["reaped_elapsed_s"] = time.monotonic() - started
