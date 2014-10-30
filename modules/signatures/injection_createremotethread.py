# Copyright (C) 2012 JoseMi "h0rm1" Holguin (@j0sm1)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class InjectionCRT(Signature):
    name = "injection_createremotethread"
    description = "Code injection with CreateRemoteThread in a remote process"
    severity = 2
    categories = ["injection"]
    authors = ["JoseMi Holguin", "nex"]
    minimum = "1.2"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    def on_call(self, call, pid, tid):
        process = list(self.get_processes_by_pid(pid))[0]
        if process is not self.lastprocess:
            self.sequence = 0
            self.process_handle = 0
            self.lastprocess = process

        if call["api"]  == "NtOpenProcess" and self.sequence == 0:
            if self.get_argument(call, "process_identifier") != process["process_identifier"]:
                self.sequence = 1
                self.process_handle = call["return_value"]
        elif call["api"] == "VirtualAllocEx" and self.sequence == 1:
            if self.get_argument(call, "process_handle") == self.process_handle:
                self.sequence = 2
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "WriteProcessMemory") and self.sequence == 2:
            if self.get_argument(call, "process_handle") == self.process_handle:
                self.sequence = 3
        elif call["api"].startswith("CreateRemoteThread") and self.sequence == 3:
            if self.get_argument(call, "process_handle") == self.process_handle:
                return True
