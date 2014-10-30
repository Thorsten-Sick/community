# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class AntiVMServices(Signature):
    name = "antivm_generic_services"
    description = "Enumerates services, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.2"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    def on_call(self, call, pid, tid):
        if call["api"].startswith("EnumServicesStatus"):
            return True
        process = self.get_processes_by_pid(pid)
        if process is not self.lastprocess:
            self.handle = None
            self.lastprocess = process

        if not self.handle:
            if call["api"].startswith("RegOpenKeyEx"):
                correct = False
                if self.get_argument(call,"regkey").lower() == "hkey_local_machine\\system\\controlset001\\services":
                    correct = True
                else:
                    self.handle = self.get_argument(call,"key_handle")

                if not correct:
                    self.handle = None
        else:
            if call["api"].startswith("RegEnumKeyEx"):
                if self.get_argument(call,"key_handle") == self.handle:
                    return True
