# Copyright (C) 2013 Claudio "nex" Guarnieri (@botherder)
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

class AntiVMBios(Signature):
    name = "antivm_generic_bios"
    description = "Checks the version of Bios, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.2"

    def on_call(self, call, pid, tid):
        #if self.check_key(pattern="HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System"):
        if (self.check_argument_call(call, pattern="SystemBiosVersion", name="value", category="registry") or
            self.check_argument_call(call, pattern="VideoBiosVersion", name="value", category="registry")):
            return True
