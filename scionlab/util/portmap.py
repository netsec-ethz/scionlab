# Copyright 2018 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from scionlab.defines import MAX_PORT


class PortMap:
    """
    Simple helper for managing/assigning ports.
    Keeps a set of used ports per IP.
    The IP `None` is used for ports bound on any address (0.0.0.0 / ::).

    Note: this map does not care about the type used to represent the IPs; it just assumes
    that identical values represent identical addresses.
    """

    def __init__(self):
        self.ports = dict()  # ports[ip] = set of used ports

    def get_port(self, ip, min, max=MAX_PORT, preferred=None):
        """
        Get a free port for this IP address in the given range.
        The returned port is immediately marked as used for the queried IP address.
        :param ip: IP address or `None` for the unspecified address
        :param int min: Start of acceptable port range
        :param int max: Optional, end (included) of acceptable port range
        :param int preferred: Optional, preferred port. Will be selected if free (range not checked)
        :returns: Port
        :raises: RuntimeError if no free port could be found
        """
        port = self._find_free_port(ip, min, max, preferred)
        if port is None:
            raise RuntimeError('No free port available in range')
        self.add(ip, port)
        return port

    def _find_free_port(self, ip, min, max, preferred):
        """
        Find a free port for this IP address in the given range.
        """
        if preferred and self.is_free(ip, preferred):
            return preferred
        for port in range(min, max):
            if self.is_free(ip, port):
                return port
        return None

    def is_free(self, ip, port):
        """
        Check if the given IP/port combination is free.
        :param ip: IP address or `None` for the unspecified address
        :param int port: Port
        :returns: True iff port is free
        """
        return not self.is_used(ip, port)

    def is_used(self, ip, port):
        """
        check if the given ip/port combination is used.
        :param ip: ip address or `none` for the unspecified address
        :param int port: port
        :returns: true iff port is used
        """
        if ip is not None:
            return port in self.ports.get(ip, set()) or port in self.ports.get(None, set())
        else:
            return any(port in portset for portset in self.ports.values())

    def add(self, ip, port):
        """
        add a ip/port combination to the set of used ports. this has no effect if it
        is already present in the set of used ports.
        :param ip: ip address or `none` for the unspecified address
        :param int port: port
        """
        assert isinstance(port, int)
        self.ports.setdefault(ip, set()).add(port)

    def update(self, ip, ports):
        """
        Add many IP/port combination to the set of used ports. This has no effect if it
        is already present in the set of used ports.
        :param ip: IP address or `None` for the unspecified address
        :param iterable ports: Ports
        """
        assert all(isinstance(port, int) for port in ports)
        self.ports.setdefault(ip, set()).update(ports)


class LazyPortMap:
    """
    Lazy Proxy for PortMap. Unfortuntely there doesn't seem to be a generic implementation for
    this in the standard library (third party libraries exist).

    To keep this simple and obvious, this is verbose rather than fancy.
    """
    def __init__(self, factory):
        self._factory = factory
        self.instance = None

    def _wrapped(self):
        if self.instance is None:
            self.instance = self._factory()
        return self.instance

    def get_port(self, *args, **kwargs):
        return self._wrapped().get_port(*args, **kwargs)

    def is_free(self, *args, **kwargs):
        return self._wrapped().is_free(*args, **kwargs)

    def is_used(self, *args, **kwargs):
        return self._wrapped().is_used(*args, **kwargs)

    def add(self, *args, **kwargs):
        return self._wrapped().add(*args, **kwargs)

    def update(self, *args, **kwargs):
        return self._wrapped().update(*args, **kwargs)
