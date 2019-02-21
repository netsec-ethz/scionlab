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

import base64
import binascii
from django.http import HttpResponse


class HttpResponseAttachment(HttpResponse):
    """
    Simple HttpResponse to send content with Content-Disposition "attachment".
    In contrast to django.http.FileResponse, this is non-streaming.
    """
    def __init__(self, filename, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self['Content-Disposition'] = 'attachment; filename="{}"'.format(filename)


class HttpResponseAuthenticate(HttpResponse):
    """
    Response to unauthenticated requests to views requiring Basic authentication.
    """
    status_code = 401

    def __init__(self, realm, *args, **kwargs):
        """
        :param str realm: User visible realm
        """
        super().__init__(*args, **kwargs)
        self['WWW-Authenticate'] = 'Basic realm="%s", charset="UTF-8"' % realm


def _parse_basic_auth(request):
    """
    Helper for basicauth. Extract password, username from Authorization Basic header.
    :returns: username, password as (str, str) or (None, None) if header not present or malformed.
    """
    if 'HTTP_AUTHORIZATION' in request.META:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        if len(auth) == 2 and auth[0].lower() == "basic":
            try:
                auth_str = base64.b64decode(auth[1], validate=True).decode()
                uname_pwd = auth_str.split(':')
                if len(uname_pwd) == 2:
                    return tuple(uname_pwd)
            except binascii.Error:
                pass
            except UnicodeDecodeError:
                pass
    return (None, None)


def basicauth(authenticate, realm=""):
    """
    View decorator for basic authentication.
    :param authenticate: function (username: str, password: str) -> bool
    :param str realm: User visible realm
    """
    def view_decorator(view):
        def wrapper(request, *args, **kwargs):
            uname, passwd = _parse_basic_auth(request)
            if uname and passwd and authenticate(uname, passwd):
                return view(request, *args, **kwargs)
            else:
                return HttpResponseAuthenticate(realm)
        return wrapper
    return view_decorator
