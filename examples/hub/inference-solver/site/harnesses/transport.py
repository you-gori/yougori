"""Fixed loopback transport for Yougori's isolated application origins."""
import http.client
import re
import socket
import urllib.request


def local_hostname(host):
    return host in ('127.0.0.1', 'localhost', '::1') or bool(re.fullmatch(r'[a-z0-9]+\.localhost', host or ''))


class LocalConnection(http.client.HTTPConnection):
    def connect(self):
        # Preserve HTTP Host (the publication identity); never resolve this name
        # through DNS, a system proxy, or a hosts-file entry.
        if local_hostname(self.host) and self.host.endswith('.localhost'):
            self.sock = socket.create_connection(('127.0.0.1', self.port), self.timeout, self.source_address)
        else:
            super().connect()


class LocalHTTP(urllib.request.HTTPHandler):
    def http_open(self, request):
        return self.do_open(LocalConnection, request)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalHTTP(), NoRedirect())
