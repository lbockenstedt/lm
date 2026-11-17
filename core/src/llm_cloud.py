"""OpenAI-compatible cloud inference for explicitly approved public tasks."""

import http.client
import ipaddress
import json
import socket
from urllib.parse import urlsplit

from access import safe_external_url

TOKEN_LIMIT_FIELDS = ("max_tokens", "max_completion_tokens")


def valid_endpoint(url):
    """Require a public HTTPS API URL without embedded credentials or queries."""
    if not safe_external_url(url):
        return False
    try:
        parts = urlsplit(url)
        return (parts.username is None and parts.password is None
                and not parts.query and not parts.fragment and parts.port in (None, 443)
                and parts.path.endswith("/chat/completions"))
    except ValueError:
        return False


class PublicHTTPSConnection(http.client.HTTPSConnection):
    """Pin the validated address while authenticating TLS against the hostname."""

    def connect(self):
        """Never connect if resolution contains any non-public address."""
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        resolved = [ipaddress.ip_address(row[4][0]) for row in addresses]
        if not resolved or any(not ip.is_global or ip.is_multicast for ip in resolved):
            raise OSError("Cloud endpoint did not resolve exclusively to public addresses")
        sock = socket.create_connection((addresses[0][4][0], self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except OSError:
            sock.close()
            raise


def complete_public(endpoint, model, api_key, prompt, token_limit_field="max_tokens"):
    """Send one capped request to the configured endpoint, without redirects."""
    if not valid_endpoint(endpoint):
        return {"status": "ERROR", "code": "cloud_invalid_endpoint"}
    if token_limit_field not in TOKEN_LIMIT_FIELDS:
        return {"status": "ERROR", "code": "cloud_invalid_profile"}
    target = urlsplit(endpoint)
    conn = PublicHTTPSConnection(target.hostname, timeout=45)
    try:
        # Do not log the credential, provider response body, or user payload.
        conn.request("POST", target.path, json.dumps({
            "model": model, "messages": [{"role": "user", "content": prompt}],
            "stream": False, token_limit_field: 1024,
        }), headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
        reply = conn.getresponse()
        if reply.status == 429:
            return {"status": "ERROR", "code": "cloud_rate_limit", "retryable": True}
        if reply.status != 200:
            return {"status": "ERROR", "code": "cloud_provider_failed"}
        raw = reply.read(262145)
        if len(raw) > 262144 or reply.length:
            return {"status": "ERROR", "code": "invalid_response"}
        data = json.loads(raw.decode("utf-8"))
        choice = data["choices"][0]
        if choice["finish_reason"] == "length":
            return {"status": "ERROR", "code": "truncated_response"}
        text = choice["message"]["content"]
        if (choice["finish_reason"] != "stop" or not isinstance(text, str) or not text.strip()
                or "\ufffd" in text or any(0xD800 <= ord(char) <= 0xDFFF for char in text)):
            return {"status": "ERROR", "code": "invalid_response"}
        return {"status": "SUCCESS", "text": text, "model": model, "tier": "cloud"}
    except TimeoutError:
        return {"status": "ERROR", "code": "cloud_timeout"}
    except (http.client.HTTPException, OSError, ValueError, KeyError, IndexError, TypeError):
        return {"status": "ERROR", "code": "cloud_provider_failed"}
    finally:
        conn.close()
