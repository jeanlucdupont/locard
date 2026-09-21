"""Direct HTTP to numeric loopback addresses; no DNS, proxies or redirects."""
import http.client
import ipaddress
import json
import socket
import threading
from urllib.parse import urlsplit


class LLMError(RuntimeError):
    pass


def endpoint_parts(endpoint):
    try:
        parts = urlsplit(endpoint)
        host = parts.hostname
        if host == "localhost":
            host = "127.0.0.1"
        if (parts.scheme != "http" or not host or not ipaddress.ip_address(host).is_loopback
                or parts.username or parts.password or parts.query or parts.fragment
                or parts.path.rstrip("/") not in ("", "/v1") or "%" in host):
            raise ValueError()
        return host, parts.port or 8080
    except ValueError as exc:
        raise ValueError("LLM endpoint must be an HTTP loopback URL, e.g. http://127.0.0.1:8080") from exc


class LocalClient:
    def __init__(self, endpoint="http://127.0.0.1:8080", timeout=120):
        self.host, self.port = endpoint_parts(endpoint)
        if not 0 < timeout <= 600:
            raise ValueError("Timeout must be 1..600 seconds")
        self.timeout = timeout

    def complete(self, messages, schema=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        self.last_metadata = {}
        transport = []
        def expire():
            # A peer sending bytes slowly must not extend the total call indefinitely.
            sock = getattr(connection, 'sock', None) or (transport[0] if transport else None)
            if sock is not None:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
            connection.close()
        watchdog = threading.Timer(self.timeout, expire)
        watchdog.daemon = True
        watchdog.start()
        body = json.dumps({"messages": messages, "temperature": 0.2, "top_p": 0.95,
                           "max_tokens": 1024, "stream": False,
                           "chat_template_kwargs": {"enable_thinking": False},
                           "response_format": ({"type": "json_schema", "json_schema": {
                               "name": "forensic_analysis", "strict": True, "schema": schema}}
                               if schema else {"type": "json_object"})}, ensure_ascii=True).encode()
        try:
            connection.request("POST", "/v1/chat/completions", body=body,
                               headers={"Content-Type": "application/json"})
            # HTTP/1.0 can detach the socket from HTTPConnection while the response
            # still owns a file object. Keep it reachable for the wall-clock limit.
            transport.append(getattr(connection, 'sock', None))
            response = connection.getresponse()
            if response.status != 200:
                raise LLMError(f"Local llama.cpp returned HTTP {response.status}; redirects are never followed. Check server/model/context settings")
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise LLMError("Local server response exceeds the size limit")
            decoded = json.loads(raw)
            choice = decoded["choices"][0]
            if choice.get("finish_reason") == "length":
                raise LLMError("Model answer exceeded its output budget; narrow the question")
            text = choice["message"]["content"]
            if not isinstance(text, str) or not text.strip():
                raise LLMError("Local model returned an empty answer")
            self.last_metadata = {'model': str(decoded.get('model', 'not reported'))[:200],
                                  'identity_basis': 'Local server self-report; weights not attested',
                                  'finish_reason': str(choice.get('finish_reason', 'not reported'))[:40]}
            usage = decoded.get('usage', {})
            if isinstance(usage, dict):
                self.last_metadata['usage'] = {k: v for k, v in usage.items()
                    if k in ('prompt_tokens', 'completion_tokens', 'total_tokens') and type(v) is int and 0 <= v <= 10000000}
            return text
        except (OSError, http.client.HTTPException) as exc:
            raise LLMError("Cannot reach local llama.cpp. Start llama-server and check the loopback endpoint. Deterministic searches remain available") from exc
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError("Local llama.cpp returned an invalid chat-completion response") from exc
        finally:
            watchdog.cancel()
            connection.close()
