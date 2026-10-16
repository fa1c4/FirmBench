#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import requests
import logging
import time
import os
import datetime
from urllib.parse import urljoin
import argparse
from typing import List, Dict, Any, Tuple


class APIFuzzer:
    def __init__(self, base_url: str, json_file: str, delay: float = 1.0, target_host: str = "", taint_tag: str = "taint_tag", tag_mode: str = "constant"):
        """
        Initialize API Fuzzer.
        :param base_url: Base API URL (e.g., http://192.168.0.1)
        :param json_file: Path to the JSON file containing API definitions
        :param delay: Delay between requests (seconds)
        :param tag_mode: 'constant' (default) or 'unique' — unique injects {tag}_{seq} per request
        """
        self.base_url = base_url.rstrip('/')
        self.json_file = json_file
        self.delay = delay
        self.target_host = target_host
        self.taint_tag = taint_tag
        self.tag_mode = tag_mode
        self.session = requests.Session()
        self._request_counter = 0
        # Payload encoding for POST/PUT: "json" (default) or "form"
        # (application/x-www-form-urlencoded, required by most firmware CGI
        # handlers, e.g. Tenda/Realtek boa).
        self.content_type = "json"

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('fuzzing_results.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _resolve_result_path(self) -> str:
        """Resolve result output path; prefer JSON sibling dir, fallback to cwd."""
        input_dir = os.path.dirname(os.path.abspath(self.json_file))
        preferred = os.path.join(input_dir, "result.json")

        try:
            os.makedirs(input_dir, exist_ok=True)
            with open(preferred, 'w', encoding='utf-8') as f:
                json.dump([], f)
            return preferred
        except Exception as e:
            self.logger.warning(f"Cannot write result.json next to input JSON: {e}")

        fallback = os.path.join(os.getcwd(), "result.json")
        with open(fallback, 'w', encoding='utf-8') as f:
            json.dump([], f)
        self.logger.warning(f"Fallback result path: {fallback}")
        return fallback

    def _flush_results(self, result_path: str, results: List[Dict[str, Any]]) -> None:
        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    def _resolve_stream_path(self) -> str:
        """Resolve ndjson stream path next to result.json."""
        input_dir = os.path.dirname(os.path.abspath(self.json_file))
        return os.path.join(input_dir, "result_stream.ndjson")

    def _append_stream_entry(self, entry: Dict[str, Any]) -> None:
        """Append a single result entry to the ndjson stream (immediate flush)."""
        stream_path = getattr(self, '_stream_path', None)
        if stream_path is None:
            stream_path = self._resolve_stream_path()
            self._stream_path = stream_path
        with open(stream_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    def load_targets(self) -> Tuple[List[str], List[str]]:
        """Load target APIs and parameters from JSON file.

        Preferred format:
        {
          "api_endpoints": [...],
          "para": [...]
        }
        """
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            api_endpoints: List[str] = []
            parameters: List[str] = []

            if isinstance(data, dict):
                raw_apis = data.get("api_endpoints", [])
                raw_para = data.get("para", [])
                if isinstance(raw_apis, list):
                    api_endpoints = [str(item).strip() for item in raw_apis if str(item).strip()]
                if isinstance(raw_para, list):
                    parameters = [str(item).strip() for item in raw_para if str(item).strip()]

            if not api_endpoints and isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("api_url"):
                        api_endpoints.append(str(item["api_url"]).strip())

            if not api_endpoints:
                self.logger.error("No api_endpoints found in input JSON")
                return [], []

            # ȥ�ز�����˳��
            dedup_apis = list(dict.fromkeys(api_endpoints))
            dedup_para = list(dict.fromkeys(parameters))
            return dedup_apis, dedup_para
        except Exception as e:
            self.logger.error(f"Failed to load JSON file: {e}")
            return [], []

    def build_taint_payload(self, parameters: List[str], taint_param: str, request_id: int = 0) -> Dict[str, str]:
        """Build payload with all parameters present; only one parameter is tainted per request."""
        payload = {param: "" for param in parameters}
        if taint_param in payload:
            if self.tag_mode == "unique":
                payload[taint_param] = f"{self.taint_tag}_{request_id}"
            else:
                payload[taint_param] = self.taint_tag
        fixed = getattr(self, "fixed_params", None)
        if fixed:
            payload.update({k: str(v) for k, v in fixed.items()})
        return payload

    def send_request(self, api_url: str, payload: Dict[str, str], method: str = "POST") -> Dict[str, Any]:
        """Send HTTP request with one API + all parameters filled by taint_tag."""
        fixed = getattr(self, "fixed_params", None)
        if fixed:
            payload = dict(payload)
            for _k, _v in fixed.items():
                payload[str(_k)] = str(_v)
        trailing = getattr(self, "trailing_taint", None)
        if trailing:
            payload = dict(payload)
            payload[str(trailing)] = str(self.taint_tag)
        url = urljoin(self.base_url + '/', api_url.lstrip('/'))
        method_upper = method.upper()
        # Supplementary authentication information
        headers = {
            "Host": self.target_host if self.target_host else self.base_url.replace("http://", "").replace("https://", ""),
            "Cache-Control": "max-age=0",
            "Accept-Language": "zh-CN",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": getattr(self, "user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Connection": "close" if getattr(self, "connection_close", False) else "keep-alive"
        }

        try:
            if method_upper == 'GET':
                response = self.session.get(url, params=payload, headers=headers, timeout=(getattr(self, "t_connect", 4), getattr(self, "t_read", 2)), verify=False, stream=True)
            elif getattr(self, "raw_space", False):
                import socket as _socket
                from urllib.parse import urlsplit, urlencode
                parts = urlsplit(url)
                raw_target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
                raw_target = raw_target.replace("%20", " ")
                body = urlencode(payload).encode()
                lines = ["%s %s HTTP/1.0" % (method_upper, raw_target)]
                for k, v in headers.items():
                    if k.lower() in ("content-length", "connection"):
                        continue
                    lines.append("%s: %s" % (k, v))
                auth = self.session.auth
                if auth:
                    import base64
                    token = base64.b64encode(("%s:%s" % auth).encode()).decode()
                    lines.append("Authorization: Basic " + token)
                lines.append("Content-Length: %d" % len(body))
                lines.append("Connection: close")
                raw_req = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
                sock = _socket.create_connection((parts.hostname, parts.port or 80), timeout=15)
                sock.sendall(raw_req)
                sock.shutdown(_socket.SHUT_WR)
                chunks = []
                try:
                    while True:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                except Exception:
                    pass
                sock.close()
                raw_resp = b"".join(chunks)
                head, _, content = raw_resp.partition(b"\r\n\r\n")
                try:
                    status_code = int(head.split(b" ")[1])
                except Exception:
                    status_code = None
                return {
                    'url': url,
                    'method': method_upper,
                    'status_code': status_code,
                    'response_time': 0.0,
                    'content_length': len(content),
                    'headers': {},
                    'content': content.decode('utf-8', errors='ignore')[:1000]
                }
            else:
                if self.content_type == "form":
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    response = self.session.request(method_upper, url, data=payload, headers=headers, timeout=(getattr(self, "t_connect", 4), getattr(self, "t_read", 2)), verify=False, stream=True)
                elif self.content_type == "multipart":
                    headers.pop("Content-Type", None)
                    files = {k: (None, str(v)) for k, v in payload.items()}
                    response = self.session.request(method_upper, url, files=files, headers=headers, timeout=(getattr(self, "t_connect", 4), getattr(self, "t_read", 2)), verify=False, stream=True)
                else:
                    response = self.session.request(method_upper, url, json=payload, headers=headers, timeout=(getattr(self, "t_connect", 4), getattr(self, "t_read", 2)), verify=False, stream=True)

            # Some firmware handlers send the body but never close the socket
            # (boa without Content-Length). Read what is available within the
            # read timeout instead of failing the whole request.
            status_code = response.status_code
            headers_out = dict(response.headers)
            elapsed = response.elapsed.total_seconds()
            try:
                content = response.content
            except requests.exceptions.RequestException:
                content = b""

            return {
                'url': url,
                'method': method_upper,
                'status_code': status_code,
                'response_time': elapsed,
                'content_length': len(content),
                'headers': headers_out,
                'content': content.decode('utf-8', errors='ignore')[:1000]
            }

        except requests.exceptions.RequestException as e:
            return {
                'error': str(e),
                'status_code': None,
                'response_time': None
            }

    def analyze_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze response for basic anomaly signals."""
        analysis = {
            'potential_issue': False,
            'issue_type': None,
            'evidence': []
        }

        if 'error' in response_data:
            analysis['evidence'].append(f"Request error: {response_data['error']}")
            analysis['potential_issue'] = True
            analysis['issue_type'] = 'RequestError'
            return analysis

        status_code = response_data.get('status_code')
        response_time = response_data.get('response_time', 0)

        if status_code in [500, 502, 503]:
            analysis['potential_issue'] = True
            analysis['issue_type'] = 'ServerError'
            analysis['evidence'].append(f'Status code: {status_code}')

        if response_time and response_time > 3:
            analysis['potential_issue'] = True
            if not analysis['issue_type']:
                analysis['issue_type'] = 'SlowResponse'
            analysis['evidence'].append(f'Long response time: {response_time}s')

        return analysis

    def fuzz_api(self, api_url: str, parameters: List[str], method: str) -> List[Dict[str, Any]]:
        """For one API, iterate all parameters and taint one parameter per request."""
        self.logger.info(f"Testing API: {api_url}")
        results: List[Dict[str, Any]] = []

        if not parameters:
            self._request_counter += 1
            rid = self._request_counter
            sent_at = datetime.datetime.utcnow().isoformat() + "Z"
            payload = {}
            response_data = self.send_request(api_url, payload, method)
            received_at = datetime.datetime.utcnow().isoformat() + "Z"
            analysis = self.analyze_response(response_data)
            result = {
                'request_id': rid,
                'sent_at': sent_at,
                'received_at': received_at,
                'api_url': api_url,
                'method': method.upper(),
                'taint_param': None,
                'taint_tag': self.taint_tag,
                'post_payload': payload,
                'response': response_data,
                'analysis': analysis
            }
            results.append(result)
            self._append_stream_entry(result)
            time.sleep(self.delay)
            return results

        for param in parameters:
            self._request_counter += 1
            rid = self._request_counter
            sent_at = datetime.datetime.utcnow().isoformat() + "Z"
            payload = self.build_taint_payload(parameters, param, rid)
            response_data = self.send_request(api_url, payload, method)
            received_at = datetime.datetime.utcnow().isoformat() + "Z"
            analysis = self.analyze_response(response_data)

            result = {
                'request_id': rid,
                'sent_at': sent_at,
                'received_at': received_at,
                'api_url': api_url,
                'method': method.upper(),
                'taint_param': param,
                'taint_tag': payload.get(param, self.taint_tag),
                'post_payload': payload,
                'response': response_data,
                'analysis': analysis
            }
            results.append(result)
            self._append_stream_entry(result)

            if analysis['potential_issue']:
                self.logger.warning(f"[!] Potential issue on {api_url} param {param}: {analysis['issue_type']}")
                self.logger.warning(f"Evidence: {analysis['evidence']}")

            time.sleep(self.delay)

        return results

    def run_fuzzing(self) -> None:
        """Run taint-tag requests on all APIs.

        Logic:
        - pick one URL
        - iterate all parameters, taint one parameter per request
        - then move to next URL
        """
        result_path = self._resolve_result_path()
        self.logger.info(f"Result file will be written to: {result_path}")

        # Initialize stream file (truncate if exists)
        stream_path = self._resolve_stream_path()
        self._stream_path = stream_path
        with open(stream_path, 'w', encoding='utf-8') as f:
            pass  # truncate
        self.logger.info(f"Stream file will be written to: {stream_path}")

        api_endpoints, parameters = self.load_targets()
        all_results: List[Dict[str, Any]] = []

        if not api_endpoints:
            self.logger.error("No API endpoints found")
            self._flush_results(result_path, all_results)
            return

        if not parameters:
            self.logger.warning("No parameters found, requests will carry empty JSON payload")

        for i, api_url in enumerate(api_endpoints, 1):
            self.logger.info(f"Progress: {i}/{len(api_endpoints)}")
            try:
                per_api_results = self.fuzz_api(api_url, parameters, self.method)
                all_results.extend(per_api_results)
                self._flush_results(result_path, all_results)
            except Exception as e:
                self.logger.error(f"Error fuzzing {api_url}: {e}")
                self._flush_results(result_path, all_results)

        self._flush_results(result_path, all_results)
        self.logger.info(f"Saved request packets to: {result_path}")

        self.logger.info("Fuzzing completed!")

    @property
    def method(self) -> str:
        return getattr(self, "_method", "POST")

    @method.setter
    def method(self, value: str) -> None:
        self._method = (value or "POST").upper()


def main():
    parser = argparse.ArgumentParser(description="API Fuzzer Tool")
    parser.add_argument("--json-file", required=True, help="Path to the JSON file containing API definitions")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--host", required=True, help="Host header value (IP or domain)")
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT"], help="HTTP method used for all API requests")
    parser.add_argument("--taint-tag", default="taint_tag", help="Tag string injected to every parameter")
    parser.add_argument("--tag-mode", default="constant", choices=["constant", "unique"],
                        help="'constant' (default): same tag for all requests; 'unique': {tag}_{seq} per request")
    # Feedback-guided greybox options (plan section 6.2). Full feedback is only
    # enabled when BOTH --distance-file and --qemu-log are present; otherwise the
    # legacy basic per-API/per-parameter traversal runs unchanged (section 11).
    parser.add_argument("--distance-file", default=None,
                        help="Path to sink_distance_scores.json (metadata object or legacy array)")
    parser.add_argument("--qemu-log", default=None,
                        help="Path to the QEMU basic-block exec log (host-side shared log)")
    parser.add_argument("--idle-pause-container", default=None,
                        help="Pause this Docker container between guided-fuzz requests")
    parser.add_argument("--trace-windows-out", default=None,
                        help="Write exact QEMU byte windows directly from the guided fuzzer")
    parser.add_argument("--feedback-settle", type=float, default=0.3,
                        help="Seconds to wait after a response before slicing the trace window (default: 0.3)")
    parser.add_argument("--iterations", type=int, default=1000,
                        help="Max guided-fuzzing iterations (default: 1000)")
    parser.add_argument("--random-seed", type=int, default=None,
                        help="Seed for reproducible seed selection (default: None)")
    parser.add_argument("--dictionary-file", default=None,
                        help="AFL-style dictionary file (name=\"value\" or \"value\") for value mutation")
    parser.add_argument("--content-type", default="json", choices=["json", "form", "multipart"],
                        help="POST body encoding: json (default), form (urlencoded) or multipart (firmware upload forms)")
    parser.add_argument("--basic-auth", default=None,
                        help="user:pass for HTTP Basic authentication on every request")
    parser.add_argument("--cookie", default=None,
                        help="Cookie header value sent with every request")
    parser.add_argument("--raw-space", action="store_true",
                        help="send request targets verbatim (spaces not percent-encoded)")
    parser.add_argument("--timeout-connect", type=float, default=4.0)
    parser.add_argument("--timeout-read", type=float, default=2.0)
    parser.add_argument("--connection-close", action="store_true",
                        help="send Connection: close on every request")
    parser.add_argument("--user-agent", default=None,
                        help="override the User-Agent header")
    parser.add_argument("--fixed-params", default=None,
                        help="JSON object of parameters forced to fixed values in every request")
    parser.add_argument("--host-header", default=None,
                        help="override the Host header value (connection still uses --host)")
    parser.add_argument("--trailing-taint", default=None,
                        help="append a trailing parameter with this name carrying the taint tag")
    args = parser.parse_args()

    if args.host.startswith("http://") or args.host.startswith("https://"):
        base_url = args.host
        host_header = args.host.replace("http://", "").replace("https://", "")
    else:
        base_url = f"http://{args.host}"
        host_header = args.host

    fuzzer = APIFuzzer(base_url, args.json_file, args.delay, host_header, args.taint_tag, args.tag_mode)
    fuzzer.method = args.method
    fuzzer.content_type = args.content_type
    if args.basic_auth and ":" in args.basic_auth:
        auth_user, auth_pass = args.basic_auth.split(":", 1)
        fuzzer.session.auth = (auth_user, auth_pass)
    if args.cookie:
        fuzzer.session.headers.update({"Cookie": args.cookie})
    if args.raw_space:
        fuzzer.raw_space = True
    fuzzer.t_connect = args.timeout_connect
    fuzzer.t_read = args.timeout_read
    if args.connection_close:
        fuzzer.connection_close = True
    if args.user_agent:
        fuzzer.user_agent = args.user_agent
    if args.fixed_params:
        import json as _json
        try:
            fuzzer.fixed_params = _json.loads(args.fixed_params)
        except Exception as exc:
            fuzzer.logger.warning("bad --fixed-params: %s" % exc)
    if args.host_header:
        fuzzer.target_host = args.host_header
    if args.trailing_taint:
        fuzzer.trailing_taint = args.trailing_taint

    guided = args.distance_file is not None and args.qemu_log is not None
    if (args.idle_pause_container or args.trace_windows_out) and not guided:
        parser.error("--idle-pause-container and --trace-windows-out require --distance-file and --qemu-log")
    if guided:
        from feedback_fuzzing import (  # same-directory module (section 9)
            DistanceIndex,
            GuidedFuzzer,
            IdlePauseController,
            MutationDictionary,
            TraceWindowReader,
        )

        distance_index = DistanceIndex(args.distance_file)
        trace_reader = TraceWindowReader(args.qemu_log, settle=args.feedback_settle)
        try:
            with open(args.json_file, "r", encoding="utf-8") as f:
                json_data = json.load(f)
        except Exception:
            json_data = {}
        dictionary = MutationDictionary.from_json(json_data, args.dictionary_file)
        idle_controller = (IdlePauseController(args.idle_pause_container)
                           if args.idle_pause_container else None)
        guided_fuzzer = GuidedFuzzer(
            fuzzer,
            distance_index,
            trace_reader,
            iteration_limit=max(args.iterations, 1),
            random_seed=args.random_seed,
            dictionary=dictionary,
            tag_mode=args.tag_mode,
            delay=args.delay,
            method=args.method,
            idle_controller=idle_controller,
            trace_windows_out=args.trace_windows_out,
        )
        fuzzer.logger.info(
            "Enabled feedback-guided greybox mode: distance file + QEMU log present"
        )
        try:
            guided_fuzzer.run_fuzzing()
        finally:
            if idle_controller:
                idle_controller.release()
    else:
        # Legacy behavior: basic per-API taint traversal with no trace feedback.
        fuzzer.logger.info("Running legacy basic traversal (no distance/trace feedback)")
        fuzzer.run_fuzzing()


if __name__ == '__main__':
    main()
