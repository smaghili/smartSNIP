#!/usr/bin/env python3
import asyncio
import base64
import gc
import json
import logging
import os
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Deque, Any
from queue import Queue
from threading import Lock
from collections import deque
import ssl
import ipaddress
import socket

import aiohttp
from aiohttp import web

import dns
from dns import message, rdatatype, rdataclass
from dns.rrset import from_text

gc.set_threshold(700, 10, 5)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("iran_server")

DOH_TIMEOUT = 10.0
BACKEND_CONNECT_TIMEOUT = 25.0
BACKEND_RW_TIMEOUT = 60.0
IDLE_CONNECTION_TIMEOUT = 300.0
POOL_MAX_PER_HOST = 16
GLOBAL_BACKEND_CONNECTION_LIMIT = 2000
MAX_CONCURRENT_ACCEPTS = 2000
DOH_CONCURRENCY = 500


def now_ts() -> float:
    return time.time()


def matches_domain_key(domain: str, key: str) -> bool:
    domain_clean = domain.rstrip(".").lower()
    key_lower = key.lower()
    
    if domain_clean == key_lower:
        return True
    if domain_clean.endswith("." + key_lower):
        return True
    
    return False


def is_ip_address(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except Exception:
        return False


def resolve_route(target_host: str, matched_value: str, server_ip: str) -> Tuple[str, int]:
    if matched_value == "direct":
        return target_host, 443
    elif is_ip_address(matched_value):
        return "127.0.0.1", 60000
    elif ":" in matched_value:
        parts = matched_value.split(":")
        return parts[0], int(parts[1])
    else:
        return target_host, 443


def should_fake_sni(target_host: str, config_host: str, domains: Dict[str, str]) -> bool:
    if target_host == config_host:
        return False
    return any(matches_domain_key(target_host, key) for key in domains.keys())


def find_matching_domain(domain: str, domains: Dict[str, str]) -> Optional[str]:
    domain_clean = domain.rstrip(".").lower()
    for key, val in domains.items():
        if matches_domain_key(domain_clean, key):
            if ":" in val:
                return val.split(":")[0]
            return val
    return None


class Config:
    def __init__(self, host: str, server_ip: str, foreign_doh_url: str, domains: Dict[str, str]):
        self.host = host
        self.server_ip = server_ip
        self.foreign_doh_url = foreign_doh_url
        self._config_dir = os.getcwd()
        self.domains = self._expand_domains(domains)

    @staticmethod
    def load_config(filename: str = "iran_config.json") -> "Config":
        config_path = os.path.abspath(filename)
        config_dir = os.path.dirname(config_path)

        with open(config_path, "r") as f:
            data = json.load(f)

        cfg = Config(
            host=data["host"],
            server_ip=data["server_ip"],
            foreign_doh_url=data["foreign_doh_url"],
            domains=data.get("domains", {})
        )

        cfg._config_dir = config_dir
        cfg.domains = cfg._expand_domains(cfg.domains)

        return cfg

    def _expand_domains(self, domains: Dict[str, str]) -> Dict[str, str]:
        final_map = {}

        for key, value in domains.items():
            if key.endswith(".txt"):
                file_path = key

                if not os.path.isabs(file_path):
                    file_path = os.path.join(self._config_dir, file_path)

                if os.path.isfile(file_path):
                    try:
                        loaded_count = 0
                        with open(file_path, "r", encoding="utf-8") as f:
                            for line in f:
                                domain = line.strip()
                                if domain and not domain.startswith("#"):
                                    final_map[domain.lower()] = value
                                    loaded_count += 1
                        logger.info(f"Config: loaded {loaded_count} domains from {file_path}")
                    except Exception as e:
                        logger.error(f"Config: failed to load domains from {file_path}: {e}")
                else:
                    logger.warning(f"Config: domain file not found: {file_path}")

            else:
                final_map[key.lower()] = value

        return final_map


class BufferPool:
    def __init__(self, buffer_size: int = 8192, pool_size: int = 200):
        self.buffer_size = buffer_size
        self.pool: Queue = Queue(maxsize=pool_size)

    def get(self) -> bytearray:
        try:
            return self.pool.get_nowait()
        except Exception:
            return bytearray(self.buffer_size)

    def put(self, buffer: bytearray):
        if len(buffer) == self.buffer_size:
            buffer[:] = bytearray(self.buffer_size)
            try:
                self.pool.put_nowait(buffer)
            except Exception:
                pass


class RateLimiter:
    def __init__(self, requests_per_second: int, burst: int):
        self.requests_per_second = requests_per_second
        self.burst = burst
        self.tokens = float(burst)
        self.last = asyncio.get_event_loop().time()
        self.lock = Lock()

    def allow(self) -> bool:
        with self.lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self.last
            self.tokens = min(self.burst, self.tokens + elapsed * self.requests_per_second)
            self.last = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


class DNSHandler:
    def __init__(self, config: Config, buffer_pool: BufferPool, session: aiohttp.ClientSession, doh_semaphore: asyncio.Semaphore):
        self.config = config
        self.buffer_pool = buffer_pool
        self.session = session
        self.doh_semaphore = doh_semaphore

    async def process_dns_query(self, query_bytes: bytes) -> bytes:
        try:
            dns_message = message.from_wire(query_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse DNS message: {e}")

        if len(dns_message.question) == 0:
            raise ValueError("No DNS question found")

        question = dns_message.question[0]
        domain = question.name.to_text()
        qtype = question.rdtype
        mode = find_matching_domain(domain, self.config.domains)

        logger.info(f"DNSHandler: received query for domain={domain} qtype={qtype} mode={mode}")

        if mode:
            if is_ip_address(mode):
                fake_ip = self.config.server_ip
                try:
                    logger.info(f"DNSHandler: domain={domain} rewriting to server_ip={fake_ip} (anti-sanction, will route to {mode})")
                    response_message = message.make_response(dns_message)
                    response_message.flags |= 0x0080
                    rrset = from_text(
                        question.name,
                        300,
                        rdataclass.IN,
                        rdatatype.A,
                        fake_ip,
                    )
                    response_message.answer.append(rrset)
                    return response_message.to_wire()
                except Exception as e:
                    logger.exception(f"DNSHandler: failed to create rewrite response for {domain}: {e}")
            elif mode == "direct":
                logger.info(f"DNSHandler: domain={domain} mode=direct -> forwarding to foreign DoH {self.config.foreign_doh_url}")
        else:
            logger.info(f"DNSHandler: domain={domain} not in config (filtered) -> forwarding to foreign DoH {self.config.foreign_doh_url}")

        logger.info(f"DNSHandler: forwarding query for {domain} to foreign DoH {self.config.foreign_doh_url}")
        async with self.doh_semaphore:
            for attempt in range(3):
                try:
                    async with self.session.post(
                        self.config.foreign_doh_url,
                        data=query_bytes,
                        headers={"Content-Type": "application/dns-message", "Connection": "keep-alive"},
                        timeout=aiohttp.ClientTimeout(total=DOH_TIMEOUT),
                    ) as resp:
                        if resp.status != 200:
                            logger.error(f"DNSHandler: foreign DoH returned status {resp.status} for {domain}")
                            raise RuntimeError(f"Foreign DoH returned {resp.status}")
                        buffer = self.buffer_pool.get()
                        try:
                            chunk = await resp.content.read(len(buffer))
                            if len(chunk) < len(buffer):
                                logger.info(f"DNSHandler: successfully resolved {domain} from foreign DoH (short response)")
                                return chunk
                            result = bytearray(chunk)
                            while True:
                                chunk = await resp.content.read(len(buffer))
                                if not chunk:
                                    break
                                result.extend(chunk)
                            logger.info(f"DNSHandler: successfully resolved {domain} from foreign DoH (long response)")
                            return bytes(result)
                        finally:
                            self.buffer_pool.put(buffer)
                except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                    logger.warning("DNSHandler: DoH attempt %d failed for %s: %s", attempt + 1, domain, e)
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue
            logger.error(f"DNSHandler: all foreign DoH attempts failed for {domain}")
            raise RuntimeError("DNSHandler: foreign DoH failed after retries")


@dataclass
class BackendConn:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    last_used: float = field(default_factory=now_ts)
    in_use: bool = False

    def touch(self):
        self.last_used = now_ts()

    async def close(self):
        try:
            if self.writer and not self.writer.is_closing():
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass


class HostPool:
    def __init__(self, host: str, max_per_host: int = POOL_MAX_PER_HOST):
        self.host = host
        self.max_per_host = max_per_host
        self.idle: Deque[BackendConn] = deque()
        self.active_count = 0
        self.lock = asyncio.Lock()

    async def acquire(self) -> Optional[BackendConn]:
        async with self.lock:
            while self.idle:
                conn = self.idle.popleft()
                if conn.writer.is_closing():
                    continue
                conn.in_use = True
                conn.touch()
                return conn
            if self.active_count < self.max_per_host:
                self.active_count += 1
                return None
            return None

    async def release(self, conn: BackendConn):
        async with self.lock:
            conn.in_use = False
            conn.touch()
            if len(self.idle) < self.max_per_host:
                self.idle.append(conn)
            else:
                self.active_count -= 1
                await conn.close()

    async def evict_idle(self, idle_timeout: float):
        now = now_ts()
        async with self.lock:
            new_idle = deque()
            while self.idle:
                conn = self.idle.popleft()
                if conn.in_use:
                    new_idle.append(conn)
                    continue
                if now - conn.last_used > idle_timeout:
                    self.active_count = max(0, self.active_count - 1)
                    await conn.close()
                else:
                    new_idle.append(conn)
            self.idle = new_idle


class SNIProxy:
    def __init__(self, config: Config):
        self.config = config
        self.host_pools: Dict[str, HostPool] = {}
        self.global_semaphore = asyncio.Semaphore(GLOBAL_BACKEND_CONNECTION_LIMIT)
        self.accept_semaphore = asyncio.Semaphore(MAX_CONCURRENT_ACCEPTS)
        self.cleanup_task: Optional[asyncio.Task] = None
        self.watchdog_task: Optional[asyncio.Task] = None
        self.running = False

    def _get_host_pool(self, host: str) -> HostPool:
        if host not in self.host_pools:
            self.host_pools[host] = HostPool(host)
        return self.host_pools[host]

    def _read_client_hello(self, data: bytes) -> Optional[str]:
        try:
            if len(data) < 43:
                return None
            if data[0] != 0x16:
                return None
            pos = 43
            if pos + 1 > len(data):
                return None
            session_id_length = data[pos]
            pos += 1 + session_id_length
            if pos + 2 > len(data):
                return None
            cipher_suites_length = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2 + cipher_suites_length
            if pos + 1 > len(data):
                return None
            compression_methods_length = data[pos]
            pos += 1 + compression_methods_length
            if pos + 2 > len(data):
                return None
            extensions_length = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            extensions_end = pos + extensions_length
            while pos + 4 <= extensions_end:
                extension_type = struct.unpack("!H", data[pos:pos+2])[0]
                extension_length = struct.unpack("!H", data[pos+2:pos+4])[0]
                pos += 4
                if extension_type == 0:
                    if pos + 2 > len(data):
                        return None
                    server_name_list_length = struct.unpack("!H", data[pos:pos+2])[0]
                    pos += 2
                    if pos + server_name_list_length > len(data):
                        return None
                    if pos + 3 <= len(data):
                        name_type = data[pos]
                        name_length = struct.unpack("!H", data[pos+1:pos+3])[0]
                        pos += 3
                        if name_type == 0 and pos + name_length <= len(data):
                            server_name = data[pos:pos+name_length].decode("utf-8", errors="ignore")
                            return server_name
                    return None
                pos += extension_length
            return None
        except Exception:
            return None

    def _force_replace_sni_in_client_hello(self, data: bytes, fake_sni: str, original_sni: str) -> bytes:
        """
        Rebuild ClientHello with fake SNI for DPI bypass.
        Adds custom extension (type 65001) containing original SNI.
        """
        try:
            if len(data) < 43 or data[0] != 0x16:
                return data

            content_type = data[0]
            version = data[1:3]
            record_length = struct.unpack("!H", data[3:5])[0]

            handshake_type = data[5]
            handshake_len = int.from_bytes(data[6:9], "big")

            pos = 9

            client_version = data[pos:pos+2]
            pos += 2

            random_bytes = data[pos:pos+32]
            pos += 32

            session_id_len = data[pos]
            pos += 1
            session_id = data[pos:pos+session_id_len]
            pos += session_id_len

            cipher_len = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            cipher_suites = data[pos:pos+cipher_len]
            pos += cipher_len

            comp_len = data[pos]
            pos += 1
            compression = data[pos:pos+comp_len]
            pos += comp_len

            ext_total_len = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            ext_end = pos + ext_total_len

            new_ext = bytearray()
            fake_sni_bytes = fake_sni.encode()
            orig_bytes = original_sni.encode()

            while pos < ext_end:
                ext_type = struct.unpack("!H", data[pos:pos+2])[0]
                ext_len = struct.unpack("!H", data[pos+2:pos+4])[0]

                if ext_type == 0:
                    sni = bytearray()
                    sni.extend(struct.pack("!H", 0))
                    server_name_list = 3 + len(fake_sni_bytes)
                    sni.extend(struct.pack("!H", server_name_list + 2))
                    sni.extend(struct.pack("!H", server_name_list))
                    sni.append(0)
                    sni.extend(struct.pack("!H", len(fake_sni_bytes)))
                    sni.extend(fake_sni_bytes)

                    new_ext.extend(sni)
                else:
                    new_ext.extend(data[pos:pos+4+ext_len])

                pos += 4 + ext_len

            custom = bytearray()
            custom.extend(struct.pack("!H", 65001))
            custom.extend(struct.pack("!H", len(orig_bytes)))
            custom.extend(orig_bytes)
            new_ext.extend(custom)

            body = bytearray()
            body.extend(client_version)
            body.extend(random_bytes)
            body.append(session_id_len)
            body.extend(session_id)
            body.extend(struct.pack("!H", cipher_len))
            body.extend(cipher_suites)
            body.append(comp_len)
            body.extend(compression)
            body.extend(struct.pack("!H", len(new_ext)))
            body.extend(new_ext)

            new_hs = bytearray()
            new_hs.append(handshake_type)
            new_hs.extend(len(body).to_bytes(3, "big"))
            new_hs.extend(body)

            out = bytearray()
            out.append(content_type)
            out.extend(version)
            out.extend(struct.pack("!H", len(new_hs)))
            out.extend(new_hs)

            return bytes(out)

        except Exception:
            return data

    async def _peek_client_hello(self, reader: asyncio.StreamReader) -> Tuple[Optional[str], bytes]:
        try:
            peeked = bytearray()
            first = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            if not first:
                return None, b""
            peeked.extend(first)
            if first[0] == 0x16:
                header = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
                peeked.extend(header)
                record_length = struct.unpack("!H", header[2:4])[0]
                body = await asyncio.wait_for(reader.readexactly(record_length), timeout=5.0)
                peeked.extend(body)
                sni = self._read_client_hello(bytes(peeked))
                return sni, bytes(peeked)
            return None, bytes(peeked)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            logger.debug("SNIProxy: timeout or incomplete read: %s", e)
            return None, b""
        except ConnectionResetError as e:
            logger.debug("SNIProxy: connection reset while reading client hello (client cancelled): %s", e)
            return None, b""
        except Exception as e:
            logger.error("SNIProxy: error reading client hello: %s", e)
            return None, b""

    async def _create_backend_connection(self, target_address: str, target_port: int) -> BackendConn:
        await self.global_semaphore.acquire()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_address, target_port),
                timeout=BACKEND_CONNECT_TIMEOUT,
            )
            sock = writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return BackendConn(reader=reader, writer=writer, last_used=now_ts(), in_use=True)
        except Exception:
            self.global_semaphore.release()
            raise

    async def _safe_close_backend(self, conn: BackendConn):
        try:
            await conn.close()
        finally:
            try:
                self.global_semaphore.release()
            except Exception:
                pass

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            if not await self.accept_semaphore.acquire():
                writer.close()
                await writer.wait_closed()
                return
        except Exception:
            writer.close()
            await writer.wait_closed()
            return

        try:
            server_name, peeked_bytes = await self._peek_client_hello(reader)
            if not server_name or server_name.strip() == "":
                logger.debug("SNIProxy: empty or missing SNI, closing (likely client cancelled)")
                return

            original_server_name = server_name
            target_host = original_server_name.lower().rstrip(".")
            
            if should_fake_sni(target_host, self.config.host, self.config.domains):
                FAKE_SNI = "google.com"
                peeked_bytes = self._force_replace_sni_in_client_hello(peeked_bytes, FAKE_SNI, original_server_name)
                logger.info("SNIProxy: forced SNI replacement: %s -> %s (original stored in extension 65001)", original_server_name, FAKE_SNI)
            else:
                logger.debug("SNIProxy: keeping original SNI: %s", original_server_name)
            
            if target_host == self.config.host:
                target_address = "127.0.0.1"
                target_port = 8443
                logger.debug("SNIProxy: routing internal host %s -> 127.0.0.1:8443", target_host)
            else:
                matched_domain = find_matching_domain(target_host, self.config.domains)
                
                if matched_domain:
                    target_address, target_port = resolve_route(target_host, matched_domain, self.config.server_ip)
                    logger.info("SNIProxy: host=%s, matched_domain=%s, routing to %s:%d", target_host, matched_domain, target_address, target_port)
                else:
                    target_address = target_host
                    target_port = 443
                    logger.info("SNIProxy: host=%s, routing directly to %s:%d", target_host, target_address, target_port)

            host_pool = self._get_host_pool(target_host)

            conn = await host_pool.acquire()
            created_new = False
            if conn is None:
                try:
                    conn = await self._create_backend_connection(target_address, target_port)
                    created_new = True
                except Exception as e:
                    logger.error("SNIProxy: backend connect failed for %s to %s:%d - %s", target_host, target_address, target_port, e)
                    return

            try:
                conn.writer.write(peeked_bytes)
                await conn.writer.drain()
            except Exception as e:
                logger.warning("SNIProxy: failed to write peeked bytes to backend %s: %s (retrying once...)", target_host, e)
                try:
                    await self._safe_close_backend(conn)
                    await asyncio.sleep(0.3)
                    conn = await self._create_backend_connection(target_address, target_port)
                    conn.writer.write(peeked_bytes)
                    await conn.writer.drain()
                except Exception as e2:
                    logger.error("SNIProxy: retry also failed for %s: %s", target_host, e2)
                    await self._safe_close_backend(conn)
                    return

            conn.touch()
            conn.in_use = True

            async def forward(src_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter, name: str):
                try:
                    while True:
                        try:
                            data = await asyncio.wait_for(src_reader.read(8192), timeout=BACKEND_RW_TIMEOUT)
                        except asyncio.TimeoutError:
                            break
                        if not data:
                            break
                        dst_writer.write(data)
                        try:
                            await asyncio.wait_for(dst_writer.drain(), timeout=BACKEND_RW_TIMEOUT)
                        except asyncio.TimeoutError:
                            break
                except Exception:
                    pass
                finally:
                    dst_writer.close()
                    await dst_writer.wait_closed()

            logger.info("SNIProxy: successfully connected %s to %s:%d", target_host, target_address, target_port)
            try:
                await asyncio.gather(
                    forward(reader, conn.writer, "client->backend"),
                    forward(conn.reader, writer, "backend->client"),
                    return_exceptions=True,
                )
            finally:
                logger.debug("SNIProxy: connection closed for %s", target_host)
                conn.in_use = False
                conn.touch()
                if created_new:
                    await host_pool.release(conn)
                else:
                    await host_pool.release(conn)
        except Exception as e:
            logger.exception("SNIProxy: error handling connection: %s", e)
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass
            try:
                self.accept_semaphore.release()
            except Exception:
                pass
            try:
                self.global_semaphore.release()
            except Exception:
                pass

    async def _cleanup_loop(self):
        try:
            while self.running:
                await asyncio.sleep(30)
                for host, pool in list(self.host_pools.items()):
                    try:
                        await pool.evict_idle(IDLE_CONNECTION_TIMEOUT)
                    except Exception:
                        logger.debug("SNIProxy: pool eviction error for %s", host)
        except asyncio.CancelledError:
            pass

    async def run(self, port: int = 443):
        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.watchdog_task = asyncio.create_task(self.watchdog())
        server = await asyncio.start_server(self.handle_connection, "0.0.0.0", port, limit=2**16)
        logger.info("SNI Proxy started on port %d", port)
        async with server:
            await server.serve_forever()

    async def shutdown(self):
        self.running = False
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except Exception:
                pass
        if self.watchdog_task:
            self.watchdog_task.cancel()
            try:
                await self.watchdog_task
            except Exception:
                pass
        for host, pool in list(self.host_pools.items()):
            async with pool.lock:
                while pool.idle:
                    conn = pool.idle.popleft()
                    await conn.close()

    async def watchdog(self):
        while self.running:
            await asyncio.sleep(120)
            try:
                locked = getattr(self.global_semaphore, "_value", 1)
            except Exception:
                locked = 1
            if locked <= 0:
                logger.warning("Watchdog: global semaphore exhausted, resetting pools")
                for host, pool in list(self.host_pools.items()):
                    async with pool.lock:
                        while pool.idle:
                            conn = pool.idle.popleft()
                            await conn.close()
                self.global_semaphore = asyncio.Semaphore(GLOBAL_BACKEND_CONNECTION_LIMIT)
                logger.info("Watchdog: semaphore reset complete")


class DOHServer:
    def __init__(self, dns_handler: DNSHandler, rate_limiter: RateLimiter):
        self.dns_handler = dns_handler
        self.rate_limiter = rate_limiter
        self.app: Optional[web.Application] = None

    async def handle_doh_request(self, request: web.Request) -> web.Response:
        try:
            if not self.rate_limiter.allow():
                return web.Response(text="Rate limit exceeded", status=429)

            if request.method == "GET":
                dns_param = request.query.get("dns")
                if not dns_param:
                    return web.Response(text="Missing 'dns' parameter", status=400)
                try:
                    padding = 4 - (len(dns_param) % 4)
                    if padding != 4:
                        dns_param += "=" * padding
                    query_bytes = base64.urlsafe_b64decode(dns_param)
                except Exception:
                    return web.Response(text="Invalid 'dns' parameter", status=400)
            elif request.method == "POST":
                query_bytes = await request.read()
                if len(query_bytes) == 0:
                    return web.Response(text="Empty request body", status=400)
            else:
                return web.Response(text="Only GET and POST allowed", status=405)

            try:
                resp = await self.dns_handler.process_dns_query(query_bytes)
            except Exception as e:
                logger.exception("DOHServer: DNS processing error: %s", e)
                return web.Response(text=f"Failed to process DNS query: {e}", status=500)

            return web.Response(body=resp, content_type="application/dns-message", status=200)

        except Exception as e:
            logger.debug(f"DOHServer: unexpected input: {e}")
            return web.Response(status=400, text="Bad Request")

    async def create_app(self) -> web.Application:
        self.app = web.Application()
        self.app.router.add_route("*", "/{path:.*}", self.handle_path)
        return self.app

    async def handle_path(self, request: web.Request) -> web.Response:
        if request.path == "/dns-query":
            return await self.handle_doh_request(request)
        return web.Response(text="Unsupported path", status=404)

    async def run(self, host: str = "0.0.0.0", port: int = 8080):
        app = await self.create_app()
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        logger.info("DoH server started on %s:%d", host, port)

    async def shutdown(self):
        if self.app:
            await self.app.shutdown()
            await self.app.cleanup()


class DOTServer:
    def __init__(self, dns_handler: DNSHandler, rate_limiter: RateLimiter, config: Config):
        self.dns_handler = dns_handler
        self.rate_limiter = rate_limiter
        self.config = config

    async def handle_dot_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            if not self.rate_limiter.allow():
                logger.warning("DoT rate limit exceeded")
                return

            length_bytes = await reader.readexactly(2)
            dns_message_length = struct.unpack("!H", length_bytes)[0]
            query_bytes = await reader.readexactly(dns_message_length)

            response = await self.dns_handler.process_dns_query(query_bytes)

            response_length = struct.pack("!H", len(response))
            writer.write(response_length)
            writer.write(response)
            await writer.drain()
        except Exception as e:
            logger.error(f"DoT connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def run(self, port: int = 853):
        cert_path = f"/etc/letsencrypt/live/{self.config.host}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{self.config.host}/privkey.pem"

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, key_path)

        server = await asyncio.start_server(
            self.handle_dot_connection,
            "0.0.0.0",
            port,
            ssl=ssl_context,
        )
        logger.info(f"DoT server started on port {port}")

        async with server:
            await server.serve_forever()


async def main():
    config = Config.load_config("iran_config.json")
    buffer_pool = BufferPool()

    logger.info("=" * 60)
    logger.info("Iran Server Configuration:")
    logger.info(f"  Host: {config.host}")
    logger.info(f"  Server IP: {config.server_ip}")
    logger.info(f"  Foreign DoH URL: {config.foreign_doh_url}")
    logger.info(f"  Domains configured: {len(config.domains)}")
    for domain, mode in config.domains.items():
        logger.info(f"    {domain}: {mode}")
    logger.info("=" * 60)

    conn = aiohttp.TCPConnector(limit=DOH_CONCURRENCY, force_close=False, ssl=False)
    session = aiohttp.ClientSession(connector=conn)

    doh_semaphore = asyncio.Semaphore(DOH_CONCURRENCY)
    rate_limiter = RateLimiter(requests_per_second=200, burst=500)
    dns_handler = DNSHandler(config, buffer_pool, session, doh_semaphore)
    doh_server = DOHServer(dns_handler, rate_limiter)
    dot_server = DOTServer(dns_handler, rate_limiter, config)
    sni_proxy = SNIProxy(config)

    logger.info("Starting Iran Server: DoH, DoT and SNI services")
    try:
        await asyncio.gather(
            doh_server.run(host="0.0.0.0", port=8080),
            dot_server.run(port=853),
            sni_proxy.run(port=443),
        )
    finally:
        logger.info("Shutting down Iran Server")
        await doh_server.shutdown()
        await sni_proxy.shutdown()
        await session.close()
        await conn.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Iran Server stopped by user")