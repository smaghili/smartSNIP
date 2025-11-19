#!/usr/bin/env python3
import asyncio
import base64
import gc
import json
import logging
import time
import struct
import socket
from queue import Queue
from threading import Lock
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Deque

import aiohttp
from aiohttp import web

import dns
from dns import message

gc.set_threshold(700, 10, 5)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("foreign_server")

PROXY_URL = "socks5://127.0.0.1:50000"
DOH_TIMEOUT = 10.0
DOH_CONCURRENCY = 500
DEFAULT_UPSTREAM = "https://1.1.1.1/dns-query"
BACKEND_CONNECT_TIMEOUT = 25.0
BACKEND_RW_TIMEOUT = 60.0
IDLE_CONNECTION_TIMEOUT = 300.0
POOL_MAX_PER_HOST = 16
GLOBAL_BACKEND_CONNECTION_LIMIT = 2000
MAX_CONCURRENT_ACCEPTS = 2000


def now_ts() -> float:
    return time.time()


class Config:
    def __init__(self, upstream_doh: str, port: int, domains: Dict[str, str]):
        self.upstream_doh = upstream_doh
        self.port = port
        self.domains = domains

    @staticmethod
    def load_config(filename: str = "foreign_config.json") -> "Config":
        with open(filename, "r") as f:
            data = json.load(f)
        return Config(
            upstream_doh=data.get("upstream_doh", DEFAULT_UPSTREAM),
            port=data.get("port", 8080),
            domains=data.get("domains", {}),
        )


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


class DNSForwarder:
    def __init__(self, config: Config, buffer_pool: BufferPool, session: aiohttp.ClientSession, doh_semaphore: asyncio.Semaphore):
        self.config = config
        self.buffer_pool = buffer_pool
        self.session = session
        self.doh_semaphore = doh_semaphore

    async def forward_dns_query(self, query_bytes: bytes) -> bytes:
        try:
            dns_message = message.from_wire(query_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse DNS message: {e}")

        if len(dns_message.question) == 0:
            raise ValueError("No DNS question found")

        question = dns_message.question[0]
        domain = question.name.to_text()
        qtype = question.rdtype

        logger.info(f"DNSForwarder: received query for domain={domain} qtype={qtype}")

        async with self.doh_semaphore:
            for attempt in range(3):
                try:
                    async with self.session.post(
                        self.config.upstream_doh,
                        data=query_bytes,
                        headers={"Content-Type": "application/dns-message", "Connection": "keep-alive"},
                        timeout=aiohttp.ClientTimeout(total=DOH_TIMEOUT),
                    ) as resp:
                        if resp.status != 200:
                            logger.error(f"DNSForwarder: upstream DoH returned status {resp.status} for {domain}")
                            raise RuntimeError(f"Upstream DoH returned {resp.status}")
                        buffer = self.buffer_pool.get()
                        try:
                            chunk = await resp.content.read(len(buffer))
                            if len(chunk) < len(buffer):
                                logger.info(f"DNSForwarder: successfully resolved {domain} from upstream (short response)")
                                return chunk
                            result = bytearray(chunk)
                            while True:
                                chunk = await resp.content.read(len(buffer))
                                if not chunk:
                                    break
                                result.extend(chunk)
                            logger.info(f"DNSForwarder: successfully resolved {domain} from upstream (long response)")
                            return bytes(result)
                        finally:
                            self.buffer_pool.put(buffer)
                except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                    logger.warning("DNSForwarder: DoH attempt %d failed for %s: %s", attempt + 1, domain, e)
                    await asyncio.sleep(0.1 * (attempt + 1))
                    continue
            logger.error(f"DNSForwarder: all upstream DoH attempts failed for {domain}")
            raise RuntimeError("DNSForwarder: upstream DoH failed after retries")


class DOHServer:
    def __init__(self, dns_forwarder: DNSForwarder, rate_limiter: RateLimiter):
        self.dns_forwarder = dns_forwarder
        self.rate_limiter = rate_limiter
        self.app = None

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
                resp = await self.dns_forwarder.forward_dns_query(query_bytes)
            except Exception as e:
                logger.exception("DOHServer: DNS forwarding error: %s", e)
                return web.Response(text=f"Failed to forward DNS query: {e}", status=500)

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
        logger.info("Foreign DoH server started on %s:%d", host, port)

    async def shutdown(self):
        if self.app:
            await self.app.shutdown()
            await self.app.cleanup()


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


class SimpleSNIProxy:
    def __init__(self, config: Config):
        self.config = config
        self.host_pools: Dict[str, HostPool] = {}
        self.global_semaphore = asyncio.Semaphore(GLOBAL_BACKEND_CONNECTION_LIMIT)
        self.accept_semaphore = asyncio.Semaphore(MAX_CONCURRENT_ACCEPTS)
        self.cleanup_task: Optional[asyncio.Task] = None
        self.running = False

    def _get_host_pool(self, host: str) -> HostPool:
        if host not in self.host_pools:
            self.host_pools[host] = HostPool(host)
        return self.host_pools[host]

    def _read_client_hello(self, data: bytes) -> Optional[str]:
        try:
            if len(data) < 43 or data[0] != 0x16:
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
                            return data[pos:pos+name_length].decode("utf-8", errors="ignore")
                    return None
                pos += extension_length
            return None
        except Exception:
            return None

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
        except Exception as e:
            logger.debug(f"SNIProxy: error reading client hello: {e}")
            return None, b""

    def _should_use_warp(self, domain: str) -> bool:
        domain_clean = domain.rstrip(".").lower()
        for key, val in self.config.domains.items():
            if val != "warp":
                continue
            key_lower = key.lower()
            if domain_clean == key_lower:
                return True
            if domain_clean.endswith("." + key_lower):
                return True
            if key_lower in domain_clean:
                return True
        return False

    async def _create_backend_connection(self, target_address: str, target_port: int, use_warp: bool) -> BackendConn:
        await self.global_semaphore.acquire()
        try:
            if use_warp:
                from aiohttp_socks import open_connection
                reader, writer = await asyncio.wait_for(
                    open_connection(proxy_url=PROXY_URL, host=target_address, port=target_port, ssl=False),
                    timeout=BACKEND_CONNECT_TIMEOUT,
                )
                sock = writer.get_extra_info("socket")
                if sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            else:
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

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await self.accept_semaphore.acquire()
        except Exception:
            writer.close()
            await writer.wait_closed()
            return

        try:
            server_name, peeked_bytes = await self._peek_client_hello(reader)
            if not server_name:
                logger.debug("SNIProxy: empty SNI")
                return

            target_host = server_name.lower().rstrip(".")
            use_warp = self._should_use_warp(target_host)
            
            if use_warp:
                logger.info(f"SNIProxy: routing {target_host} via WARP to real destination")
            else:
                logger.info(f"SNIProxy: routing {target_host} directly to real destination")

            host_pool = self._get_host_pool(target_host)
            conn = await host_pool.acquire()
            if conn is None:
                try:
                    conn = await self._create_backend_connection(target_host, 443, use_warp)
                except Exception as e:
                    logger.error(f"SNIProxy: backend connect failed for {target_host}: {e}")
                    return

            try:
                conn.writer.write(peeked_bytes)
                await conn.writer.drain()
            except Exception as e:
                logger.error(f"SNIProxy: failed to write peeked bytes for {target_host}: {e}")
                await conn.close()
                self.global_semaphore.release()
                return

            async def forward(src_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter):
                try:
                    while True:
                        data = await asyncio.wait_for(src_reader.read(8192), timeout=BACKEND_RW_TIMEOUT)
                        if not data:
                            break
                        dst_writer.write(data)
                        await asyncio.wait_for(dst_writer.drain(), timeout=BACKEND_RW_TIMEOUT)
                except Exception:
                    pass
                finally:
                    dst_writer.close()
                    await dst_writer.wait_closed()

            logger.info(f"SNIProxy: successfully connected {target_host}")
            await asyncio.gather(
                forward(reader, conn.writer),
                forward(conn.reader, writer),
                return_exceptions=True,
            )
            await host_pool.release(conn)
        except Exception as e:
            logger.exception(f"SNIProxy: error handling connection: {e}")
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
                    await pool.evict_idle(IDLE_CONNECTION_TIMEOUT)
        except asyncio.CancelledError:
            pass

    async def run(self, port: int = 443):
        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        server = await asyncio.start_server(self.handle_connection, "0.0.0.0", port, limit=2**16)
        logger.info(f"SNI Proxy started on port {port}")
        async with server:
            await server.serve_forever()

    async def shutdown(self):
        self.running = False
        if self.cleanup_task:
            self.cleanup_task.cancel()


async def main():
    config = Config.load_config("foreign_config.json")
    buffer_pool = BufferPool()

    logger.info("=" * 60)
    logger.info("Foreign Server Configuration:")
    logger.info(f"  Upstream DoH: {config.upstream_doh}")
    logger.info(f"  DoH Port: {config.port}")
    logger.info(f"  SNI Proxy Port: 443")
    logger.info("=" * 60)

    conn = aiohttp.TCPConnector(limit=DOH_CONCURRENCY, force_close=False, ssl=False)
    session = aiohttp.ClientSession(connector=conn)

    doh_semaphore = asyncio.Semaphore(DOH_CONCURRENCY)
    rate_limiter = RateLimiter(requests_per_second=500, burst=1000)
    dns_forwarder = DNSForwarder(config, buffer_pool, session, doh_semaphore)
    doh_server = DOHServer(dns_forwarder, rate_limiter)
    sni_proxy = SimpleSNIProxy(config)

    logger.info("Starting Foreign Server: DoH and SNI Proxy")
    logger.info(f"  WARP Domains configured: {len(config.domains)}")
    for domain, mode in config.domains.items():
        logger.info(f"    {domain}: {mode}")
    try:
        await asyncio.gather(
            doh_server.run(host="0.0.0.0", port=config.port),
            sni_proxy.run(port=443),
        )
    finally:
        logger.info("Shutting down Foreign Server")
        await doh_server.shutdown()
        await sni_proxy.shutdown()
        await session.close()
        await conn.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Foreign Server stopped by user")

