import asyncio
import aiohttp
import base64
import gc
import ipaddress
import json
import logging
import struct
import sys
import time
from queue import Queue
from threading import Lock
from typing import Dict, Optional, Tuple
from aiohttp import web
import dns
from dns import message, rdatatype, rdataclass
from dns.rdtypes.IN.A import A


gc.set_threshold(700, 10, 5)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Config:
    def __init__(self, host: str, domains: Dict[str, str]):
        self.host = host
        self.domains = domains

    @staticmethod
    def load_config(filename: str = "config.json") -> 'Config':
        with open(filename, 'r') as file:
            config_data = json.load(file)
        
        return Config(
            host=config_data['host'],
            domains=config_data['domains']
        )


class BufferPool:
    def __init__(self, buffer_size: int = 4096, pool_size: int = 100):
        self.buffer_size = buffer_size
        self.pool = Queue(maxsize=pool_size)

    def get(self) -> bytearray:
        try:
            return self.pool.get_nowait()
        except:
            return bytearray(self.buffer_size)

    def put(self, buffer: bytearray) -> None:
        if len(buffer) == self.buffer_size:
            buffer[:] = bytearray(self.buffer_size)
            try:
                self.pool.put_nowait(buffer)
            except:
                pass


class RateLimiter:
    def __init__(self, rate_per_second: float, burst_size: int):
        self.rate_per_second = rate_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = Lock()

    def allow(self) -> bool:
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + elapsed * self.rate_per_second
            )
            self.last_update = now

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


class DNSHandler:
    def __init__(self, config: Config, buffer_pool: BufferPool):
        self.config = config
        self.buffer_pool = buffer_pool

    def _find_domain_match(self, domain: str) -> Optional[str]:
        domain_lower = domain.lower()
        for key, value in self.config.domains.items():
            if key.lower() in domain_lower:
                return value
        return None

    async def process_dns_query(self, query_bytes: bytes) -> bytes:
        try:
            dns_message = message.from_wire(query_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse DNS message: {e}")

        if len(dns_message.question) == 0:
            raise ValueError("No DNS question found in the request")

        question = dns_message.question[0]
        domain = question.name.to_text()
        matched_ip = self._find_domain_match(domain)

        if matched_ip:
            try:
                ip_address = ipaddress.IPv4Address(matched_ip)
            except ValueError:
                raise ValueError("Invalid IP address")

            response_message = message.make_response(dns_message)
            answer_rr = A(
                rdataclass.IN,
                rdatatype.A,
                str(ip_address)
            )
            rrset = dns.rrset.from_rdata(question.name, 3600, answer_rr)
            response_message.answer.append(rrset)
            return response_message.to_wire()

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://1.1.1.1/dns-query",
                data=query_bytes,
                headers={"Content-Type": "application/dns-message"}
            ) as response:
                buffer = self.buffer_pool.get()
                try:
                    chunk = await response.content.read(len(buffer))
                    if len(chunk) < len(buffer):
                        return chunk
                    
                    result = bytearray(chunk)
                    while True:
                        chunk = await response.content.read(len(buffer))
                        if not chunk:
                            break
                        result.extend(chunk)
                    return bytes(result)
                finally:
                    self.buffer_pool.put(buffer)


class DOHServer:
    def __init__(self, dns_handler: DNSHandler, rate_limiter: RateLimiter):
        self.dns_handler = dns_handler
        self.rate_limiter = rate_limiter

    async def handle_doh_request(self, request: web.Request) -> web.Response:
        if not self.rate_limiter.allow():
            return web.Response(
                text="Rate limit exceeded",
                status=429
            )

        if request.method == "GET":
            dns_param = request.query.get("dns")
            if not dns_param:
                return web.Response(
                    text="Missing 'dns' query parameter",
                    status=400
                )
            try:
                padding = 4 - (len(dns_param) % 4)
                if padding != 4:
                    dns_param += '=' * padding
                query_bytes = base64.urlsafe_b64decode(dns_param)
            except Exception:
                return web.Response(
                    text="Invalid 'dns' query parameter",
                    status=400
                )
        elif request.method == "POST":
            query_bytes = await request.read()
            if len(query_bytes) == 0:
                return web.Response(
                    text="Empty request body",
                    status=400
                )
        else:
            return web.Response(
                text="Only GET and POST methods are allowed",
                status=405
            )

        try:
            dns_response = await self.dns_handler.process_dns_query(query_bytes)
        except Exception as e:
            logger.error(f"DNS query processing error: {e}", exc_info=True)
            return web.Response(
                text=f"Failed to process DNS query: {str(e)}",
                status=500
            )

        return web.Response(
            body=dns_response,
            content_type="application/dns-message",
            status=200
        )

    async def handle_path(self, request: web.Request) -> web.Response:
        if request.path == "/dns-query":
            return await self.handle_doh_request(request)
        else:
            return web.Response(
                text="Unsupported path",
                status=404
            )

    async def create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.handle_path)
        return app

    async def run(self, host: str = "127.0.0.1", port: int = 8080):
        app = await self.create_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        logger.info(f"DoH server started on {host}:{port}")


class DOTServer:
    def __init__(self, dns_handler: DNSHandler, rate_limiter: RateLimiter, config: Config):
        self.dns_handler = dns_handler
        self.rate_limiter = rate_limiter
        self.config = config

    async def handle_dot_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            if not self.rate_limiter.allow():
                logger.warning("limit exceeded")
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
            logger.error(f"Error handling DoT connection: {e}")
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
            ssl=ssl_context
        )

        logger.info(f"DoT server started on port {port}")
        async with server:
            await server.serve_forever()


class SNIProxy:
    def __init__(self, config: Config):
        self.config = config

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
            cipher_suites_length = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2 + cipher_suites_length
            
            if pos + 1 > len(data):
                return None
            compression_methods_length = data[pos]
            pos += 1 + compression_methods_length
            
            if pos + 2 > len(data):
                return None
            extensions_length = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            
            extensions_end = pos + extensions_length
            while pos + 4 <= extensions_end:
                extension_type = struct.unpack('!H', data[pos:pos+2])[0]
                extension_length = struct.unpack('!H', data[pos+2:pos+4])[0]
                pos += 4
                
                if extension_type == 0:
                    if pos + 2 > len(data):
                        return None
                    server_name_list_length = struct.unpack('!H', data[pos:pos+2])[0]
                    pos += 2
                    
                    if pos + server_name_list_length > len(data):
                        return None
                    
                    if pos + 3 <= len(data):
                        name_type = data[pos]
                        name_length = struct.unpack('!H', data[pos+1:pos+3])[0]
                        pos += 3
                        
                        if name_type == 0 and pos + name_length <= len(data):
                            server_name = data[pos:pos+name_length].decode('utf-8', errors='ignore')
                            return server_name
                    return None
                
                pos += extension_length
            
            return None
        except Exception:
            return None

    async def _peek_client_hello(self, reader: asyncio.StreamReader) -> Tuple[Optional[str], bytes]:
        try:
            peeked_data = bytearray()
            
            first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            if not first_byte:
                return None, b""
            
            peeked_data.extend(first_byte)
            
            if first_byte[0] == 0x16:
                record_header = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
                if len(record_header) < 4:
                    return None, b""
                
                peeked_data.extend(record_header)
                record_length = struct.unpack("!H", record_header[2:4])[0]
                
                record_body = await asyncio.wait_for(reader.readexactly(record_length), timeout=5.0)
                if len(record_body) < record_length:
                    return None, b""
                
                peeked_data.extend(record_body)
                
                server_name = self._read_client_hello(bytes(peeked_data))
                return server_name, bytes(peeked_data)
            
            return None, bytes(peeked_data)
        except asyncio.TimeoutError:
            return None, b""
        except asyncio.IncompleteReadError:
            return None, b""
        except Exception as e:
            logger.error(f"Error peeking client hello: {e}")
            return None, b""

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            server_name, peeked_bytes = await self._peek_client_hello(reader)
            
            if not server_name or server_name.strip() == "":
                logger.warning("empty sni not allowed here")
                response = (
                    "HTTP/1.1 502 OK\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "Content-Length: 21\r\n"
                    "\r\n"
                    "nginx, malformed data"
                )
                writer.write(response.encode())
                await writer.drain()
                return
            
            target_host = server_name.lower()
            
            if target_host == self.config.host:
                target_address = "127.0.0.1"
                target_port = 8443
            else:
                target_address = target_host
                target_port = 443
            
            try:
                backend_reader, backend_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_address, target_port),
                    timeout=5.0
                )
            except Exception as e:
                logger.error(f"Failed to connect to backend: {e}")
                return
            
            try:
                backend_writer.write(peeked_bytes)
                await backend_writer.drain()
                
                async def forward_to_backend():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            backend_writer.write(data)
                            await backend_writer.drain()
                    except Exception:
                        pass
                    finally:
                        try:
                            backend_writer.write_eof()
                            await backend_writer.drain()
                        except:
                            pass
                        backend_writer.close()
                    await backend_writer.wait_closed()
                
                async def forward_to_client():
                    try:
                        while True:
                            data = await backend_reader.read(4096)
                            if not data:
                                break
                            writer.write(data)
                            await writer.drain()
                    except Exception:
                        pass
                    finally:
                        try:
                            writer.write_eof()
                            await writer.drain()
                        except:
                            pass
                        writer.close()
                    await writer.wait_closed()
                
                await asyncio.gather(
                    forward_to_backend(),
                    forward_to_client(),
                    return_exceptions=True
                )
            finally:
                if not backend_writer.is_closing():
                    backend_writer.close()
                    await backend_writer.wait_closed()
        except Exception as e:
            logger.error(f"Error handling SNI connection: {e}")
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

    async def run(self, port: int = 443):
        server = await asyncio.start_server(
            self.handle_connection,
            "0.0.0.0",
            port
        )
        
        logger.info(f"SNI Proxy started on port {port}")
        async with server:
            await server.serve_forever()


async def main():
    try:
        config = Config.load_config("config.json")
    except Exception as e:
        logger.fatal(f"Failed to load configuration: {e}")
        sys.exit(1)

    buffer_pool = BufferPool(buffer_size=4096, pool_size=100)
    rate_limiter = RateLimiter(rate_per_second=10.0, burst_size=50)
    dns_handler = DNSHandler(config, buffer_pool)

    doh_server = DOHServer(dns_handler, rate_limiter)
    dot_server = DOTServer(dns_handler, rate_limiter, config)
    sni_proxy = SNIProxy(config)

    logger.info("Starting SSNI proxy server on :443, :853...")

    await asyncio.gather(
        doh_server.run(host="127.0.0.1", port=8080),
        dot_server.run(port=853),
        sni_proxy.run(port=443),
        return_exceptions=True
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.fatal(f"Fatal error: {e}")
        sys.exit(1)
