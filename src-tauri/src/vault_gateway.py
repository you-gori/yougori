"""Untrusted, credential-free TCP relay for the dedicated vault OCI container.

8443 is MCP-over-TLS ingress; 8444 holds reverse connections from Desktop.
TLS is terminated only by the protected broker. No TLS keys, vault data,
host folders, logs, shell execution, or plaintext MCP parsing live here.
"""
import asyncio
import os


class Gateway:
    # A reverse connection waits this long to be taken before Desktop replaces it; once a
    # client takes it, that client's session limit applies instead of the time it waited.
    IDLE_SECONDS = 1900
    SESSION_SECONDS = 1800

    def __init__(self):
        self.workers = asyncio.Queue(maxsize=16)
        self.active = 0

    async def worker(self, reader, writer):
        done = asyncio.get_running_loop().create_future()
        taken = asyncio.Event()
        try:
            self.workers.put_nowait((reader, writer, done, taken))
            await asyncio.wait_for(taken.wait(), self.IDLE_SECONDS)
            await asyncio.wait_for(asyncio.shield(done), self.SESSION_SECONDS + 100)
        except (asyncio.QueueFull, TimeoutError, ConnectionError):
            pass
        finally:
            if not done.done():
                done.cancel()
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def client(self, reader, writer):
        if self.active >= 16:
            writer.close()
            return
        self.active += 1
        done = None
        try:
            async with asyncio.timeout(15):
                # Readiness probes and abandoned sockets must not consume a
                # reverse connection intended for an authenticated TLS client.
                first = await reader.read(1)
                if not first:
                    return
                while True:
                    upstream_r, upstream_w, done, taken = await self.workers.get()
                    if not done.done() and not upstream_r.at_eof():
                        taken.set()
                        break
            upstream_w.write(b"\x01" + first)
            await upstream_w.drain()

            async def copy(source, destination):
                while chunk := await source.read(32768):
                    destination.write(chunk)
                    await destination.drain()

            tasks = [asyncio.create_task(copy(reader, upstream_w)),
                     asyncio.create_task(copy(upstream_r, writer))]
            try:
                async with asyncio.timeout(self.SESSION_SECONDS):
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            if done is not None and not done.done():
                done.set_result(None)
            writer.close()
            self.active -= 1


async def main():
    gateway = Gateway()
    host = os.environ.get("YOUGORI_GATEWAY_BIND", "0.0.0.0")
    incoming = await asyncio.start_server(gateway.client, host, 8443, limit=65536)
    reverse = await asyncio.start_server(gateway.worker, host, 8444, limit=65536)
    async with incoming, reverse:
        await asyncio.gather(incoming.serve_forever(), reverse.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
