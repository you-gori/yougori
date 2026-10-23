import asyncio
import unittest
from vault_gateway import Gateway


class GatewayTest(unittest.IsolatedAsyncioTestCase):
    async def test_binary_stream_is_preserved_in_both_directions(self):
        gateway = Gateway()
        clients = await asyncio.start_server(gateway.client, "127.0.0.1", 0)
        workers = await asyncio.start_server(gateway.worker, "127.0.0.1", 0)
        async with clients, workers:
            upstream_r, upstream_w = await asyncio.open_connection(
                "127.0.0.1", workers.sockets[0].getsockname()[1])
            client_r, client_w = await asyncio.open_connection(
                "127.0.0.1", clients.sockets[0].getsockname()[1])
            ciphertext = bytes(range(256)) * 200
            client_w.write(ciphertext)
            await client_w.drain()
            self.assertEqual(await asyncio.wait_for(upstream_r.readexactly(1), 2), b"\x01")
            self.assertEqual(await asyncio.wait_for(upstream_r.readexactly(len(ciphertext)), 2), ciphertext)
            upstream_w.write(ciphertext[::-1])
            await upstream_w.drain()
            self.assertEqual(await asyncio.wait_for(client_r.readexactly(len(ciphertext)), 2), ciphertext[::-1])
            client_w.close()
            await client_w.wait_closed()
            self.assertEqual(await asyncio.wait_for(upstream_r.read(1), 2), b"")
            upstream_w.close()
            await upstream_w.wait_closed()

    async def test_time_spent_waiting_for_a_client_does_not_shorten_its_session(self):
        gateway = Gateway()
        gateway.IDLE_SECONDS = 0.3
        gateway.SESSION_SECONDS = 5
        clients = await asyncio.start_server(gateway.client, "127.0.0.1", 0)
        workers = await asyncio.start_server(gateway.worker, "127.0.0.1", 0)
        async with clients, workers:
            upstream_r, upstream_w = await asyncio.open_connection(
                "127.0.0.1", workers.sockets[0].getsockname()[1])
            await asyncio.sleep(0.2)
            client_r, client_w = await asyncio.open_connection(
                "127.0.0.1", clients.sockets[0].getsockname()[1])
            client_w.write(b"x")
            await client_w.drain()
            self.assertEqual(await asyncio.wait_for(upstream_r.readexactly(2), 2), b"\x01x")
            # Past the idle limit counted from when the connection queued; the session continues.
            await asyncio.sleep(0.3)
            upstream_w.write(b"still here")
            await upstream_w.drain()
            self.assertEqual(await asyncio.wait_for(client_r.readexactly(10), 2), b"still here")
            client_w.close()
            await client_w.wait_closed()
            upstream_w.close()
            await upstream_w.wait_closed()

    async def test_an_untaken_reverse_connection_is_closed_after_its_idle_limit(self):
        gateway = Gateway()
        gateway.IDLE_SECONDS = 0.2
        workers = await asyncio.start_server(gateway.worker, "127.0.0.1", 0)
        async with workers:
            upstream_r, upstream_w = await asyncio.open_connection(
                "127.0.0.1", workers.sockets[0].getsockname()[1])
            self.assertEqual(await asyncio.wait_for(upstream_r.read(1), 2), b"")
            upstream_w.close()
            await upstream_w.wait_closed()


if __name__ == "__main__":
    unittest.main()
