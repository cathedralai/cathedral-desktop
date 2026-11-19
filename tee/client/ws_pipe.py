"""A sealed stream byte pipe over a WebSocket relay (websockify today, the edge stream route later).

    from ws_pipe import open_ws_pipe
    r, w = await open_ws_pipe("wss://relay.example/stream")
    s = await open_stream(r, w, target="cdp", verify=...)

The relay carries opaque bytes in binary messages. Sealed stream frames are length prefixed inside
those bytes, so a relay may split or merge messages freely (the same rule as `websocketPipe` in
tee/web/sealed-stream.js). The reader pulls one message at a time, only when asked, so a slow local
client holds the relay back instead of filling memory here.

Needs the `websockets` package.
"""
from __future__ import annotations

import asyncio

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

# Above MAX_FRAME (1 MiB) plus its length prefix, so a relay that merges chunks never trips the limit.
MAX_MESSAGE = 4 << 20


class WsReader:
    def __init__(self, ws):
        self.ws, self.buf = ws, bytearray()

    async def readexactly(self, n: int) -> bytes:
        while len(self.buf) < n:
            try:
                msg = await self.ws.recv()
            except ConnectionClosed:
                raise asyncio.IncompleteReadError(bytes(self.buf), n) from None
            if isinstance(msg, str):
                # A relay that speaks text is not carrying our bytes; stop rather than guess an encoding.
                await self.ws.close(1003, "binary only")
                raise ValueError("relay sent a text message; sealed stream is binary only")
            self.buf += msg
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


class WsWriter:
    """The part of asyncio.StreamWriter the sealed stream uses: write, drain, close."""

    def __init__(self, ws):
        self.ws, self.pending, self._closing = ws, bytearray(), None

    def write(self, data: bytes):
        self.pending += data

    async def drain(self):
        if self.pending:
            data = bytes(self.pending)
            self.pending.clear()
            await self.ws.send(data)

    def is_closing(self) -> bool:
        return self._closing is not None

    def close(self):
        # StreamWriter.close is synchronous; the WebSocket close handshake runs as a task.
        if self._closing is None:
            self._closing = asyncio.ensure_future(self.ws.close())

    async def wait_closed(self):
        if self._closing is not None:
            await self._closing


async def open_ws_pipe(url: str, open_timeout: float = 10) -> tuple[WsReader, WsWriter]:
    ws = await connect(url, subprotocols=["binary"], max_size=MAX_MESSAGE, compression=None,
                       open_timeout=open_timeout)
    return WsReader(ws), WsWriter(ws)
