"""python3 tee/client/tamper_relay.py --listen 127.0.0.1:8445 --box BOXIP:8444 [--direction down|up] [--frame N | --after-seconds S]

A relay that misbehaves on purpose, to show that the sealed stream rejects an altered frame (AB#591).
Put it between websockify (or any client) and boxd. It forwards the length-prefixed frames of
SEALED-STREAM.md unchanged, except one frame per connection in the chosen direction, where it flips
the low bit of the last byte (inside the AES-GCM tag). The other direction is forwarded as raw bytes.

  down: box to client (the client must fail to decrypt and close)
  up:   client to box (boxd must fail to decrypt and close; vnc and cdp log `STREAM auth failure, closing`)

Frames are counted from 1 per direction: 1 and 2 are HELLO/ATTEST and NK message 1/2, so 3 is the
first DATA frame. With --after-seconds the first DATA frame that passes after S seconds is flipped
instead, which lets a viewer render the desktop first and then lose the stream.
Each flip prints `TAMPER flipped <direction> frame <n> (<len> bytes)` on stdout."""
import argparse
import asyncio
import struct
import sys
import time

MAX_FRAME = 1 << 20


def hostport(s):
    host, _, port = s.rpartition(":")
    return host, int(port)


async def raw(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def framed(reader, writer, direction, frame, after, t0):
    """Forward frames, flipping one. Frames are reassembled, so a split header or body does not move the flip."""
    n = 0
    flipped = False
    try:
        while True:
            hdr = await reader.readexactly(4)
            (length,) = struct.unpack(">I", hdr)
            if length > MAX_FRAME:
                return
            body = bytearray(await reader.readexactly(length))
            n += 1
            # With a delay, only DATA frames (3 on) are candidates: flipping HELLO/ATTEST or a
            # handshake message would test the handshake, not the relay path this tool is for.
            due = (n == frame) if after is None else (n >= 3 and time.monotonic() - t0 >= after)
            if not flipped and due and length > 0:
                body[-1] ^= 0x01
                flipped = True
                print(f"TAMPER flipped {direction} frame {n} ({length} bytes)", flush=True)
            writer.write(hdr + bytes(body))
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        return
    finally:
        writer.close()


async def serve(args):
    box_host, box_port = hostport(args.box)

    async def handle(cr, cw):
        t0 = time.monotonic()
        try:
            br, bw = await asyncio.open_connection(box_host, box_port)
        except OSError as e:
            print(f"box unreachable: {e}", file=sys.stderr, flush=True)
            cw.close()
            return
        if args.direction == "down":
            tasks = [framed(br, cw, "down", args.frame, args.after_seconds, t0), raw(cr, bw)]
        else:
            tasks = [framed(cr, bw, "up", args.frame, args.after_seconds, t0), raw(br, cw)]
        # Either side ending ends both: a half-open relay would hide the close from the other end.
        done, pending = await asyncio.wait([asyncio.ensure_future(t) for t in tasks], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        # Collect every result so an error in a finished side is not reported as never retrieved.
        await asyncio.gather(*done, *pending, return_exceptions=True)
        cw.close()
        bw.close()

    host, port = hostport(args.listen)
    server = await asyncio.start_server(handle, host, port)
    bound = server.sockets[0].getsockname()
    print(f"LISTEN {bound[0]}:{bound[1]} -> {args.box} tamper {args.direction} "
          + (f"after {args.after_seconds} s" if args.after_seconds is not None else f"frame {args.frame}"), flush=True)
    async with server:
        await server.serve_forever()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--listen", required=True, help="HOST:PORT to accept on (port 0 picks one)")
    p.add_argument("--box", required=True, help="boxd stream port, HOST:PORT")
    p.add_argument("--direction", choices=("down", "up"), default="down")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--frame", type=int, default=3, help="1-based frame to flip in that direction (default 3, the first DATA frame)")
    g.add_argument("--after-seconds", type=float, help="flip the first DATA frame (3 on) that passes after this many seconds")
    args = p.parse_args(argv)
    if args.frame < 1:
        p.error("--frame starts at 1")
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
