"""
Lab IMAP server: pymap (https://github.com/icgood/pymap, MIT) with its in-memory "dict" backend.

Runs inside the pymap virtual environment (lab/tools/imapvenv), started by
lab/real_mail_lab.py. The IMAP protocol handling (greeting, CAPABILITY, STARTTLS, LOGIN,
SELECT, FETCH, LOGOUT) is pymap's own code. This launcher only replaces pymap's command-line
entry point, because that entry point uses asyncio signal handlers that do not exist on Windows,
and it adds an implicit-TLS listener (IMAPS, port 993) using asyncio's standard ``ssl=`` option,
because pymap itself only offers STARTTLS.

Usage (inside the venv):
    python imap_server.py --port N --mode starttls|implicit|plaintext \
        [--cert F --key F] [--min-tls 1.0 --max-tls 1.2] [--ciphers S]

Prints "READY <port>" once listening; exits when stdin is closed.
"""
import argparse
import asyncio
import os
import ssl
import sys
from contextlib import AsyncExitStack

VERSIONS = {"1.0": ssl.TLSVersion.TLSv1, "1.1": ssl.TLSVersion.TLSv1_1,
            "1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


def server_context(a) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if a.min_tls:
        ctx.minimum_version = VERSIONS[a.min_tls]
    if a.max_tls:
        ctx.maximum_version = VERSIONS[a.max_tls]
    if a.ciphers:
        ctx.set_ciphers(a.ciphers)
    ctx.load_cert_chain(a.cert, a.key)
    return ctx


async def main(a) -> None:
    os.environ["FQDN"] = a.fqdn  # pymap greets with the FQDN; never the OS host name
    from pymap.backend.dict import DictBackend
    from pymap.imap import IMAPServer, IMAPService
    from proxyprotocol.reader import ProxyProtocolReader

    pymap_args = ["dict", "--demo-data", "--demo-user", a.user, "--demo-password", a.password]
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="backend")
    DictBackend.add_subparser("dict", sub)
    IMAPService.add_arguments(parser)
    parser.set_defaults(skip_services=[], passlib_cfg=None, inherited_sockets=None, debug=False)
    args = parser.parse_args(["--host", "127.0.0.1", "--port", str(a.port)] +
                             (["--no-tls"] if a.mode != "starttls" else []) + pymap_args)

    overrides = {"reject_dnsbl": False, "invalid_user_sleep": 0.0}
    tls_ctx = server_context(a) if a.mode in ("starttls", "implicit") else None
    if tls_ctx is not None:
        overrides["ssl_context"] = tls_ctx
    backend, config = await DictBackend.init(args, **overrides)
    config.apply_context()
    async with AsyncExitStack() as stack:
        await backend.start(stack)
        if a.mode == "implicit":
            # Implicit TLS (IMAPS): TLS starts at connect; STARTTLS is not advertised
            # (tls_enabled=False because of --no-tls), so LOGIN is offered inside TLS.
            cb = ProxyProtocolReader(config.proxy_protocol).get_callback(IMAPServer(backend.login, config))
            server = await asyncio.start_server(cb, host="127.0.0.1", port=a.port, ssl=tls_ctx)
        else:
            server = None
            await IMAPService(backend, config).start(stack)
        if server is not None:
            await stack.enter_async_context(server)
            stack.callback(asyncio.create_task(server.serve_forever()).cancel)
        print(f"READY {a.port}", flush=True)
        await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--mode", choices=["starttls", "implicit", "plaintext"], required=True)
    p.add_argument("--cert")
    p.add_argument("--key")
    p.add_argument("--min-tls")
    p.add_argument("--max-tls")
    p.add_argument("--ciphers")
    p.add_argument("--fqdn", default="imap.lab.test")
    p.add_argument("--user", default="alice")
    p.add_argument("--password", default="lab-imap-password")
    asyncio.run(main(p.parse_args()))
