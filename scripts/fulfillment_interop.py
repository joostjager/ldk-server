#!/usr/bin/env python3
"""Run fulfillment-payload interop checks against Eclair and ldk-server.

Prerequisites:
  * Build this ldk-server checkout so target/debug/ldk-server and
    target/debug/ldk-server-cli exist.
  * Build an Eclair node zip from ACINQ/eclair#3321 or compatible code.
  * Provide bitcoind and bitcoin-cli from Bitcoin Core.

Example:
  scripts/fulfillment_interop.py \
    --bitcoind /path/to/bitcoind \
    --bitcoin-cli /path/to/bitcoin-cli \
    --eclair-zip /path/to/eclair-node-...-bin.zip

The default expected payload is the high-range TLV used by the interop
receiver test patch. Pass --expected-payload-hex '' when the receiver sends
only an empty padded payload, or pass the serialized TLV bytes for another
test payload.
"""

import argparse
import base64
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CASE_MATRIX = [
    ("eclair-ldk-ldk", ("eclair", "ldk", "ldk")),
    ("ldk-eclair-ldk", ("ldk", "eclair", "ldk")),
    ("eclair-eclair-ldk", ("eclair", "eclair", "ldk")),
]

BASE: Path
BITCOIND: Path
BITCOIN_CLI: Path
LDK_SERVER: Path
LDK_CLI: Path
ECLAIR_ZIP: Path
ECLAIR_DIST: Path
ECLAIR_NODE: Path

RPC_USER = "fulfilluser"
RPC_PASSWORD = "fulfillpass"
ECLAIR_PASSWORD = "fulfillpass"
DEFAULT_EXPECTED_PAYLOAD_HEX = "fe00010001126c646b2d65636c6169722d696e7465726f70"
EXPECTED_PAYLOAD_HEX: str
PAYMENT_AMOUNT = "10000sat"
CHANNEL_AMOUNT = "1000000sat"
ECLAIR_CHANNEL_AMOUNT = "1000000"
ECLAIR_PUSH_MSAT = "500000000"


def path_arg(value):
    return Path(value).expanduser()


def hex_arg(value):
    value = value.strip().lower()
    if value:
        try:
            bytes.fromhex(value)
        except ValueError as e:
            raise argparse.ArgumentTypeError(f"invalid hex value: {value}") from e
    return value


def env_path(name):
    value = os.environ.get(name)
    return path_arg(value) if value else None


def which_path(name):
    value = shutil.which(name)
    return Path(value) if value else None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run fulfillment-payload interop checks across Eclair and ldk-server.",
    )
    parser.add_argument(
        "--base-dir",
        type=path_arg,
        default=env_path("FULFILLMENT_INTEROP_BASE")
        or Path("/private/tmp/fulfillment-interop"),
        help="scratch directory for nodes, logs, and Eclair unzip output",
    )
    parser.add_argument(
        "--bitcoind",
        type=path_arg,
        default=env_path("BITCOIND_EXE") or env_path("BITCOIND") or which_path("bitcoind"),
        help="path to bitcoind; also accepts BITCOIND_EXE or BITCOIND",
    )
    parser.add_argument(
        "--bitcoin-cli",
        type=path_arg,
        default=env_path("BITCOIN_CLI_EXE")
        or env_path("BITCOIN_CLI")
        or which_path("bitcoin-cli"),
        help="path to bitcoin-cli; defaults to a sibling of bitcoind if omitted",
    )
    parser.add_argument(
        "--ldk-server",
        type=path_arg,
        default=env_path("LDK_SERVER_EXE") or REPO_ROOT / "target/debug/ldk-server",
        help="path to the ldk-server binary",
    )
    parser.add_argument(
        "--ldk-cli",
        type=path_arg,
        default=env_path("LDK_SERVER_CLI_EXE")
        or REPO_ROOT / "target/debug/ldk-server-cli",
        help="path to the ldk-server-cli binary",
    )
    parser.add_argument(
        "--eclair-zip",
        type=path_arg,
        default=env_path("ECLAIR_ZIP"),
        help="path to the Eclair node -bin.zip built from the interop branch",
    )
    parser.add_argument(
        "--expected-payload-hex",
        type=hex_arg,
        default=hex_arg(
            os.environ.get("EXPECTED_FULFILLMENT_PAYLOAD_HEX", DEFAULT_EXPECTED_PAYLOAD_HEX)
        ),
        help=(
            "non-padding fulfillment payload TLV bytes expected in sender logs; "
            "set to '' to only require successful decode"
        ),
    )
    parser.add_argument(
        "cases",
        nargs="*",
        choices=[name for name, _ in CASE_MATRIX],
        help="optional case names to run; defaults to all cases",
    )
    return parser.parse_args()


def eclair_dist_from_zip(base_dir, eclair_zip):
    dist_name = eclair_zip.stem
    if dist_name.endswith("-bin"):
        dist_name = dist_name[:-4]
    return base_dir / dist_name


def configure(args):
    global BASE, BITCOIND, BITCOIN_CLI, LDK_SERVER, LDK_CLI
    global ECLAIR_ZIP, ECLAIR_DIST, ECLAIR_NODE, EXPECTED_PAYLOAD_HEX

    BASE = args.base_dir
    BITCOIND = args.bitcoind
    BITCOIN_CLI = args.bitcoin_cli or (BITCOIND.parent / "bitcoin-cli" if BITCOIND else None)
    LDK_SERVER = args.ldk_server
    LDK_CLI = args.ldk_cli
    ECLAIR_ZIP = args.eclair_zip
    ECLAIR_DIST = eclair_dist_from_zip(BASE, ECLAIR_ZIP) if ECLAIR_ZIP else None
    ECLAIR_NODE = ECLAIR_DIST / "bin/eclair-node.sh" if ECLAIR_DIST else None
    EXPECTED_PAYLOAD_HEX = args.expected_payload_hex


def require_existing(path, label):
    if path is None:
        raise RuntimeError(f"{label} is required")
    if not path.exists():
        raise RuntimeError(f"{label} not found: {path}")


@dataclass
class Node:
    name: str
    kind: str
    p2p_port: int
    api_port: int
    akka_port: int
    datadir: Path
    config: Path
    log: Path
    proc: subprocess.Popen | None = None
    node_id: str | None = None


@dataclass
class Case:
    name: str
    roles: tuple[str, str, str]
    index: int
    base_dir: Path
    bitcoin_dir: Path
    rpc_port: int
    p2p_port: int
    zmq_block_port: int
    zmq_tx_port: int
    procs: list[subprocess.Popen]


def run(cmd, *, timeout=60, cwd=None, check=True):
    print("+ " + " ".join(str(c) for c in cmd), flush=True)
    res = subprocess.run(
        [str(c) for c in cmd],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and res.returncode != 0:
        raise RuntimeError(
            f"command failed ({res.returncode}): {' '.join(str(c) for c in cmd)}\n"
            f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
        )
    return res.stdout.strip()


def run_json(cmd, *, timeout=60):
    out = run(cmd, timeout=timeout)
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"expected JSON from {' '.join(str(c) for c in cmd)}:\n{out}") from e


def wait_until(desc, fn, *, timeout=120, interval=1):
    deadline = time.time() + timeout
    last_error = None
    last_result = None
    while time.time() < deadline:
        try:
            result = fn()
            last_result = result
            if result:
                return result
        except Exception as e:
            last_error = e
        time.sleep(interval)
    if last_error:
        raise TimeoutError(f"timed out waiting for {desc}: {last_error}")
    raise TimeoutError(f"timed out waiting for {desc}; last result={last_result!r}")


def wait_port(port, *, timeout=60):
    def probe():
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    return wait_until(f"port {port}", probe, timeout=timeout)


def port_is_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def find_free_base(start):
    offsets = [0, 1, 2, 3]
    offsets.extend([10 + idx * 10 + sub for idx in range(3) for sub in (0, 1, 2)])
    for port_base in range(start, 60000, 100):
        if all(port_is_free(port_base + offset) for offset in offsets):
            return port_base
    raise RuntimeError(f"could not find a free port block starting at {start}")


def start_process(case, cmd, log_file, *, env=None):
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log = open(log_file, "ab", buffering=0)
    print("+ start " + " ".join(str(c) for c in cmd), flush=True)
    proc = subprocess.Popen(
        [str(c) for c in cmd],
        stdout=log,
        stderr=subprocess.STDOUT,
        env=env,
        start_new_session=True,
    )
    case.procs.append(proc)
    return proc


def stop_case(case):
    for proc in reversed(case.procs):
        if proc.poll() is not None:
            continue
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    deadline = time.time() + 10
    for proc in reversed(case.procs):
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.2)
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def stop_node(node):
    if not node.proc or node.proc.poll() is not None:
        return
    try:
        os.killpg(node.proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        node.proc = None
        return
    deadline = time.time() + 10
    while node.proc.poll() is None and time.time() < deadline:
        time.sleep(0.2)
    if node.proc.poll() is None:
        try:
            os.killpg(node.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    node.proc = None


def prepare_dist():
    BASE.mkdir(parents=True, exist_ok=True)
    if ECLAIR_DIST.exists():
        shutil.rmtree(ECLAIR_DIST)
    run(["unzip", "-q", "-o", ECLAIR_ZIP, "-d", BASE], timeout=120)
    require_existing(ECLAIR_NODE, "eclair-node.sh")


def make_case(name, roles, index):
    base = BASE / "cases" / name
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    port_base = find_free_base(41000 + index * 1000)
    return Case(
        name=name,
        roles=roles,
        index=index,
        base_dir=base,
        bitcoin_dir=base / "bitcoin",
        rpc_port=port_base,
        p2p_port=port_base + 1,
        zmq_block_port=port_base + 2,
        zmq_tx_port=port_base + 3,
        procs=[],
    )


def btc(case, args, *, wallet=None, timeout=60):
    cmd = [
        BITCOIN_CLI,
        "-regtest",
        f"-datadir={case.bitcoin_dir}",
        f"-rpcport={case.rpc_port}",
        f"-rpcuser={RPC_USER}",
        f"-rpcpassword={RPC_PASSWORD}",
    ]
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(args)
    return run(cmd, timeout=timeout)


def mine(case, blocks):
    address = btc(case, ["getnewaddress"], wallet="miner")
    btc(case, ["generatetoaddress", str(blocks), address], timeout=120)
    time.sleep(1)


def start_bitcoind(case):
    case.bitcoin_dir.mkdir(parents=True)
    cmd = [
        BITCOIND,
        "-regtest",
        f"-datadir={case.bitcoin_dir}",
        "-server=1",
        "-txindex=1",
        f"-rpcuser={RPC_USER}",
        f"-rpcpassword={RPC_PASSWORD}",
        "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1",
        f"-rpcport={case.rpc_port}",
        "-listen=0",
        "-discover=0",
        "-dnsseed=0",
        "-fixedseeds=0",
        f"-zmqpubrawblock=tcp://127.0.0.1:{case.zmq_block_port}",
        f"-zmqpubrawtx=tcp://127.0.0.1:{case.zmq_tx_port}",
        "-fallbackfee=0.0001",
    ]
    start_process(case, cmd, case.base_dir / "bitcoind.log")
    wait_until("bitcoind RPC", lambda: btc(case, ["getblockchaininfo"], timeout=5), timeout=60)
    btc(case, ["createwallet", "miner"])
    mine(case, 101)


def create_eclair_wallet(case, wallet):
    btc(case, ["createwallet", wallet])
    address = btc(case, ["getnewaddress"], wallet=wallet)
    btc(case, ["sendtoaddress", address, "2"], wallet="miner")
    mine(case, 1)


def write_ldk_config(case, node):
    node.config.parent.mkdir(parents=True, exist_ok=True)
    node.config.write_text(
        f"""
[node]
network = "regtest"
listening_addresses = ["127.0.0.1:{node.p2p_port}"]
grpc_service_address = "127.0.0.1:{node.api_port}"
alias = "{node.name}"

[storage.disk]
dir_path = "{node.datadir}"

[log]
level = "Debug"
file = "{node.datadir}/ldk-server.log"
log_to_file = true

[tls]
hosts = ["localhost", "127.0.0.1"]

[bitcoind]
rpc_address = "127.0.0.1:{case.rpc_port}"
rpc_user = "{RPC_USER}"
rpc_password = "{RPC_PASSWORD}"
""".strip()
        + "\n"
    )


def write_eclair_config(case, node, wallet, zero_conf_peers=()):
    node.datadir.mkdir(parents=True, exist_ok=True)
    overrides = ""
    if zero_conf_peers:
        peer_entries = []
        for node_id in zero_conf_peers:
            peer_entries.append(
                f"""
  {{
    nodeid = "{node_id}"
    features = {{
      option_static_remotekey = optional
      option_anchors_zero_fee_htlc_tx = optional
      option_scid_alias = optional
      option_zeroconf = optional
    }}
  }}"""
            )
        overrides = "eclair.override-init-features = [" + ",".join(peer_entries) + "\n]\n"
    node.config.write_text(
        f"""
eclair.chain = "regtest"
eclair.datadir = "{node.datadir}"
eclair.printToConsole = true
eclair.node-alias = "{node.name}"
eclair.server.binding-ip = "127.0.0.1"
eclair.server.port = {node.p2p_port}
eclair.api.enabled = true
eclair.api.binding-ip = "127.0.0.1"
eclair.api.port = {node.api_port}
eclair.api.password = "{ECLAIR_PASSWORD}"
eclair.bitcoind.host = "127.0.0.1"
eclair.bitcoind.rpcport = {case.rpc_port}
eclair.bitcoind.auth = "password"
eclair.bitcoind.rpcuser = "{RPC_USER}"
eclair.bitcoind.rpcpassword = "{RPC_PASSWORD}"
eclair.bitcoind.wallet = "{wallet}"
eclair.bitcoind.zmqblock = "tcp://127.0.0.1:{case.zmq_block_port}"
eclair.bitcoind.zmqtx = "tcp://127.0.0.1:{case.zmq_tx_port}"
eclair.features.option_dual_fund = disabled
akka.remote.artery.canonical.port = {node.akka_port}
akka.cluster.seed-nodes = ["akka://eclair-node@127.0.0.1:{node.akka_port}"]
""".strip()
        + "\n"
        + overrides
    )


def make_nodes(case):
    role_names = ("sender", "middle", "receiver")
    nodes = []
    for idx, (role, kind) in enumerate(zip(role_names, case.roles)):
        base_port = case.rpc_port + 10 + idx * 10
        node = Node(
            name=f"{case.name}-{role}",
            kind=kind,
            p2p_port=base_port,
            api_port=base_port + 1,
            akka_port=base_port + 2,
            datadir=case.base_dir / role,
            config=case.base_dir / role / ("ldk-server.toml" if kind == "ldk" else "eclair.conf"),
            log=case.base_dir / role / f"{kind}.stdout.log",
        )
        if kind == "ldk":
            write_ldk_config(case, node)
        else:
            create_eclair_wallet(case, node.name.replace("-", "_"))
            write_eclair_config(case, node, node.name.replace("-", "_"))
        nodes.append(node)
    return nodes


def ldk_cli(node, args, *, timeout=60):
    return run_json([LDK_CLI, "--config", node.config, *args], timeout=timeout)


def eclair_api(node, command, params=None, *, timeout=60):
    params = params or {}
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{node.api_port}/{command}", data=data)
    auth = base64.b64encode(f":{ECLAIR_PASSWORD}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    with urllib.request.urlopen(req, timeout=timeout) as res:
        body = res.read().decode()
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def start_node(case, node):
    if node.kind == "ldk":
        node.proc = start_process(case, [LDK_SERVER, node.config], node.log)
        wait_until(
            f"{node.name} ldk API",
            lambda: ldk_cli(node, ["get-node-info"], timeout=5),
            timeout=120,
        )
        info = ldk_cli(node, ["get-node-info"])
        node.node_id = info["node_id"]
    else:
        env = os.environ.copy()
        env["JAVA_OPTS"] = env.get("JAVA_OPTS", "-Xmx768m")
        node.proc = start_process(
            case,
            [ECLAIR_NODE, "-Declair.allow-unsafe-startup=true", f"-Declair.datadir={node.datadir}"],
            node.log,
            env=env,
        )
        wait_port(node.api_port, timeout=120)
        info = wait_until(
            f"{node.name} eclair API",
            lambda: eclair_api(node, "getinfo", timeout=5),
            timeout=120,
        )
        node.node_id = info.get("nodeId") or info.get("node_id")
    print(f"{node.name}: {node.kind} {node.node_id}", flush=True)


def restart_eclairs_with_zeroconf_overrides(case, nodes):
    eclairs = [node for node in nodes if node.kind == "eclair"]
    if len(eclairs) < 2:
        return
    print(f"{case.name}: restarting Eclair nodes with zeroconf peer overrides", flush=True)
    for node in eclairs:
        stop_node(node)
    for node in eclairs:
        peers = [peer.node_id for peer in eclairs if peer.node_id != node.node_id]
        write_eclair_config(case, node, node.name.replace("-", "_"), peers)
    for node in eclairs:
        start_node(case, node)


def fund_ldk(case, node):
    response = ldk_cli(node, ["onchain-receive"])
    address = response.get("address") or response.get("bech32_address")
    if not address:
        raise RuntimeError(f"could not find LDK onchain address in {response}")
    btc(case, ["sendtoaddress", address, "2"], wallet="miner")


def connect_peer(src, dst):
    if src.kind == "ldk":
        ldk_cli(src, ["connect-peer", dst.node_id, f"127.0.0.1:{dst.p2p_port}", "--persist"])
    else:
        eclair_api(src, "connect", {"uri": f"{dst.node_id}@127.0.0.1:{dst.p2p_port}"})


def open_channel(src, dst, *, push_msat="0", announce_channel="true", channel_type=None):
    connect_peer(src, dst)
    time.sleep(1)
    if src.kind == "ldk":
        if push_msat != "0":
            raise ValueError("push_msat is only supported for Eclair-funded channels")
        if announce_channel != "true" or channel_type is not None:
            raise ValueError("custom channel settings are only supported for Eclair-funded channels")
        ldk_cli(
            src,
            [
                "open-channel",
                dst.node_id,
                f"127.0.0.1:{dst.p2p_port}",
                CHANNEL_AMOUNT,
                "--announce-channel",
            ],
            timeout=120,
        )
    else:
        if dst.kind == "eclair" and channel_type is None:
            announce_channel = "false"
            channel_type = "anchor_outputs_zero_fee_htlc_tx+scid_alias+zeroconf"
        params = {
            "nodeId": dst.node_id,
            "fundingSatoshis": ECLAIR_CHANNEL_AMOUNT,
            "pushMsat": push_msat,
            "announceChannel": announce_channel,
            "openTimeoutSeconds": "60",
        }
        if channel_type:
            params["channelType"] = channel_type
        eclair_api(
            src,
            "open",
            params,
            timeout=120,
        )
    time.sleep(3)


def json_contains(value, text):
    if isinstance(value, dict):
        return any(json_contains(v, text) for v in value.values())
    if isinstance(value, list):
        return any(json_contains(v, text) for v in value)
    return text in str(value)


def wait_channels(node, expected):
    if node.kind == "ldk":
        def ready():
            resp = ldk_cli(node, ["list-channels"], timeout=10)
            channels = resp.get("channels", [])
            return len(channels) >= expected and all(ch.get("is_usable") for ch in channels)
        wait_until(f"{node.name} usable LDK channels", ready, timeout=180)
    else:
        def ready():
            resp = eclair_api(node, "channels", timeout=10)
            if not isinstance(resp, list) or len(resp) < expected:
                return False
            return json_contains(resp, "DATA_NORMAL") or json_contains(resp, "NORMAL")
        wait_until(f"{node.name} NORMAL Eclair channels", ready, timeout=180)


def wait_graph_channels(node, expected):
    if node.kind != "ldk":
        return True

    def ready():
        resp = ldk_cli(node, ["graph-list-channels"], timeout=10)
        return len(resp.get("short_channel_ids", [])) >= expected

    try:
        wait_until(f"{node.name} LDK graph channels", ready, timeout=30)
        return True
    except TimeoutError as e:
        print(f"{node.name}: warning: {e}", flush=True)
        return False


def create_invoice(receiver, case_name):
    resp = ldk_cli(receiver, ["bolt11-receive", PAYMENT_AMOUNT, "--description", case_name])
    for key in ("invoice", "bolt11_invoice", "payment_request"):
        if key in resp:
            return resp[key]
    raise RuntimeError(f"could not find invoice in {resp}")


def send_payment(sender, invoice):
    if sender.kind == "ldk":
        resp = ldk_cli(
            sender,
            ["bolt11-send", invoice, "--max-total-routing-fee", "10000sat"],
            timeout=120,
        )
        payment_id = resp.get("payment_id")
        if payment_id:
            def succeeded():
                details = ldk_cli(sender, ["get-payment-details", payment_id], timeout=10)
                return json_contains(details, "Succeeded") or json_contains(details, "SUCCEEDED")

            wait_until(
                f"{sender.name} payment success",
                succeeded,
                timeout=120,
            )
        return resp
    return eclair_api(
        sender,
        "payinvoice",
        {
            "invoice": invoice,
            "blocking": "true",
            "maxFeeFlatSat": "10000",
            "maxFeePct": "10",
        },
        timeout=180,
    )


def collect_logs(node):
    chunks = []
    for path in [node.log, node.datadir / "ldk-server.log", node.datadir / "eclair.log"]:
        if path.exists():
            chunks.append(path.read_text(errors="replace"))
    return "\n".join(chunks)


def parse_bigsize(data, offset):
    if offset >= len(data):
        raise ValueError("missing BigSize value")
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    if first == 0xfd:
        if offset + 3 > len(data):
            raise ValueError("truncated BigSize u16")
        return int.from_bytes(data[offset + 1 : offset + 3], "big"), offset + 3
    if first == 0xfe:
        if offset + 5 > len(data):
            raise ValueError("truncated BigSize u32")
        return int.from_bytes(data[offset + 1 : offset + 5], "big"), offset + 5
    if offset + 9 > len(data):
        raise ValueError("truncated BigSize u64")
    return int.from_bytes(data[offset + 1 : offset + 9], "big"), offset + 9


def encode_bigsize(value):
    if value < 0xfd:
        return bytes([value])
    if value <= 0xffff:
        return b"\xfd" + value.to_bytes(2, "big")
    if value <= 0xffffffff:
        return b"\xfe" + value.to_bytes(4, "big")
    return b"\xff" + value.to_bytes(8, "big")


def strip_padding_tlv(payload_hex):
    data = bytes.fromhex(payload_hex)
    offset = 0
    out = bytearray()
    while offset < len(data):
        tlv_type, offset = parse_bigsize(data, offset)
        tlv_len, value_offset = parse_bigsize(data, offset)
        value_end = value_offset + tlv_len
        if value_end > len(data):
            raise ValueError("truncated TLV value")
        if tlv_type != 1:
            out += encode_bigsize(tlv_type)
            out += encode_bigsize(tlv_len)
            out += data[value_offset:value_end]
        offset = value_end
    return out.hex()


def decoded_payload_hex(sender, logs):
    if sender.kind == "ldk":
        matches = re.findall(r"Decoded fulfillment payload ([0-9a-fA-F]+)", logs)
    else:
        matches = re.findall(r"decoded fulfillment payload=Some\(([0-9a-fA-F]+)\)", logs)
    return matches[-1].lower() if matches else None


def verify_sender(sender, nodes):
    logs = collect_logs(sender)
    case_logs = "\n".join(collect_logs(node) for node in nodes)
    decoded_payload = decoded_payload_hex(sender, logs)
    try:
        decoded_non_padding_payload = (
            strip_padding_tlv(decoded_payload) if decoded_payload is not None else None
        )
    except ValueError:
        decoded_non_padding_payload = decoded_payload
    payload_ok = (
        not EXPECTED_PAYLOAD_HEX
        or decoded_non_padding_payload == EXPECTED_PAYLOAD_HEX
        or EXPECTED_PAYLOAD_HEX in logs.lower()
    )
    if sender.kind == "ldk":
        attribution_ok = (
            "Invalid fulfill HMAC in attribution data" not in logs
            and "AttributionData(" in case_logs
        )
        decoded_ok = decoded_payload is not None
    else:
        attribution_ok = bool(re.search(r"hold_times=[1-9][0-9]*", logs))
        decoded_ok = decoded_payload is not None
    if not payload_ok or not attribution_ok or not decoded_ok:
        raise AssertionError(
            f"{sender.name} verification failed: "
            f"decoded={decoded_ok} payload={payload_ok} attribution={attribution_ok} "
            f"decoded_payload={decoded_non_padding_payload!r} "
            f"expected_payload={EXPECTED_PAYLOAD_HEX!r}\n"
            f"last log lines:\n" + "\n".join(logs.splitlines()[-80:])
        )
    display_payload = decoded_non_padding_payload if decoded_non_padding_payload else "<empty>"
    print(
        f"{sender.name}: decoded fulfillment payload "
        f"(without padding) {display_payload}",
        flush=True,
    )


def run_case(case):
    print(f"\n=== {case.name}: {'->'.join(case.roles)} ===", flush=True)
    start_bitcoind(case)
    nodes = make_nodes(case)
    for node in nodes:
        start_node(case, node)
    restart_eclairs_with_zeroconf_overrides(case, nodes)

    for node in nodes:
        if node.kind == "ldk":
            fund_ldk(case, node)
    mine(case, 6)

    sender, middle, receiver = nodes
    if sender.kind == "ldk" and middle.kind == "eclair":
        open_channel(middle, sender, push_msat=ECLAIR_PUSH_MSAT)
    else:
        open_channel(sender, middle)
    if middle.kind == "eclair" and receiver.kind == "ldk":
        open_channel(
            middle,
            receiver,
            announce_channel="false",
            channel_type="anchor_outputs_zero_fee_htlc_tx+scid_alias",
        )
    else:
        open_channel(middle, receiver)
    mine(case, 10)

    wait_channels(sender, 1)
    wait_channels(middle, 2)
    wait_channels(receiver, 1)
    wait_graph_channels(sender, 2)

    invoice = create_invoice(receiver, case.name)
    print(f"{case.name}: invoice created", flush=True)
    result = send_payment(sender, invoice)
    print(f"{case.name}: payment result {json.dumps(result)[:500]}", flush=True)
    time.sleep(2)
    verify_sender(sender, nodes)
    print(f"{case.name}: verified sender payload and attribution", flush=True)


def main():
    args = parse_args()
    configure(args)

    require_existing(BITCOIND, "bitcoind")
    require_existing(BITCOIN_CLI, "bitcoin-cli")
    require_existing(LDK_SERVER, "ldk-server")
    require_existing(LDK_CLI, "ldk-server-cli")
    require_existing(ECLAIR_ZIP, "Eclair node zip")
    prepare_dist()

    cases = CASE_MATRIX
    selected = set(args.cases)
    if selected:
        cases = [case for case in cases if case[0] in selected]
    failures = []
    for index, (name, roles) in enumerate(cases):
        case = make_case(name, roles, index)
        try:
            run_case(case)
        except Exception as e:
            failures.append((name, e))
            print(f"{name}: FAILED: {e}", file=sys.stderr, flush=True)
        finally:
            stop_case(case)

    if failures:
        print("\nFailures:", file=sys.stderr)
        for name, err in failures:
            print(f"- {name}: {err}", file=sys.stderr)
        return 1
    print("\nAll interop cases passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
