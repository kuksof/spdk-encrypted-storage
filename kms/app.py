#!/usr/bin/env python3
import argparse
import base64
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from aiohttp import web

try:
	from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
	AESGCM = None
	_AESGCM_IMPORT_ERROR = e

STATE_DEFAULT = Path(__file__).resolve().parent / "kms_state.json"


def _now_ts() -> int:
	return int(time.time())

def _uuid_hex() -> str:
	return uuid.uuid4().hex

def _rand_bytes(n: int) -> bytes:
	return os.urandom(n)

def _b64e(b: bytes) -> str:
	return base64.b64encode(b).decode("ascii")

def _hex(b: bytes) -> str:
	return b.hex()

def _unhex(s: str) -> bytes:
	return bytes.fromhex(s)

def wrap_dek_aes256gcm(dek: bytes, kek: bytes) -> str:
	"""
	Returns base64( IV(12) || TAG(16) || CT )
	"""
	if AESGCM is None:
		raise RuntimeError(f"Install: pip install cryptography")
	if len(kek) != 32:
		raise ValueError("KEK must be 32 bytes for AES-256-GCM")
	iv = _rand_bytes(12)
	aesgcm = AESGCM(kek)
	ct_and_tag = aesgcm.encrypt(iv, dek, None)
	ct = ct_and_tag[:-16]
	tag = ct_and_tag[-16:]
	blob = iv + tag + ct
	return _b64e(blob)

def load_state(path: Path) -> Dict[str, Any]:
	if not path.exists():
		return {"volumes": {}}
	raw = path.read_text("utf-8")
	if not raw.strip():
		return {"volumes": {}}
	return json.loads(raw)

def save_state(path: Path, st: Dict[str, Any]) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	tmp = path.with_suffix(".tmp")
	tmp.write_text(json.dumps(st, indent=2, sort_keys=True), "utf-8")
	os.replace(tmp, path)

def spdk_rpc_unix(sock_path: str, method: str, params: Dict[str, Any], timeout_s: float = 5.0) -> Dict[str, Any]:
	req = {
		"jsonrpc": "2.0",
		"method": method,
		"params": params,
		"id": 1,
	}
	data = (json.dumps(req) + "\n").encode("utf-8")
	s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	s.settimeout(timeout_s)
	try:
		s.connect(sock_path)
		s.sendall(data)
		buf = b""
		while b"\n" not in buf:
			chunk = s.recv(4096)
			if not chunk:
				break
			buf += chunk
		line = buf.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
		if not line:
			raise RuntimeError("empty response from SPDK RPC")
		resp = json.loads(line)
		return resp
	finally:
		try:
			s.close()
		except Exception:
			pass

@dataclass
class Volume:
	volume_id: str
	dek1_hex: str
	dek2_hex: str
	kek_hex: str
	wrapped_key: str
	wrapped_key2: str
	created_at: int
	updated_at: int

	def public(self) -> Dict[str, Any]:
		return {
			"volume_id": self.volume_id,
			"kek_hex": self.kek_hex,
			"wrapped_key": self.wrapped_key,
			"wrapped_key2": self.wrapped_key2,
			"updated_at": self.updated_at,
			"created_at": self.created_at,
		}

def volume_from_state(d: Dict[str, Any]) -> Volume:
	return Volume(
		volume_id=d["volume_id"],
		dek1_hex=d["dek1_hex"],
		dek2_hex=d["dek2_hex"],
		kek_hex=d["kek_hex"],
		wrapped_key=d["wrapped_key"],
		wrapped_key2=d["wrapped_key2"],
		created_at=d["created_at"],
		updated_at=d["updated_at"],
	)

def volume_to_state(v: Volume) -> Dict[str, Any]:
	return {
		"volume_id": v.volume_id,
		"dek1_hex": v.dek1_hex,
		"dek2_hex": v.dek2_hex,
		"kek_hex": v.kek_hex,
		"wrapped_key": v.wrapped_key,
		"wrapped_key2": v.wrapped_key2,
		"created_at": v.created_at,
		"updated_at": v.updated_at,
	}

async def health(_: web.Request) -> web.Response:
	return web.json_response({"alive": True})

async def create_volume(req: web.Request) -> web.Response:
	app = req.app
	state_path: Path = app["state_path"]
	_ = await req.json() if req.can_read_body else {}
	st = load_state(state_path)
	volume_id = _uuid_hex()
	dek1 = _rand_bytes(32)  # XTS part 1
	dek2 = _rand_bytes(32)  # XTS part 2
	kek = _rand_bytes(32)   # KEK for wrapping
	wrapped1 = wrap_dek_aes256gcm(dek1, kek)
	wrapped2 = wrap_dek_aes256gcm(dek2, kek)
	now = _now_ts()
	v = Volume(
		volume_id=volume_id,
		dek1_hex=_hex(dek1),
		dek2_hex=_hex(dek2),
		kek_hex=_hex(kek),
		wrapped_key=wrapped1,
		wrapped_key2=wrapped2,
		created_at=now,
		updated_at=now,
	)
	st.setdefault("volumes", {})
	st["volumes"][volume_id] = volume_to_state(v)
	save_state(state_path, st)
	return web.json_response({"ok": True, **v.public()})

async def get_volume(req: web.Request) -> web.Response:
	app = req.app
	state_path: Path = app["state_path"]
	vid = req.match_info["volume_id"]
	st = load_state(state_path)
	d = st.get("volumes", {}).get(vid)
	if not d:
		return web.json_response({"ok": False, "error": "volume not found"}, status=404)

async def rekey_volume(req: web.Request) -> web.Response:
	app = req.app
	state_path: Path = app["state_path"]
	vid = req.match_info["volume_id"]
	body = await req.json() if req.can_read_body else {}
	apply_spdk = bool(body.get("apply_spdk", False))
	spdk_sock = body.get("spdk_sock") or app["spdk_sock"]
	crypto_bdev_name = body.get("crypto_bdev_name")
	st = load_state(state_path)
	d = st.get("volumes", {}).get(vid)
	if not d:
		return web.json_response({"ok": False, "error": "volume not found"}, status=404)
	v = volume_from_state(d)
	dek1 = _unhex(v.dek1_hex)
	dek2 = _unhex(v.dek2_hex)
	new_kek = _rand_bytes(32)
	new_wrapped1 = wrap_dek_aes256gcm(dek1, new_kek)
	new_wrapped2 = wrap_dek_aes256gcm(dek2, new_kek)
	v.kek_hex = _hex(new_kek)
	v.wrapped_key = new_wrapped1
	v.wrapped_key2 = new_wrapped2
	v.updated_at = _now_ts()
	st["volumes"][vid] = volume_to_state(v)
	save_state(state_path, st)
	spdk_resp: Optional[Dict[str, Any]] = None
	if apply_spdk:
		if not crypto_bdev_name:
			return web.json_response(
				{"ok": False, "error": "crypto_bdev_name is required when apply_spdk=true"},
				status=400,
			)
		try:
			spdk_resp = spdk_rpc_unix(
				spdk_sock,
				"bdev_crypto_update_wrapped_keys",
				{
					"name": crypto_bdev_name,
					"kek_hex": v.kek_hex,
					"wrapped_key": v.wrapped_key,
					"wrapped_key2": v.wrapped_key2,
				},
			)
			if "error" in spdk_resp:
				return web.json_response(
					{
						"ok": False,
						"error": "spdk rpc returned error",
						"spdk": spdk_resp,
						**v.public(),
					},
					status=500,
				)
		except Exception as e:
			return web.json_response(
				{"ok": False, "error": f"failed to call spdk rpc: {e}", **v.public()},
				status=500,
			)
	resp = {"ok": True, **v.public()}
	if spdk_resp is not None:
		resp["spdk"] = spdk_resp
	return web.json_response(resp)

def make_app(state_path: Path, spdk_sock: str) -> web.Application:
	app = web.Application()
	app["state_path"] = state_path
	app["spdk_sock"] = spdk_sock
	app.router.add_get("/health", health)
	app.router.add_post("/v1/volumes", create_volume)
	app.router.add_get("/v1/volumes/{volume_id}", get_volume)
	app.router.add_post("/v1/volumes/{volume_id}/rekey", rekey_volume)
	return app

def main() -> None:
	p = argparse.ArgumentParser()
	p.add_argument("--listen", default="127.0.0.1")
	p.add_argument("--port", type=int, default=8080)
	p.add_argument("--state", default=str(STATE_DEFAULT))
	p.add_argument("--spdk-sock", default="/var/tmp/spdk.sock")
	args = p.parse_args()
	app = make_app(Path(args.state), args.spdk_sock)
	web.run_app(app, host=args.listen, port=args.port)

if __name__ == "__main__":
	main()
