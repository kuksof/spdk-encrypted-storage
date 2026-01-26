#!/usr/bin/env python3
import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional


def http_json(method: str, url: str, payload: Optional[Dict[str, Any]] = None, timeout_s: float = 5.0) -> Dict[str, Any]:
	data = None
	headers = {"Content-Type": "application/json"}
	if payload is not None:
		data = json.dumps(payload).encode("utf-8")
	req = urllib.request.Request(url=url, data=data, headers=headers, method=method)
	with urllib.request.urlopen(req, timeout=timeout_s) as resp:
		body = resp.read().decode("utf-8")
		return json.loads(body)

def build_spdk_config(
	dev_name: str,
	malloc_size_mb: int,
	crypto_name: str,
	cipher: str,
	kek_hex: str,
	wrapped_key: str,
	wrapped_key2: str,
	with_nvmf: bool,
	nqn: str,
	trtype: str,
	traddr: str,
	trsvcid: str,
) -> Dict[str, Any]:
	subsystems = []
	bdev_cfg = []
	bdev_cfg.append({
		"method": "bdev_aio_create",
		"params": {
			"name": dev_name,
			"filename": "/dev/vda",
			"block_size": 512
		}
	})
	bdev_cfg.append({
		"method": "bdev_crypto_create",
		"params": {
			"base_bdev_name": dev_name,
			"name": crypto_name,
			"cipher": cipher,
			"wrapped_key": wrapped_key,
			"wrapped_key2": wrapped_key2,
			"kek_hex": kek_hex,
		}
	})
	subsystems.append({"subsystem": "bdev", "config": bdev_cfg})
	if with_nvmf:
		nvmf_cfg = []
		nvmf_cfg.append({
			"method": "nvmf_create_transport",
			"params": {
				"trtype": trtype
			}
		})
		nvmf_cfg.append({
			"method": "nvmf_create_subsystem",
			"params": {
				"nqn": nqn,
				"allow_any_host": True
			}
		})
		nvmf_cfg.append({
			"method": "nvmf_subsystem_add_listener",
			"params": {
				"nqn": nqn,
				"listen_address": {
					"trtype": trtype,
					"traddr": traddr,
					"trsvcid": trsvcid
				}
			}
		})
		nvmf_cfg.append({
			"method": "nvmf_subsystem_add_ns",
			"params": {
				"nqn": nqn,
				"namespace": {
					"bdev_name": crypto_name
				}
			}
		})
		subsystems.append({"subsystem": "nvmf", "config": nvmf_cfg})
	return {"subsystems": subsystems}

def cmd_create(args: argparse.Namespace) -> None:
	kms_url = args.kms_url.rstrip("/")
	out_path = Path(args.out)
	r = http_json("POST", f"{kms_url}/v1/volumes", payload={})
	if not r.get("ok"):
		raise SystemExit(f"KMS error: {r}")
	volume_id = r["volume_id"]
	kek_hex = r["kek_hex"]
	wrapped_key = r["wrapped_key"]
	wrapped_key2 = r["wrapped_key2"]
	cfg = build_spdk_config(
		dev_name=args.dev_name,
		malloc_size_mb=args.malloc_size_mb,
		crypto_name=args.crypto_name,
		cipher=args.cipher,
		kek_hex=kek_hex,
		wrapped_key=wrapped_key,
		wrapped_key2=wrapped_key2,
		with_nvmf=not args.no_nvmf,
		nqn=args.nqn,
		trtype=args.trtype,
		traddr=args.traddr,
		trsvcid=args.trsvcid,
	)
	out_path.parent.mkdir(parents=True, exist_ok=True)
	out_path.write_text(json.dumps(cfg, indent=2), "utf-8")
	print("OK")
	print(f"volume_id={volume_id}")
	print(f"wrote={out_path}")
	if args.print_secrets:
		print(f"kek_hex={kek_hex}")
		print(f"wrapped_key={wrapped_key}")
		print(f"wrapped_key2={wrapped_key2}")

def cmd_rekey(args: argparse.Namespace) -> None:
	kms_url = args.kms_url.rstrip("/")
	payload = {
		"apply_spdk": bool(args.apply_spdk),
		"spdk_sock": args.spdk_sock,
		"crypto_bdev_name": args.crypto_bdev_name,
	}
	r = http_json("POST", f"{kms_url}/v1/volumes/{args.volume_id}/rekey", payload=payload)
	if not r.get("ok"):
		raise SystemExit(f"rekey failed: {r}")
	print("OK")
	print(f"volume_id={r['volume_id']}")
	print(f"updated_at={r['updated_at']}")
	if args.print_secrets:
		print(f"kek_hex={r['kek_hex']}")
		print(f"wrapped_key={r['wrapped_key']}")
		print(f"wrapped_key2={r['wrapped_key2']}")
	if "spdk" in r:
		print("spdk=", json.dumps(r["spdk"], indent=2))

def main() -> None:
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest="cmd", required=True)
	c = sub.add_parser("create", help="Create new volume in KMS and write SPDK JSON config")
	c.add_argument("--kms-url", required=True)
	c.add_argument("--out", required=True)
	c.add_argument("--dev-name", default="Malloc0")
	c.add_argument("--malloc-size-mb", type=int, default=64)
	c.add_argument("--crypto-name", default="Crypto0")
	c.add_argument("--cipher", default="AES_XTS")
	c.add_argument("--no-nvmf", action="store_true")
	c.add_argument("--nqn", default="nqn.2016-06.io.spdk:cnode1")
	c.add_argument("--trtype", default="tcp")
	c.add_argument("--traddr", default="127.0.0.1")
	c.add_argument("--trsvcid", default="4420")
	c.add_argument("--print-secrets", action="store_true")
	c.set_defaults(fn=cmd_create)
	r = sub.add_parser("rekey", help="Rotate KEK (rewrap same DEK). Optionally apply to SPDK via RPC.")
	r.add_argument("--kms-url", required=True)
	r.add_argument("--volume-id", required=True)
	r.add_argument("--apply-spdk", action="store_true")
	r.add_argument("--spdk-sock", default="/var/tmp/spdk.sock")
	r.add_argument("--crypto-bdev-name", default="Crypto0")
	r.add_argument("--print-secrets", action="store_true")
	r.set_defaults(fn=cmd_rekey)
	args = p.parse_args()
	args.fn(args)

if __name__ == "__main__":
	main()
