# SPDK Encrypted Storage (Prototype)

Prototype of NVMe-oF target with SPDK `bdev_crypto` (AES-XTS) and a simple KMS service that issues Data Encryption Keys (DEKs).

> Tested on Ubuntu/Debian (uses `apt` in install script).

## Prerequisites
- Linux host with sudo
- `git`
- Python 3
- `nvme-cli`
- `fio`

## Build / Setup

### Clone repository and init submodules:
```bash
git clone <REPO_URL>
cd spdk-encrypted-storage
git submodule update --init --recursive
```

### Build SPDK and install dependencies:
```bash
./scripts/install_spdk.sh
```

### Run demo

1. Start KMS
```bash
cd kms
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py --listen 127.0.0.1 --port 8080 --spdk-sock /var/tmp/spdk.sock
```
KMS should be available at http://127.0.0.1:8080.

2. Generate SPDK config from KMS
```bash
python3 kms/gen_spdk_config.py create \
  --kms-url http://127.0.0.1:8080 \
  --out spdk-configs/crypto.json
```

3. Run SPDK NVMe-oF target
```bash
sudo ./scripts/run_spdk.sh spdk-configs/crypto.json
```

4. Connect as NVMe-oF initiator
In a new terminal:
```bash
sudo nvme connect -t tcp -a 127.0.0.1 -s 4420 -n nqn.2016-06.io.spdk:cnode1

sudo nvme list
```
Identify the created namespace device (e.g. /dev/nvme0n1)

5. Test I/O with fio
Replace /dev/nvme0n1 with your actual device from nvme list:
```bash
sudo fio --name=crypto_test \
  --filename=/dev/nvme0n1 \
  --rw=randwrite \
  --bs=4k \
  --iodepth=32 \
  --numjobs=1 \
  --time_based=1 \
  --runtime=60 \
  --ioengine=libaio \
  --direct=1
```

rekey:
Replace <VOLUME_ID_FROM_CREATE> with your actual volume id 2nd step:
```bash
python3 kms/gen_spdk_config.py rekey \
  --kms-url http://127.0.0.1:8080 \
  --volume-id <VOLUME_ID_FROM_CREATE> \
  --apply-spdk \
  --spdk-sock /var/tmp/spdk.sock \
  --crypto-bdev-name Crypto0
```

### Cleanup
1. Disconnect NVMe-oF:
```bash
sudo nvme disconnect -n nqn.2016-06.io.spdk:cnode1
```

2. Stop SPDK target (Ctrl+C in its terminal) and stop KMS (Ctrl+C).
