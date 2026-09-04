# Bamboo

A lightweight, unsupervised network intrusion detection system written in Go. Designed for IoT networks and resource-constrained devices like the Raspberry Pi.

Bamboo uses an ensemble of autoencoders to learn normal network behavior from raw packet captures, then flags anomalies in real time. It requires no labelled training data and no signatures.

## Architecture

```
Packet Capture (gopacket)
    |
    v
Feature Extraction (net_stat.go)
    |  100 damped incremental statistics
    v
Feature Mapper (nn/feature_mapper.go)
    |  Correntropy-based clustering
    v
Autoencoder Ensemble (nn/bamboo.go)
    |  Reconstruction error -> anomaly score
    v
Log-Normal Thresholding
```

## Build

```
go build -o bamboo-nids
```

Requires `libpcap`. On Debian/Ubuntu: `sudo apt install libpcap-dev`.

## Usage

Edit `config.yaml`, then:

```
# Live capture (requires root for raw sockets)
sudo ./bamboo-nids -c config.yaml

# Offline PCAP analysis
./bamboo-nids -c config.yaml
```

## Configuration

All settings are in `config.yaml`.

| Parameter | Description |
|---|---|
| `pcap_path` | Path to a PCAP file. Leave empty for live capture. |
| `interface` | Network interface for live capture (e.g. `eth0`). |
| `bpf_filter` | Optional BPF filter expression (e.g. `ip and not broadcast`). |
| `fm_grace_period` | Packets used to learn feature clustering ($N_{FM}$). |
| `ad_grace_period` | Packets used to train the autoencoder ensemble ($N_{AD}$). |
| `threshold_beta` | Sigma multiplier for the log-normal anomaly threshold ($\beta$). |
| `model_save_path` | Path to save the trained model binary (e.g. `models/bamboo.bin`). |
| `model_load_path` | Path to load a pre-trained model (skips grace periods). |
| `cleanup_interval` | Inactivity decay sweep interval in packets (prevents memory growth). |
| `csv_enabled` | Toggle writing anomaly scores to CSV (`true`/`false`). |
| `test_mode` | Human-readable terminal output instead of JSON. |
| `metrics_enabled` | Expose a Prometheus metrics endpoint. |

## Project Structure

```
main.go          CLI & capture initialization
pipeline.go      NIDS execution pipeline & lifecycle
config.go        YAML config loader
capture.go       Packet parsing (IPv4, IPv6, ICMP, TCP, UDP, ARP)
net_stat.go      Feature extraction & decay memory cleanup
inc_stat.go      Damped incremental statistics (AfterImage)
metrics.go       Prometheus counters/gauges
nn/
  bamboo.go          Hierarchical autoencoder ensemble
  autoencoder.go     Single denoising autoencoder (tied weights)
  feature_mapper.go  Correlation clustering
  persistence.go     Gzip-compressed model serialization
```

## References & Academic Citations

Bamboo's algorithms and design are based on the following research:

1. **KitNET / Kitsune Architecture**:  
   Yisroel Mirsky, Tomer Doitshman, Yuval Elovici, and Asaf Shabtai.  
   *"Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection"*,  
   Proceedings of the Network and Distributed System Security Symposium (**NDSS 2018**). [DOI: 10.14722/ndss.2018.23204](https://doi.org/10.14722/ndss.2018.23204)

2. **Dynamic Learning & Adversarial Evasion Robustness**:  
   Mohamed elShehaby and Ashraf Matrawy.  
   *"Evasion Adversarial Attacks Remain Impractical Against ML-based Network Intrusion Detection Systems, Especially Dynamic Ones"*,  
   arXiv:2306.05494 [cs.CR], March 2026. (Copy archived in [`papers/dynamic_realtime.pdf`](papers/dynamic_realtime.pdf))

For full bibliographic information, Welford's algorithm notes, dataset citations (UNSW-NB15, CSE-CIC-IDS2018), and copy-pasteable BibTeX entries, see [**`REFERENCES.md`**](REFERENCES.md).

## License

MIT
