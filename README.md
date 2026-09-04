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
| `fm_grace_period` | Packets used to learn feature clustering. |
| `ad_grace_period` | Packets used to train the autoencoder ensemble. |
| `threshold_beta` | Sigma multiplier for the log-normal anomaly threshold. |
| `test_mode` | Human-readable terminal output instead of JSON. |
| `metrics_enabled` | Expose a Prometheus metrics endpoint. |

## Project Structure

```
main.go          Pipeline orchestration
config.go        YAML config loader
capture.go       Packet parsing
net_stat.go      Feature extraction (zero-allocation struct keys)
inc_stat.go      Damped incremental statistics
metrics.go       Prometheus counters/gauges
nn/
  bamboo.go      Autoencoder ensemble (pre-allocated inference)
  autoencoder.go Single autoencoder (forward/backward)
  feature_mapper.go  Correntropy clustering
```

## License

MIT
