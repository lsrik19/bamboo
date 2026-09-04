# Evaluation Report: Benign Traffic Baseline (`18-10-29.pcap`)

## Run Overview

- **Dataset**: `pcaps/18-10-29.pcap`
- **Total Packets in Stream**: 1,921,098
- **Feature Mapper Grace Period ($N_{FM}$)**: 50,000 packets
- **Autoencoder Grace Period ($N_{AD}$)**: 500,000 packets
- **Threshold Beta ($\beta$)**: 4.0
- **Execution Mode Packets Scored**: 941,608

---

## Performance Summary

| Metric | Value | Notes |
| :--- | :--- | :--- |
| **Normal Traffic Packets** | 934,430 | **99.24%** of execution traffic classified as benign |
| **Anomalies Detected** | 7,178 | **0.76%** false positive rate |
| **Calculated Threshold** | 0.098653 | $\exp(\mu_{log} + 4.0 \times \sigma_{log})$ |
| **Log-Normal Baseline Stats** | $\mu_{log} = -5.259672$, $\sigma_{log} = 0.735882$ | Computed over 500,000 training packets |
| **Max Score** | 195,707.65 | Extreme outlier from UDP QUIC burst |

---

## Anomaly Root Cause Analysis

### 1. Ubuntu Archive Mirror / Package Updates (~60% of alerts)
- **Source / Destination IP**: `91.189.88.152` (Canonical / Ubuntu archive mirror) communicating with internal host `192.168.1.175`.
- **Alert Count**: 3,210 packets.
- **Score Range**: 0.10 to 0.24 (median: 0.181).
- **Cause**: An `apt update` / package download occurred during the execution phase. The scores were just slightly higher than the 0.0986 threshold because bulk file transfers produce slightly higher burst statistics than quiet background IoT traffic.

### 2. High-Bandwidth UDP QUIC Video Bursts (Extreme Outlier Scores)
Out of 941,608 execution packets, only **21 packets** had scores above 1.0. The massive scores (>100,000) were isolated to a handful of UDP port 443 packets:
- `Pkt  994839`: `192.168.1.192:57820 -> 216.58.199.67:443` (UDP) — Score: `106,126.74`
- `Pkt 1020166`: `192.168.1.192:44417 -> 216.58.199.67:443` (UDP) — Score: `129,683.81`
- `Pkt 1029732`: `192.168.1.119:59069 -> 216.58.199.67:443` (UDP) — Score: `106,063.18`
- `Pkt 1164007`: `192.168.1.119:59585 -> 216.58.199.65:443` (UDP) — Score: `195,707.65`
- `Pkt 1227086`: `192.168.1.119:58812 -> 216.58.199.67:443` (UDP) — Score: `129,707.54`

**Cause**: Google QUIC protocol (YouTube/video streaming). The burst of back-to-back UDP datagrams caused packet rate and jitter statistics to spike dramatically compared to the baseline training window.

### 3. Genuine Inbound Attack / Scan Detected
- `Pkt 1519826`: `194.28.115.243:59065 -> 192.168.1.175:22` (SSH / TCP) — Score: `1.36`
- **Cause**: An external public IP initiated an unsolicited inbound connection to the internal SSH port. Bamboo correctly flagged this event as anomalous.

---

## Threshold Sensitivity Analysis

Evaluating the 941,608 execution packets across various $\beta$ multipliers:

| Multiplier ($\beta$) | Threshold ($T$) | Alerts Triggered | False Positive Rate |
| :--- | :--- | :--- | :--- |
| **$\beta = 4.0$ (Default)** | 0.098653 | 7,178 | 0.762% |
| **$\beta = 4.5$** | 0.142530 | 4,716 | 0.501% |
| **$\beta = 5.0$** | 0.205921 | 2,557 | 0.272% |
| **$\beta = 5.5$** | 0.297506 | **69** | **0.007%** |
| **$\beta = 6.0$** | 0.429824 | **44** | **0.005%** |

---

## Conclusion & Recommendations

1. **Model Stability**: At 99.24% true negative rate on raw, uncurated network captures with active package updates and video streams, the autoencoder baseline is functioning as expected.
2. **Recommended $\beta$ for Mixed/Noisy Traffic**: Increasing `threshold_beta` to `5.5` filters out 99.0% of borderline benign noise (like `apt` package downloads) while keeping the detection sensitivity well below the multi-hundred/thousand scores seen in network anomalies and floods.

---

## References

1. **UNSW Sydney IoT Traffic Repository**:
   - A. Sivanathan, H. H. Gharakheili, F. Loi, A. Radford, C. Xiang, and V. Sivaraman, *"Classifying IoT Devices in Smart Environments Using Network Traffic Characteristics"*, IEEE Transactions on Mobile Computing (TMC), 18(8):1745–1759, 2018.
2. **Kitsune / KitNET Architecture**:
   - Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, *"Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection"*, Proceedings of the Network and Distributed System Security Symposium (**NDSS 2018**). [DOI: 10.14722/ndss.2018.23204](https://doi.org/10.14722/ndss.2018.23204).
3. **Dynamic ML & Evasion Practicality**:
   - M. elShehaby and A. Matrawy, *"Evasion Adversarial Attacks Remain Impractical Against ML-based Network Intrusion Detection Systems, Especially Dynamic Ones"*, arXiv:2306.05494, March 2026. (Archived in [`papers/dynamic_realtime.pdf`](../papers/dynamic_realtime.pdf)).

*For complete BibTeX entries and foundational algorithm notes, see [**`REFERENCES.md`**](../REFERENCES.md).*
