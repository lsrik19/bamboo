# Evaluation Report: IoT Malfunction / DNS Storm (`18-10-28.pcap`)

## 1. Overview & Execution Parameters

- **Dataset**: `pcaps/18-10-28.pcap` (UNSW Sydney IoT Testbed, 2018-10-28)
- **Traffic Nature**: Labeled benign trace containing a real-world IoT device malfunction (DNS flood storm)
- **Total Packets in PCAP**: 7,720,905 (Execution interrupted at packet 3,976,748)
- **Feature Mapper Grace ($N_{FM}$)**: 50,000 packets
- **Anomaly Detector Grace ($N_{AD}$)**: 500,000 packets
- **Threshold Multiplier ($\beta$)**: 4.0
- **Learned Threshold ($T$)**: `0.112420`
- **Execution Packets Scored (Sampled)**: 3,206,379
- **Anomalies Flagged**: 2,826,224 (**88.14%** of execution traffic)
- **Maximum Anomaly Score**: `1,590,954.67`

---

## 2. Packet Progression & Root Cause Timeline

| Packet Range | Traffic Phase | Alert % | Avg Anomaly Score | Traffic Profile |
| :--- | :--- | :--- | :--- | :--- |
| **`600k – 800k`** | **Normal Baseline** | **4.84%** | **0.0208** | IoT background traffic; scores well below threshold (`0.112`) |
| **`800k – 1.0M`** | **Normal Baseline** | **5.95%** | **0.0220** | Steady IoT polling and telemetry |
| **`1.0M – 1.2M`** | **Storm Onset** | **51.63%** | **1.1192** | Glitch begins at packet ~1,100,000 (`00:27:01 UTC`) |
| **`1.2M – 4.0M`** | **Active Storm** | **98.1% – 98.2%** | **12.3 – 21.9** | Millions of rapid DNS queries to the local gateway |

---

## 3. Incident Forensics: The SmartThings DNS Storm

### Device Identification
- **Device IP**: `192.168.1.196`
- **MAC Address**: `d0:52:a8:00:67:5e` (OUI: Samsung SmartThings Inc.)
- **Gateway / Resolver**: `192.168.1.1:53`

### The Malfunction Lifecycle
1. **Normal Behavior (Packets 1 – 1,050,000):**
   - The SmartThings Hub transmitted standard background telemetry and time-sync queries once every 10 minutes (`18:37, 18:47, 18:57, 19:07...` querying `pool.ntp.org`).
   - Bamboo completed training ($N_{FM} = 50k, N_{AD} = 500k$) on this calm baseline, calculating a threshold of `0.1124`.
2. **Failure Event at `00:27:01 UTC` (Timestamp `1540686421`):**
   - The hub encountered an internal connectivity/resolution failure and entered an aggressive, unthrottled retry loop.
   - It began transmitting between **1,700 and 2,000 UDP DNS queries per second** to the gateway, rapidly cycling ephemeral source ports (`6098, 6099, 6100, 6101...`):
     ```text
     1100000  00:27:01.629  192.168.1.1:53   -> 192.168.1.196:6098  UDP
     1100001  00:27:01.630  192.168.1.196:6099 -> 192.168.1.1:53   UDP
     1100002  00:27:01.630  192.168.1.1:53   -> 192.168.1.196:6099  UDP
     1100003  00:27:01.631  192.168.1.196:6100 -> 192.168.1.1:53   UDP
     ```
   - In 58 seconds (packets 1.1M to 1.2M), over **100,000 UDP packets** were exchanged. This pattern persisted for millions of packets.

---

## 4. NIDS Behavioral Analysis & Insights

1. **Why Unsupervised NIDS Flagged "Benign" Data:**
   - Although UNSW marked this day as benign, Bamboo correctly detected a massive physical behavioral anomaly. A 1,000x surge in packet rate and jitter between an IoT hub and the gateway is indistinguishable from a DNS amplification flood or denial-of-service attack.
2. **Grace Period Considerations ($N_{AD}$):**
   - **Baseline Detection Mode ($N_{AD} = 500,000$):** Catches the glitch immediately at packet 1.1M.
   - **Noise-Tolerant Mode ($N_{AD} \ge 2,000,000$):** If an operator wants the model to accept such storms as normal, the training window must encompass the incident to prevent false alarms.

---

## 5. References

1. **UNSW Sydney IoT Traffic Repository**:
   - A. Sivanathan, H. H. Gharakheili, F. Loi, A. Radford, C. Xiang, and V. Sivaraman, *"Classifying IoT Devices in Smart Environments Using Network Traffic Characteristics"*, IEEE Transactions on Mobile Computing (TMC), 18(8):1745–1759, 2018.
2. **Kitsune / KitNET Architecture**:
   - Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, *"Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection"*, Proceedings of the Network and Distributed System Security Symposium (**NDSS 2018**). [DOI: 10.14722/ndss.2018.23204](https://doi.org/10.14722/ndss.2018.23204).
3. **Dynamic ML & Evasion Practicality**:
   - M. elShehaby and A. Matrawy, *"Evasion Adversarial Attacks Remain Impractical Against ML-based Network Intrusion Detection Systems, Especially Dynamic Ones"*, [arXiv:2306.05494](https://arxiv.org/abs/2306.05494), March 2026.

*For complete BibTeX entries and foundational algorithm notes, see [**`REFERENCES.md`**](../REFERENCES.md).*
