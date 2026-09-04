# Academic References & Theoretical Foundations

This document provides academic citations, theoretical backgrounds, and BibTeX entries for the research literature and datasets upon which **Bamboo NIDS** is built.

---

## 1. Primary Foundational Literature

### 1.1 KitNET / Kitsune Architecture
* **Paper:** *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*
* **Authors:** Yisroel Mirsky, Tomer Doitshman, Yuval Elovici, and Asaf Shabtai
* **Venue:** Network and Distributed System Security Symposium (NDSS 2018)
* **DOI:** [10.14722/ndss.2018.23204](https://doi.org/10.14722/ndss.2018.23204)
* **Relevance:**
  * **Feature Extraction (AfterImage):** Defines the damped incremental statistics framework across decay factors $\lambda \in \{5.0, 3.0, 1.0, 0.1, 0.01\}$ implemented in [`inc_stat.go`](inc_stat.go) and [`net_stat.go`](net_stat.go).
  * **Feature Mapper:** Defines the online correlation tracking via Welford's multivariate residual products and bounded agglomerative clustering ($k \le m$) implemented in [`nn/feature_mapper.go`](nn/feature_mapper.go).
  * **Ensemble Anomaly Detector:** Defines the two-tier hierarchical autoencoder architecture ($K$ ensemble autoencoders in L1, 1 aggregator autoencoder in L2) with tied weights ($W' = W^T$) and log-normal thresholding implemented in [`nn/autoencoder.go`](nn/autoencoder.go) and [`nn/bamboo.go`](nn/bamboo.go).

### 1.2 Dynamic Learning & Adversarial Evasion Robustness
* **Paper:** *Evasion Adversarial Attacks Remain Impractical Against ML-based Network Intrusion Detection Systems, Especially Dynamic Ones*
* **Authors:** Mohamed elShehaby and Ashraf Matrawy
* **Preprint:** [arXiv:2306.05494 [cs.CR]](https://arxiv.org/abs/2306.05494), March 2026
* **Relevance:**
  * Establishes the real-world practicality gap between computer vision adversarial perturbations and network security constraints (the *Inverse Feature-Mapping Problem*, collateral/side-effect features, and protocol adherence).
  * Demonstrates empirically that continuous re-training and dynamic learning naturally neutralize static gradient-based evasion attacks (e.g., FGSM, PGD, BIM) as decision boundaries shift over time.
  * Informs Bamboo's design for streaming, real-time adaptation and persistent model checkpointing ([`nn/persistence.go`](nn/persistence.go)).

---

## 2. Algorithmic Foundations

### 2.1 Online Incremental Variance and Covariance
* **Paper:** *Note on a Method for Calculating Corrected Sums of Squares and Products*
* **Author:** B. P. Welford
* **Journal:** *Technometrics*, 4(3):419–420, 1962
* **Relevance:** Provides the numerically stable online one-pass recurrence relations for running mean, variance, and cross-residual products implemented in [`inc_stat.go`](inc_stat.go) and [`nn/feature_mapper.go`](nn/feature_mapper.go).

### 2.2 Denoising Autoencoders with Tied Weights
* **Paper:** *Extracting and Composing Robust Features with Denoising Autoencoders*
* **Authors:** Pascal Vincent, Hugo Larochelle, Yoshua Bengio, and Pierre-Antoine Manzagol
* **Venue:** Proceedings of the 25th International Conference on Machine Learning (ICML 2008)
* **DOI:** [10.1145/1390156.1390294](https://doi.org/10.1145/1390156.1390294)
* **Relevance:** Foundation for the tied-weight ($W_{decode} = W_{encode}^T$) visible-hidden bottleneck autoencoder architecture with online stochastic gradient descent (SGD) used in [`nn/autoencoder.go`](nn/autoencoder.go).

---

## 3. Evaluation & Benchmark Datasets

### 3.1 UNSW-NB15 & UNSW IoT Network Traffic
* **Paper:** *UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems (UNSW-NB15 Network Data Set)*
* **Authors:** Nour Moustafa and Jill Slay
* **Venue:** 2015 Military Communications and Information Systems Conference (MilCIS 2015)
* **DOI:** [10.1109/MilCIS.2015.7348942](https://doi.org/10.1109/MilCIS.2015.7348942)
* **Relevance:** Used as the benign baseline and attack evaluation PCAPs (`pcaps/18-10-23.pcap`, `pcaps/18-10-29.pcap`) for validating detection rate, false positives, and log-normal threshold stability.

### 3.2 CSE-CIC-IDS2018
* **Paper:** *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*
* **Authors:** Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani
* **Venue:** Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018)
* **DOI:** [10.5220/0006639801080116](https://doi.org/10.5220/0006639801080116)
* **Relevance:** Primary multi-day dataset analyzed by elShehaby & Matrawy ([arXiv:2306.05494](https://arxiv.org/abs/2306.05494)) to demonstrate how daily retraining mitigates adversarial evasion.

---

## 4. Code Traceability Matrix

| Source File | Component | Academic Foundation |
| :--- | :--- | :--- |
| [`inc_stat.go`](inc_stat.go) | `IncStat`, `IncStatCov` | AfterImage exponential damping (Mirsky et al., 2018) & Welford (1962) |
| [`net_stat.go`](net_stat.go) | 100-dim Feature Extraction & Cleanup | 5-context multi-scale extraction (Mirsky et al., 2018) |
| [`nn/feature_mapper.go`](nn/feature_mapper.go) | Online Clustering | Welford correlation distances & bounded agglomeration ($m \le 10$) |
| [`nn/autoencoder.go`](nn/autoencoder.go) | Single Autoencoder | Tied-weight denoising dA (Vincent et al., 2008; Mirsky et al., 2018) |
| [`nn/bamboo.go`](nn/bamboo.go) | Ensemble & Log-Normal Threshold | KitNET hierarchical ensemble & log-normal stats ($\mu + \beta\sigma$) |
| [`nn/persistence.go`](nn/persistence.go) | Model Save / Load | Dynamic model persistence to prevent blind retraining (elShehaby & Matrawy, 2026) |
| [`capture.go`](capture.go) | Packet Parsing & IPv6 | Problem-space network protocol conformance (Pierazzi et al., 2020) |

---

## 5. BibTeX Citations

```bibtex
@inproceedings{mirsky2018kitsune,
  author    = {Yisroel Mirsky and Tomer Doitshman and Yuval Elovici and Asaf Shabtai},
  title     = {Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection},
  booktitle = {Proceedings of the Network and Distributed System Security Symposium (NDSS)},
  year      = {2018},
  doi       = {10.14722/ndss.2018.23204}
}

@article{elshehaby2026evasion,
  author        = {Mohamed elShehaby and Ashraf Matrawy},
  title         = {Evasion Adversarial Attacks Remain Impractical Against {ML}-based Network Intrusion Detection Systems, Especially Dynamic Ones},
  journal       = {arXiv preprint arXiv:2306.05494},
  year          = {2026},
  eprint        = {2306.05494},
  archiveprefix = {arXiv},
  primaryclass  = {cs.CR}
}

@inproceedings{vincent2008extracting,
  author    = {Pascal Vincent and Hugo Larochelle and Yoshua Bengio and Pierre-Antoine Manzagol},
  title     = {Extracting and Composing Robust Features with Denoising Autoencoders},
  booktitle = {Proceedings of the 25th International Conference on Machine Learning (ICML)},
  pages     = {1096--1103},
  year      = {2008},
  doi       = {10.1145/1390156.1390294}
}

@article{welford1962note,
  author  = {B. P. Welford},
  title   = {Note on a Method for Calculating Corrected Sums of Squares and Products},
  journal = {Technometrics},
  volume  = {4},
  number  = {3},
  pages   = {419--420},
  year    = {1962},
  doi     = {10.1080/00401706.1962.10490022}
}

@inproceedings{moustafa2015unsw,
  author    = {Nour Moustafa and Jill Slay},
  title     = {{UNSW-NB15}: A Comprehensive Data Set for Network Intrusion Detection Systems},
  booktitle = {2015 Military Communications and Information Systems Conference (MilCIS)},
  pages     = {1--6},
  year      = {2015},
  doi       = {10.1109/MilCIS.2015.7348942}
}

@inproceedings{sharafaldin2018toward,
  author    = {Iman Sharafaldin and Arash Habibi Lashkari and Ali A. Ghorbani},
  title     = {Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization},
  booktitle = {Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)},
  pages     = {108--116},
  year      = {2018},
  doi       = {10.5220/0006639801080116}
}
```
