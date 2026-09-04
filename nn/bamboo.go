package nn

import (
	"log/slog"
	"math"
)

// Bamboo represents the two-layer autoencoder anomaly detection system
type Bamboo struct {
	HiddenRatio float64 // Inner compression ratio beta (e.g. 0.75)
	LR          float64 // Learning rate eta (e.g. 0.1)
	GracePeriod int     // N_AD: number of clean packets to train autoencoders

	EnsembleLayer []*Autoencoder // L1: k autoencoders
	OutputLayer   *Autoencoder   // L2: aggregate autoencoder
	K             int            // Number of clusters / autoencoders
	RmseBuffer    []float64      // Zero-allocation buffer for Process()

	Count         int
	MaxRMSE       float64 // Maximum clean RMSE recorded (phi) — kept for diagnostics
	ThresholdBeta float64 // Sigma multiplier for threshold: T = mean + beta * sigma

	// Training RMSE distribution tracking (robust to contamination)
	TrainRMSESum float64 // Sum of training RMSEs
	TrainRMSESS  float64 // Sum of squared training RMSEs
	Threshold    float64 // Final computed threshold
	IsTrained    bool
}

// NewBamboo creates a Bamboo instance
func NewBamboo(gracePeriod int, thresholdBeta float64) *Bamboo {
	return &Bamboo{
		HiddenRatio:   0.75,
		LR:            0.1,
		GracePeriod:   gracePeriod,
		ThresholdBeta: thresholdBeta,
		Count:         0,
		MaxRMSE:       0.0,
		IsTrained:     false,
	}
}

// InitEnsemble builds the neural architecture once FeatureMapper produces the cluster mapping
func (kn *Bamboo) InitEnsemble(clusters [][]int) {
	kn.K = len(clusters)
	kn.EnsembleLayer = make([]*Autoencoder, kn.K)
	kn.RmseBuffer = make([]float64, kn.K)

	for i, cluster := range clusters {
		dim := len(cluster)
		kn.EnsembleLayer[i] = NewAutoencoder(dim, kn.HiddenRatio, kn.LR)
	}

	// Output layer autoencoder takes k inputs (the RMSEs of L1)
	kn.OutputLayer = NewAutoencoder(kn.K, kn.HiddenRatio, kn.LR)
	slog.Info("Bamboo ensemble initialized", "ensemble_count", kn.K, "output_layer", 1)
}

// InitBuffers initializes transient scratch buffers for Bamboo and its autoencoders
func (kn *Bamboo) InitBuffers() {
	kn.RmseBuffer = make([]float64, kn.K)
	for _, ae := range kn.EnsembleLayer {
		if ae != nil {
			ae.InitScratchBuffers()
		}
	}
	if kn.OutputLayer != nil {
		kn.OutputLayer.InitScratchBuffers()
	}
}

// Process evaluates a partitioned sub-instance vector v = {v1, ..., vk}
// Returns: (finalAnomalyScore S, isAlert, isTrainingPhase)
func (kn *Bamboo) Process(v [][]float64) (float64, bool, bool) {
	if kn.EnsembleLayer == nil {
		return 0.0, false, true
	}

	kn.Count++

	// Train Mode (AD Grace Period)
	if kn.Count <= kn.GracePeriod {
		// Train each L1 autoencoder on its respective sub-instance v_i
		for i := 0; i < kn.K; i++ {
			kn.RmseBuffer[i] = kn.EnsembleLayer[i].TrainStep(v[i])
		}

		// Train L2 output autoencoder on the ensemble RMSE vector
		outRMSE := kn.OutputLayer.TrainStep(kn.RmseBuffer)

		// Track training RMSE statistics for robust threshold computation
		if outRMSE > kn.MaxRMSE {
			kn.MaxRMSE = outRMSE
		}

		// Use log-normal distribution stats
		val := outRMSE
		if val <= 1e-12 {
			val = 1e-12
		}
		logRMSE := math.Log(val)
		kn.TrainRMSESum += logRMSE
		kn.TrainRMSESS += logRMSE * logRMSE

		if kn.Count == kn.GracePeriod {
			kn.IsTrained = true

			// Compute log-normal threshold: T = exp(mean_log + beta * sigma_log)
			n := float64(kn.GracePeriod)
			meanLog := kn.TrainRMSESum / n
			variance := (kn.TrainRMSESS / n) - (meanLog * meanLog)
			if variance < 0 {
				variance = 0
			}
			sigmaLog := math.Sqrt(variance)
			kn.Threshold = math.Exp(meanLog + kn.ThresholdBeta*sigmaLog)

			slog.Info("AD Grace Period Complete",
				"mean_log", meanLog,
				"sigma_log", sigmaLog,
				"threshold", kn.Threshold,
				"threshold_beta", kn.ThresholdBeta,
			)
		}

		return outRMSE, false, true
	}

	// Execution Mode (Inference)
	// Predict forward pass through L1
	for i := 0; i < kn.K; i++ {
		kn.RmseBuffer[i] = kn.EnsembleLayer[i].Predict(v[i])
	}

	// Predict forward pass through L2
	score := kn.OutputLayer.Predict(kn.RmseBuffer)

	// Compare against robust statistical threshold
	isAlert := score >= kn.Threshold

	return score, isAlert, false
}
