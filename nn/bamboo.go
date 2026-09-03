package nn

import (
	"fmt"
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
	fmt.Printf("[Bamboo] Initialized %d ensemble autoencoders and 1 output autoencoder\n", kn.K)
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

			// Compute robust log-normal threshold: T = exp(mean_log + beta * sigma_log)
			n := float64(kn.GracePeriod)
			meanLog := kn.TrainRMSESum / n
			variance := (kn.TrainRMSESS / n) - (meanLog * meanLog)
			if variance < 0 {
				variance = 0
			}
			sigmaLog := math.Sqrt(variance)
			kn.Threshold = math.Exp(meanLog + kn.ThresholdBeta*sigmaLog)

			fmt.Printf("\n[Bamboo] AD Grace Period Complete!\n")
			fmt.Printf("[Bamboo] Log-Normal Stats — Mean(log): %.6f | StdDev(log): %.6f\n", meanLog, sigmaLog)
			fmt.Printf("[Bamboo] Threshold = %.6f (exp(mean + %.1f * sigma))\n\n", kn.Threshold, kn.ThresholdBeta)
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