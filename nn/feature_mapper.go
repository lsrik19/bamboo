package nn

import (
	"math"
	"sort"
)

// FeatureMapper groups 115 features into k <= m correlated clusters
type FeatureMapper struct {
	NumFeatures int
	MaxCluster  int // m: maximum features per autoencoder (e.g. 10)
	GracePeriod int // N_FM: number of packets used to learn the mapping

	Count int       // Samples observed so far
	Means []float64 // 1D running means for each feature
	SS    []float64 // Sum of squared residuals: sum((x_i - mean_i)^2)
	C     [][]float64 // Cross-feature residual products: sum((x_i - mean_i)*(x_j - mean_j))

	IsTrained bool
	Clusters  [][]int // The resulting k feature index groups

	// Pre-allocated scratch buffers
	deltasBuf  []float64   // len = NumFeatures, reused in updateStats
	subInstBuf [][]float64 // pre-allocated partition output, reused in Process
}

// initializes the clustering engine
func NewFeatureMapper(numFeatures, maxCluster, gracePeriod int) *FeatureMapper {
	c := make([][]float64, numFeatures)
	for i := range c {
		c[i] = make([]float64, numFeatures)
	}

	fm := &FeatureMapper{
		NumFeatures: numFeatures,
		MaxCluster:  maxCluster,
		GracePeriod: gracePeriod,
		Means:       make([]float64, numFeatures),
		SS:          make([]float64, numFeatures),
		C:           c,
		IsTrained:   false,
		Clusters:    nil,
	}
	fm.InitBuffers()
	return fm
}

// InitBuffers allocates or restores transient buffers (called after deserialization or clustering)
func (fm *FeatureMapper) InitBuffers() {
	fm.deltasBuf = make([]float64, fm.NumFeatures)
	if fm.Clusters != nil {
		fm.subInstBuf = make([][]float64, len(fm.Clusters))
		for i, cluster := range fm.Clusters {
			fm.subInstBuf[i] = make([]float64, len(cluster))
		}
	}
}

// processes an instance: updates statistics during grace period or extracts sub-instances
func (fm *FeatureMapper) Process(x []float64) ([][]float64, bool) {
	if !fm.IsTrained {
		fm.updateStats(x)
		if fm.Count >= fm.GracePeriod {
			fm.learnMapping()
			fm.IsTrained = true
		}
		return nil, false // Still learning the map; nothing to send to Bamboo yet
	}

	// Execution mode: partition vector x into k sub-instances v_1, ..., v_k
	for i, cluster := range fm.Clusters {
		for j, featIdx := range cluster {
			fm.subInstBuf[i][j] = x[featIdx]
		}
	}
	return fm.subInstBuf, true
}

// updateStats updates means and covariance online using Welford's multivariate method
func (fm *FeatureMapper) updateStats(x []float64) {
	fm.Count++
	n := float64(fm.Count)

	deltas := fm.deltasBuf
	for i := 0; i < fm.NumFeatures; i++ {
		deltas[i] = x[i] - fm.Means[i]
		fm.Means[i] += deltas[i] / n
	}

	// Update squared residuals and cross-product residuals
	for i := 0; i < fm.NumFeatures; i++ {
		delta2_i := x[i] - fm.Means[i]
		fm.SS[i] += deltas[i] * delta2_i

		for j := i; j < fm.NumFeatures; j++ {
			delta2_j := x[j] - fm.Means[j]
			fm.C[i][j] += deltas[i] * delta2_j
			if i != j {
				fm.C[j][i] = fm.C[i][j]
			}
		}
	}
}

// computes correlation distances and clusters features so each cluster size <= m
func (fm *FeatureMapper) learnMapping() {
	dist := make([][]float64, fm.NumFeatures)
	for i := range dist {
		dist[i] = make([]float64, fm.NumFeatures)
	}

	// Compute correlation distance: D_ij = 1 - (C_ij / sqrt(SS_i * SS_j))
	for i := 0; i < fm.NumFeatures; i++ {
		for j := i; j < fm.NumFeatures; j++ {
			if i == j {
				dist[i][j] = 0.0
				continue
			}
			denom := math.Sqrt(fm.SS[i] * fm.SS[j])
			var d float64
			if denom > 0 {
				r := fm.C[i][j] / denom
				// Guard against floating point imprecision pushing |r| > 1
				if r > 1.0 {
					r = 1.0
				} else if r < -1.0 {
					r = -1.0
				}
				d = 1.0 - r
			} else {
				d = 1.0 // Uncorrelated/zero-variance fallback
			}
			dist[i][j] = d
			dist[j][i] = d
		}
	}

	// Agglomerative clustering with maximum cluster size constraint <= m
	// Initialize 115 individual clusters
	var currentClusters [][]int
	for i := 0; i < fm.NumFeatures; i++ {
		currentClusters = append(currentClusters, []int{i})
	}

	// Iteratively merge closest clusters without exceeding maxCluster size m
	for {
		bestI, bestJ := -1, -1
		minDist := math.MaxFloat64

		for i := 0; i < len(currentClusters); i++ {
			for j := i + 1; j < len(currentClusters); j++ {
				// Enforce constraint: cluster size cannot exceed m
				if len(currentClusters[i])+len(currentClusters[j]) > fm.MaxCluster {
					continue
				}

				// Average linkage distance between cluster i and cluster j
				d := fm.clusterDistance(currentClusters[i], currentClusters[j], dist)
				if d < minDist {
					minDist = d
					bestI = i
					bestJ = j
				}
			}
		}

		// If no valid merge candidate exists, clustering is complete
		if bestI == -1 {
			break
		}

		// Merge bestJ into bestI and delete bestJ
		merged := append(currentClusters[bestI], currentClusters[bestJ]...)
		currentClusters[bestI] = merged
		currentClusters = append(currentClusters[:bestJ], currentClusters[bestJ+1:]...)
	}

	// Sort feature indices within each cluster for determinism
	for _, cl := range currentClusters {
		sort.Ints(cl)
	}

	fm.Clusters = currentClusters

	// Pre-allocate sub-instance partition buffers for execution mode
	fm.subInstBuf = make([][]float64, len(fm.Clusters))
	for i, cluster := range fm.Clusters {
		fm.subInstBuf[i] = make([]float64, len(cluster))
	}
}

// computes average distance between two sets of features
func (fm *FeatureMapper) clusterDistance(c1, c2 []int, dist [][]float64) float64 {
	totalDist := 0.0
	for _, f1 := range c1 {
		for _, f2 := range c2 {
			totalDist += dist[f1][f2]
		}
	}
	return totalDist / float64(len(c1)*len(c2))
}



