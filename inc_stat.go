package main

import (
	"math"
)

// maintains rolling damped 1D and 2D statistics
type IncStat struct {
	Lambda float64 // Decay factor λ
	Tlast  float64 // Last packet arrival time (seconds)
	W      float64 // Damped weight (packet count)
	LS     float64 // Linear sum of values
	SS     float64 // Sum of squared values
}

// creates a new incremental statistic for a given lambda
func NewIncStat(lambda float64) *IncStat {
	return &IncStat{
		Lambda: lambda,
		Tlast:  0,
		W:      0,
		LS:     0,
		SS:     0,
	}
}

// Update decays past state and inserts new observation x at timestamp t
func (s *IncStat) Update(x float64, t float64) {
	if s.Tlast == 0 {
		s.Tlast = t
		s.W = 1
		s.LS = x
		s.SS = x * x
		return
	}

	dt := t - s.Tlast
	if dt < 0 {
		dt = 0 // Guard against out-of-order packet timing anomalies
	}

	// Exponential decay: gamma = 2^(-lambda * dt)
	gamma := math.Exp2(-s.Lambda * dt)

	s.W = s.W*gamma + 1.0
	s.LS = s.LS*gamma + x
	s.SS = s.SS*gamma + (x * x)
	s.Tlast = t
}

// returns the decayed packet count (rate proxy)
func (s *IncStat) Weight() float64 {
	return s.W
}

// returns the running average
func (s *IncStat) Mean() float64 {
	if s.W <= 0 {
		return 0
	}
	return s.LS / s.W
}

// returns the running variance
func (s *IncStat) Variance() float64 {
	if s.W <= 0 {
		return 0
	}
	mean := s.Mean()
	variance := (s.SS / s.W) - (mean * mean)
	if variance < 0 {
		return 0
	}
	return variance
}

// returns the standard deviation
func (s *IncStat) StdDev() float64 {
	return math.Sqrt(s.Variance())
}


// IncStat2D tracks the 2D interaction between two streams
type IncStat2D struct {
	Lambda float64
	Tlast  float64
	W      float64
	LS_x   float64
	LS_y   float64
	SS_x   float64
	SS_y   float64
	SR     float64 // Sum of Residuals: Sum(x * y)
}

func NewIncStat2D(lambda float64) *IncStat2D {
	return &IncStat2D{Lambda: lambda}
}

func (s *IncStat2D) Update(x, y, t float64) {
	if s.Tlast == 0 {
		s.Tlast = t
		s.W = 1
		s.LS_x, s.LS_y = x, y
		s.SS_x, s.SS_y = x*x, y*y
		s.SR = x * y
		return
	}

	dt := t - s.Tlast
	if dt < 0 {
		dt = 0
	}
	gamma := math.Exp2(-s.Lambda * dt)

	s.W = s.W*gamma + 1.0
	s.LS_x = s.LS_x*gamma + x
	s.LS_y = s.LS_y*gamma + y
	s.SS_x = s.SS_x*gamma + (x * x)
	s.SS_y = s.SS_y*gamma + (y * y)
	s.SR = s.SR*gamma + (x * y)
	s.Tlast = t
}

// computes Cov(X, Y)
func (s *IncStat2D) Covariance() float64 {
	if s.W <= 0 {
		return 0
	}
	meanX := s.LS_x / s.W
	meanY := s.LS_y / s.W
	cov := (s.SR / s.W) - (meanX * meanY)
	return cov
}

// computes Pearson correlation coeff
func (s *IncStat2D) Correlation() float64 {
	cov := s.Covariance()
	varX := (s.SS_x / s.W) - math.Pow(s.LS_x/s.W, 2)
	varY := (s.SS_y / s.W) - math.Pow(s.LS_y/s.W, 2)
	denom := math.Sqrt(math.Abs(varX * varY))
	if denom <= 0 {
		return 0
	}
	return cov / denom
}