package nn

import (
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// ModelMagic identifies Bamboo saved model files
	ModelMagic = "BAMBOO_MODEL_V1"
)

func init() {
	gob.Register(&Model{})
	gob.Register(&Autoencoder{})
	gob.Register(&FeatureMapper{})
	gob.Register(&Bamboo{})
}

// Model encapsulates the complete trained state of a Bamboo NIDS instance
type Model struct {
	Magic         string
	Version       string
	CreatedAt     time.Time
	NumFeatures   int
	MaxClusterM   int
	Threshold     float64
	ThresholdBeta float64
	FeatureMapper *FeatureMapper
	Bamboo        *Bamboo
}

// SaveModel serializes the trained FeatureMapper and Bamboo models to disk with gzip compression
func SaveModel(path string, fm *FeatureMapper, bamboo *Bamboo) error {
	if fm == nil || bamboo == nil {
		return fmt.Errorf("cannot save nil FeatureMapper or Bamboo")
	}
	if !bamboo.IsTrained {
		return fmt.Errorf("cannot save untrained model (AD grace period not complete)")
	}

	model := &Model{
		Magic:         ModelMagic,
		Version:       "1.0.0",
		CreatedAt:     time.Now(),
		NumFeatures:   fm.NumFeatures,
		MaxClusterM:   fm.MaxCluster,
		Threshold:     bamboo.Threshold,
		ThresholdBeta: bamboo.ThresholdBeta,
		FeatureMapper: fm,
		Bamboo:        bamboo,
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write to temporary file first then atomically rename to prevent partial writes
	tmpFile := path + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create model temp file %s: %w", tmpFile, err)
	}
	defer os.Remove(tmpFile)

	gz := gzip.NewWriter(f)
	enc := gob.NewEncoder(gz)
	if err := enc.Encode(model); err != nil {
		f.Close()
		return fmt.Errorf("failed to encode model: %w", err)
	}

	if err := gz.Close(); err != nil {
		f.Close()
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close model file: %w", err)
	}

	if err := os.Rename(tmpFile, path); err != nil {
		return fmt.Errorf("failed to replace model file %s: %w", path, err)
	}

	return nil
}

// LoadModel deserializes a saved model from disk and restores all internal buffers
func LoadModel(path string) (*Model, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open model file %s: %w", path, err)
	}
	defer f.Close()

	// Check if file is gzip compressed (magic bytes: 0x1f, 0x8b)
	header := make([]byte, 2)
	n, err := f.Read(header)
	if err != nil || n < 2 {
		return nil, fmt.Errorf("failed to read model file header: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek model file: %w", err)
	}

	var r io.Reader = f
	if header[0] == 0x1f && header[1] == 0x8b {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gz.Close()
		r = gz
	}

	dec := gob.NewDecoder(r)
	var model Model
	if err := dec.Decode(&model); err != nil {
		return nil, fmt.Errorf("failed to decode model: %w", err)
	}

	if model.Magic != ModelMagic {
		return nil, fmt.Errorf("invalid model file: expected magic %s, got %s", ModelMagic, model.Magic)
	}

	if model.FeatureMapper == nil || model.Bamboo == nil {
		return nil, fmt.Errorf("invalid model file: missing FeatureMapper or Bamboo component")
	}

	// Re-initialize transient scratch buffers
	model.FeatureMapper.InitBuffers()
	model.Bamboo.InitBuffers()

	return &model, nil
}
