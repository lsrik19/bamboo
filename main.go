package main

import (
	"context"
	"encoding/csv"
	"flag"
	"log"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/lsrik19/bamboo-nids/nn"
)

func main() {
	configPath := flag.String("c", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	// Load Configuration
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize Structured Logging
	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		logLevel = slog.LevelInfo
	}

	var handler slog.Handler
	if cfg.TestMode {
		// Use clean text for terminal reading
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	} else {
		// Use JSON for production log aggregators
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	slog.Info("Starting Bamboo NIDS", "config", *configPath)

	// Setup Graceful Shutdown Context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		slog.Warn("Received shutdown signal", "signal", sig.String())
		cancel()
	}()

	// Initialize PCAP Capture
	var handle *pcap.Handle
	if cfg.PcapPath != "" {
		slog.Info("Opening offline PCAP", "path", cfg.PcapPath)
		handle, err = pcap.OpenOffline(cfg.PcapPath)
	} else if cfg.Interface != "" {
		slog.Info("Opening live interface", "interface", cfg.Interface)
		handle, err = pcap.OpenLive(cfg.Interface, cfg.SnapLen, true, pcap.BlockForever)
	} else {
		slog.Error("Configuration must specify either pcap_path or interface")
		os.Exit(1)
	}
	if err != nil {
		slog.Error("Capture initialization failed", "error", err)
		os.Exit(1)
	}
	defer handle.Close()

	// Initialize Prometheus Metrics Server
	var metricsSrv *http.Server
	if cfg.MetricsEnabled {
		metricsSrv = startMetricsServer(cfg.MetricsPort)
		defer stopMetricsServer(metricsSrv)
	}

	// Initialize pipeline stages
	netStat := NewNetStat()
	featureMapper := nn.NewFeatureMapper(cfg.NumFeatures, cfg.MaxClusterM, cfg.FMGracePeriod)
	bambooSys := nn.NewBamboo(cfg.ADGracePeriod, cfg.ThresholdBeta)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	// Initialize CSV Writer (Optional, for Evaluation)
	var csvWriter *csv.Writer
	var csvFile *os.File
	if cfg.CSVOutput != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.CSVOutput), 0755); err != nil {
			slog.Error("Failed to create results directory", "error", err)
			os.Exit(1)
		}
		csvFile, err = os.Create(cfg.CSVOutput)
		if err != nil {
			slog.Error("Failed to create CSV file", "error", err)
			os.Exit(1)
		}
		defer csvFile.Close()
		csvWriter = csv.NewWriter(csvFile)
		defer csvWriter.Flush()
		csvWriter.Write([]string{"packet", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "score", "threshold", "phase"})
	}

	pktCount := 0
	execCount := 0
	alertCount := 0
	maxScore := 0.0
	minScore := math.MaxFloat64
	scoreSum := 0.0

	slog.Info("Pipeline started. Processing packets...")
	packetChan := packetSource.Packets()

pipelineLoop:
	for {
		select {
		case <-ctx.Done():
			slog.Info("Context cancelled, stopping pipeline.")
			break pipelineLoop
		case packet, ok := <-packetChan:
			if !ok {
				slog.Info("Reached end of packet stream.")
				break pipelineLoop
			}
			pktCount++
			metricPacketsProcessed.Inc()

			meta := parsePacket(packet)
			if meta == nil {
				continue
			}

			// Extract 100 damped incremental features
			x := netStat.UpdateAndExtract(meta)

			// Feature Mapper
			v, isFMReady := featureMapper.Process(x)
			if !isFMReady {
				if pktCount%10000 == 0 {
					slog.Debug("FM Grace Period", "packet", pktCount, "required", cfg.FMGracePeriod)
				}
				continue
			}

			// Initialize Ensemble
			if bambooSys.EnsembleLayer == nil {
				bambooSys.InitEnsemble(featureMapper.Clusters)
				slog.Info("Feature Mapper ready. Autoencoder ensemble initialized.")
			}

			// Anomaly Detector
			score, isAlert, isTraining := bambooSys.Process(v)
			
			// Update Metrics
			metricCurrentScore.Set(score)
			metricThreshold.Set(bambooSys.Threshold)

			// Log to CSV if configured
			if csvWriter != nil {
				phase := "exec"
				if isTraining {
					phase = "train"
				}
				csvWriter.Write([]string{
					strconv.Itoa(pktCount),
					strconv.FormatFloat(meta.Timestamp, 'f', 6, 64),
					meta.SrcIP, meta.SrcPort, meta.DstIP, meta.DstPort, meta.Protocol,
					strconv.FormatFloat(score, 'f', 6, 64),
					strconv.FormatFloat(bambooSys.Threshold, 'f', 6, 64),
					phase,
				})
			}

			if isTraining {
				if pktCount%50000 == 0 {
					slog.Debug("AD Grace Period", "packet", bambooSys.Count, "required", cfg.ADGracePeriod, "rmse", score)
				}
			} else {
				// Execution mode
				execCount++
				scoreSum += score
				if score > maxScore {
					maxScore = score
				}
				if score < minScore {
					minScore = score
				}

				if isAlert {
					alertCount++
					metricAlertsGenerated.Inc()

					// Only log every single packet anomaly if NOT in TestMode (to prevent terminal flooding)
					if !cfg.TestMode {
						slog.Warn("Anomaly Detected", 
							"score", score, 
							"threshold", bambooSys.Threshold, 
							"src_ip", meta.SrcIP, 
							"dst_ip", meta.DstIP, 
							"protocol", meta.Protocol,
							"packet_id", pktCount,
						)
					}
				}

				if execCount%50000 == 0 {
					slog.Info("Execution Status", 
						"packets_scored", execCount, 
						"alerts", alertCount, 
						"max_score", maxScore,
						"avg_score", scoreSum/float64(execCount),
					)
				}
			}
		}
	}

	// Final Summary
	slog.Info("Pipeline Summary",
		"total_packets", pktCount,
		"exec_packets", execCount,
		"anomalies_detected", alertCount,
		"threshold", bambooSys.Threshold,
		"max_score", maxScore,
	)
}
