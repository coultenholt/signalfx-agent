// +build windows

package utilization

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/mem"
	"github.com/signalfx/golib/datapoint"
	"github.com/signalfx/golib/sfxclient"
	"github.com/signalfx/signalfx-agent/internal/monitors/telegraf/common/accumulator"
	"github.com/signalfx/signalfx-agent/internal/monitors/telegraf/common/emitter/batchemitter"
	"github.com/signalfx/signalfx-agent/internal/monitors/telegraf/common/measurement"
	"github.com/signalfx/signalfx-agent/internal/monitors/telegraf/monitors/winperfcounters"
	"github.com/signalfx/signalfx-agent/internal/utils"
)

// This maps the measurement name from telegraf to a desired metric name
var metricNameMapping = map[string]string{
	// NetworkInterface
	"Bytes_Received_persec": "network.bytes_received_per_second",
	"Bytes_Sent_persec":     "network.bytes_sent_per_second",

	//
	"Packets_Received_Errors": "if_errors.rx",
	"Packets_Outbound_Errors": "if_errors.tx",

	// LogicalDisk
	"Free_Megabytes": "disk.free", // perfcounter: "Free Megabytes"; perfcounter reporter: "logicaldisk.free_megabytes"; collectd: "df_complex.free";

	// PhysicalDisk
	"Disk_Reads_persec":  "disk.reads_per_second",
	"Disk_Writes_persec": "disk.writes_per_second",

	// Memory
	"Pages_Input_persec":  "memory.swap_in_per_second",  // perfcounter: "Pages Input/sec"; perfcounter reporter: "memory.pages_input_sec"; collectd: "vmpage_io.swap.in";
	"Pages_Output_persec": "memory.swap_out_per_second", // perfcounter: "Pages Input/sec"; perfcounter reporter: "-"; collectd: "vmpage_io.swap.out";
}

func (m *Monitor) emitMemoryUtilization() {
	dimensions := newDimensionsMap()
	memInfo, _ := mem.VirtualMemory()
	// perfcounter: ""; perfcounter reporter: "memory.available_mbytes"; collectd: "memory.free";
	dpavailable := sfxclient.Gauge("memory.free", dimensions, int64(memInfo.Available))
	m.Output.SendDatapoint(dpavailable)
	// perfcounter: ""; perfcounter reporter: "signalfx.usedmemory"; collectd: "memory.used";
	dpused := sfxclient.Gauge("memory.used", dimensions, int64(memInfo.Used))
	m.Output.SendDatapoint(dpused)
	// perfcounter: ""; perfcounter reporter: "memory."; collectd: "-";
	dptotal := sfxclient.Gauge("memory.total", dimensions, int64(memInfo.Total))
	m.Output.SendDatapoint(dptotal)
	// perfcounter: ""; perfcounter reporter: ""; collectd: "memory.utilization"
	util := (float64(memInfo.Used) / float64(memInfo.Total)) * 100
	dputil := sfxclient.GaugeF("memory.utilization", dimensions, util)
	m.Output.SendDatapoint(dputil)
}

func (m *Monitor) processCPU(ms *measurement.Measurement) {
	dimensions := newDimensionsMap()
	metricName := "cpu.utilization"

	// perfcounter: "Processor"; perfcounter reporter: "processor.pct_processor_time"; collectd: "cpu.utilization";
	// perfcounter: "Processor"; perfcounter reporter: "processor.pct_processor_time"; collectd: "cpu.utilization_per_core";

	// handle cpu utilization per core if instance isn't _Total
	if instance, ok := ms.Tags["instance"]; ok && instance != "_Total" {
		metricName = "cpu.utilization_per_core"
		dimensions["core"] = instance
	}

	// parse metric value
	var metricVal datapoint.Value
	var err error
	if val, ok := ms.Fields["Percent_Processor_Time"]; ok {
		if metricVal, err = datapoint.CastMetricValue(val); err != nil {
			logger.Error(err)
			return
		}
	}

	// create datapoint
	dp := datapoint.New(metricName, dimensions, metricVal, datapoint.Gauge, time.Time{})
	m.Output.SendDatapoint(dp)
}

func (m *Monitor) processNetInterface(ms *measurement.Measurement) {
	for field, val := range ms.Fields {
		dimensions := newDimensionsMap()

		// set metric name
		metricName := metricNameMapping[field]
		if metricName == "" {
			logger.Errorf("unable to map field '%s' to a metricname while parsing measurement '%s'",
				field, ms.Measurement)
			continue
		}

		// parse metric value
		var metricVal datapoint.Value
		var err error
		if metricVal, err = datapoint.CastMetricValue(val); err != nil {
			logger.Error(err)
			continue
		}

		// set the instance dimension
		if instance, ok := ms.Tags["instance"]; ok {
			dimensions["interface"] = instance
		} else {
			logger.Errorf("no instance tag defined in tags '%v' for field '%s' on measurement '%s'",
				ms.Tags, field, ms.Measurement)
			continue
		}

		dp := datapoint.New(metricName, dimensions, metricVal, datapoint.Counter, time.Time{})
		m.Output.SendDatapoint(dp)
	}
}

func (m *Monitor) processLogicalDisk(ms *measurement.Measurement) {
	dimensions := newDimensionsMap()

	// set the instance dimension
	if instance, ok := ms.Tags["instance"]; ok {
		dimensions["plugin_instance"] = instance
	} else {
		logger.Errorf("no instance tag defined in tags '%v' for measurement '%s'", ms.Tags, ms)
	}

	// perfcounter: "% Free Space"; perfcounter reporter: "logicaldisk.pct_free_space"; collectd: "disk.utilization";
	var utilization float64
	if val, ok := ms.Fields["Percent_Free_Space"]; ok {
		if v, ok := val.(float32); ok {
			utilization = float64(100) - float64(v)
			m.Output.SendDatapoint(datapoint.New("disk.utilization", dimensions, datapoint.NewFloatValue(utilization), datapoint.Gauge, time.Now()))
		} else {
			logger.Errorf("error parsing measurement %v", ms)
		}
	}

	var used float64
	var free float64
	if val, ok := ms.Fields["Free_Megabytes"]; ok {
		if v, ok := val.(float32); ok {
			// perfcounter: "Free Megabytes"; perfcounter reporter: "logicaldisk.free_megabytes"; collectd: "df_complex.free";
			free = (float64(v) * 1048576)
			m.Output.SendDatapoint(datapoint.New("disk.free", dimensions, datapoint.NewFloatValue(free), datapoint.Gauge, time.Now()))
			// perfcounter: ""; perfcounter reporter: ""; collectd: "df_complex.used";
			used = (free / ((100 - utilization) / 100)) - free
			m.Output.SendDatapoint(datapoint.New("disk.used", dimensions, datapoint.NewFloatValue(used), datapoint.Gauge, time.Now()))

		} else {
			logger.Errorf("error parsing measurement %v", ms)
		}
	}
}

func (m *Monitor) processPhysDisk(ms *measurement.Measurement) {
	dimensions := newDimensionsMap()

	// set the instance dimension
	if instance, ok := ms.Tags["instance"]; ok {
		dimensions["plugin_instance"] = instance
	} else {
		logger.Errorf("no instance tag defined in tags '%v' for measurement '%s'",
			ms.Tags, ms.Measurement)
	}

	for field, val := range ms.Fields {
		// set metric name
		metricName := metricNameMapping[field]
		if metricName == "" {
			logger.Errorf("unable to map field '%v' to a metricname while parsing measurement '%v'",
				field, ms.Measurement)
			continue
		}

		// parse metric value
		var metricVal datapoint.Value
		var err error
		if metricVal, err = datapoint.CastMetricValue(val); err != nil {
			logger.Error(err)
			continue
		}

		dp := datapoint.New(metricName, dimensions, metricVal, datapoint.Gauge, time.Now())
		m.Output.SendDatapoint(dp)
	}
	// logger.Debug(ms)
}

func (m *Monitor) processMemory(ms *measurement.Measurement) {
	dimensions := newDimensionsMap()
	for field, val := range ms.Fields {
		// set metric name
		metricName := metricNameMapping[field]
		if metricName == "" {
			logger.Errorf("unable to map field '%s' to a metricname while parsing measurement '%s'",
				field, ms.Measurement)
			continue
		}

		// parse metric value
		var metricVal datapoint.Value
		var err error
		if metricVal, err = datapoint.CastMetricValue(val); err != nil {
			logger.Error(err)
			continue
		}

		dp := datapoint.New(metricName, dimensions, metricVal, datapoint.Gauge, time.Now())
		m.Output.SendDatapoint(dp)
	}
	logger.Debug(ms)
}

// processMeasurments iterates over each measurement in the list and sends them to the appropriate
// function for parsing
func (m *Monitor) processMeasurements(measurements []*measurement.Measurement) {
	for _, measurement := range measurements {
		switch measurement.Measurement {
		case "win_cpu":
			m.processCPU(measurement)
		case "win_network_interface":
			m.processNetInterface(measurement)
		case "win_logical_disk":
			m.processLogicalDisk(measurement)
		case "win_physical_disk":
			m.processPhysDisk(measurement)
		case "win_memory":
			m.processMemory(measurement)
		default:
			logger.Errorf("utilization plugin collected unknown measurement %v", measurement)
		}
	}
}

// Configure the monitor and kick off metric syncing
func (m *Monitor) Configure(conf *Config) error {
	perfcounterConf := &winperfcounters.Config{
		CountersRefreshInterval: conf.CountersRefreshInterval,
		PrintValid:              conf.PrintValid,
		Object: []winperfcounters.Perfcounterobj{
			winperfcounters.Perfcounterobj{
				ObjectName:   "Processor",
				Counters:     []string{"% Processor Time"},
				Instances:    []string{"*"},
				Measurement:  "win_cpu",
				IncludeTotal: true,
			},
			// disk.utilization = 100 - % Free Space
			winperfcounters.Perfcounterobj{
				ObjectName:   "LogicalDisk",
				Counters:     []string{"% Free Space", "Free Megabytes"},
				Instances:    []string{"*"},
				Measurement:  "win_logical_disk",
				IncludeTotal: true,
			},
			winperfcounters.Perfcounterobj{
				ObjectName:   "PhysicalDisk",
				Counters:     []string{"Disk Reads/sec", "Disk Writes/sec"},
				Instances:    []string{"_Total"},
				Measurement:  "win_physical_disk",
				IncludeTotal: true,
			},
			winperfcounters.Perfcounterobj{
				ObjectName:   "NetworkInterface",
				Counters:     []string{"Bytes Received/ses", "Bytes Sent/sec"},
				Instances:    []string{"*"},
				Measurement:  "win_network_interface",
				IncludeTotal: true,
			},
			// winperfcounters.Perfcounterobj{
			// 	ObjectName:   "Paging File",
			// 	Counters:     []string{"% Usage", "% Usage Peak"},
			// 	Instances:    []string{"*"},
			// 	Measurement:  "win_logical_disk",
			// 	IncludeTotal: true,
			// },
			winperfcounters.Perfcounterobj{
				ObjectName:   "Memory",
				Counters:     []string{"Pages Input/sec", "Pages Output/sec"},
				Instances:    []string{"------"},
				Measurement:  "win_memory",
				IncludeTotal: true,
			},
		},
	}
	plugin := winperfcounters.GetPlugin(perfcounterConf)

	// create batch emitter
	emitter := batchemitter.NewEmitter(m.Output, logger)

	// create the accumulator
	ac := accumulator.NewAccumulator(emitter)

	// create contexts for managing the the plugin loop
	var ctx context.Context
	ctx, m.cancel = context.WithCancel(context.Background())

	// gather metrics on the specified interval
	utils.RunOnInterval(ctx, func() {
		if err := plugin.Gather(ac); err != nil {
			logger.Error(err)
		}

		m.processMeasurements(emitter.Measurements)
		emitter.Measurements = emitter.Measurements[:0]

		// memory utilization is collected from gopsutil instead of through perf counter
		m.emitMemoryUtilization()
	}, time.Duration(conf.IntervalSeconds)*time.Second)

	return nil
}

// Shutdown stops the metric sync
func (m *Monitor) Shutdown() {
	if m.cancel != nil {
		m.cancel()
	}
}
