// +build windows

package utilization

import (
	"context"
	"time"

	"github.com/signalfx/signalfx-agent/internal/monitors/telegraf/common/accumulator"
	"github.com/signalfx/signalfx-agent/internal/monitors/telegraf/common/emitter/baseemitter"
	"github.com/signalfx/signalfx-agent/internal/monitors/telegraf/monitors/winperfcounters"
	"github.com/signalfx/signalfx-agent/internal/utils"
)

// Configure the monitor and kick off metric syncing
func (m *Monitor) Configure(conf *Config) error {
	percounterConf := winperfcounters.Config{
		CountersRefreshInterval: conf.CountersRefreshInterval,
		PrintValid: conf.PrintValid,
		Object: []winperfcounters.Perfcounterobj{
			winperfcounters.Perfcounterobj{
				ObjectName: "Processor",
				Counters: []string{"% Processor Time"},
				Instances: []string{"*"},
				Measurement: "win_cpu",
				IncludeTotal: true,
			},
			// disk.utilization = 100 - % Free Space
			winperfcounters.Perfcounterobj{
				ObjectName: "LogicalDisk",
				Counters: []string{"% Free Space"},
				Instances: []string{"*"},
				Measurement: "win_logical_disk",
				IncludeTotal: true,
			},
			winperfcounters.Perfcounterobj{
				ObjectName: "Paging File",
				Counters: []string{"% Usage", "% Usage Peak"},
				Instances: []string{"*"},
				Measurement: "win_logical_disk",
				IncludeTotal: true,
			},
			// memory.utilization needs some work
			// winperfcounters.Perfcounterobj{
			// 	ObjectName: "Memory",
			// 	Counters: []string{"Available Bytes", "Pages Input/sec"},
			// 	Instances: []string{"------"},
			// 	Measurement: "win_mem",
			// 	IncludeTotal: true,
			// },
		}
	}
	plugin := winperfcounters.GetPlugin(conf)

	// create the accumulator
	ac := accumulator.NewAccumulator(batchemitter.NewEmitter(m.Output, logger))

	// create contexts for managing the the plugin loop
	var ctx context.Context
	ctx, m.cancel = context.WithCancel(context.Background())

	// gather metrics on the specified interval
	utils.RunOnInterval(ctx, func() {
		if err := plugin.Gather(ac); err != nil {
			logger.Error(err)
		}
	}, time.Duration(conf.IntervalSeconds)*time.Second)

	return nil
}

// Shutdown stops the metric sync
func (m *Monitor) Shutdown() {
	if m.cancel != nil {
		m.cancel()
	}
}
