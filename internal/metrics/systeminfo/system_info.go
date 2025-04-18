package systeminfo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/sensors"
	"github.com/shirou/gopsutil/v4/warning"
	"github.com/yusing/go-proxy/internal/common"
	"github.com/yusing/go-proxy/internal/logging"
	"github.com/yusing/go-proxy/internal/metrics/period"
	"github.com/yusing/go-proxy/pkg/gperr"
	"github.com/yusing/go-proxy/pkg/json"
)

// json tags are left for tests

type (
	Sensors    []sensors.TemperatureStat
	Aggregated = json.MapSlice[any]
)

type SystemInfo struct {
	Timestamp  int64                           `json:"timestamp"`
	CPUAverage *float64                        `json:"cpu_average"`
	Memory     *mem.VirtualMemoryStat          `json:"memory"`
	Disks      map[string]*disk.UsageStat      `json:"disks"`    // disk usage by partition
	DisksIO    map[string]*disk.IOCountersStat `json:"disks_io"` // disk IO by device
	Network    *net.IOCountersStat             `json:"network"`
	Sensors    Sensors                         `json:"sensors"` // sensor temperature by key
}

const (
	queryCPUAverage         = "cpu_average"
	queryMemoryUsage        = "memory_usage"
	queryMemoryUsagePercent = "memory_usage_percent"
	queryDisksReadSpeed     = "disks_read_speed"
	queryDisksWriteSpeed    = "disks_write_speed"
	queryDisksIOPS          = "disks_iops"
	queryDiskUsage          = "disk_usage"
	queryNetworkSpeed       = "network_speed"
	queryNetworkTransfer    = "network_transfer"
	querySensorTemperature  = "sensor_temperature"
)

var allQueries = []string{
	queryCPUAverage,
	queryMemoryUsage,
	queryMemoryUsagePercent,
	queryDisksReadSpeed,
	queryDisksWriteSpeed,
	queryDisksIOPS,
	queryDiskUsage,
	queryNetworkSpeed,
	queryNetworkTransfer,
	querySensorTemperature,
}

var Poller = period.NewPoller("system_info", getSystemInfo, aggregate)

func _() { // check if this behavior is not changed
	var _ sensors.Warnings = disk.Warnings{}
}

func getSystemInfo(ctx context.Context, lastResult *SystemInfo) (*SystemInfo, error) {
	errs := gperr.NewBuilder("failed to get system info")
	var s SystemInfo
	s.Timestamp = time.Now().Unix()

	if !common.MetricsDisableCPU {
		errs.Add(s.collectCPUInfo(ctx))
	}
	if !common.MetricsDisableMemory {
		errs.Add(s.collectMemoryInfo(ctx))
	}
	if !common.MetricsDisableDisk {
		errs.Add(s.collectDisksInfo(ctx, lastResult))
	}
	if !common.MetricsDisableNetwork {
		errs.Add(s.collectNetworkInfo(ctx, lastResult))
	}
	if !common.MetricsDisableSensors {
		errs.Add(s.collectSensorsInfo(ctx))
	}

	if errs.HasError() {
		allWarnings := gperr.NewBuilder("")
		allErrors := gperr.NewBuilder("failed to get system info")
		errs.ForEach(func(err error) {
			warnings := new(warning.Warning)
			if errors.As(err, &warnings) {
				allWarnings.AddRange(warnings.List...)
			} else {
				allErrors.Add(err)
			}
		})
		if allWarnings.HasError() {
			logging.Warn().Msg(allWarnings.String())
		}
		if allErrors.HasError() {
			return nil, allErrors.Error()
		}
	}

	return &s, nil
}

func (s *SystemInfo) collectCPUInfo(ctx context.Context) error {
	cpuAverage, err := cpu.PercentWithContext(ctx, 500*time.Millisecond, false)
	if err != nil {
		return err
	}
	s.CPUAverage = new(float64)
	*s.CPUAverage = cpuAverage[0]
	return nil
}

func (s *SystemInfo) collectMemoryInfo(ctx context.Context) (err error) {
	s.Memory, err = mem.VirtualMemoryWithContext(ctx)
	return err
}

func (s *SystemInfo) collectDisksInfo(ctx context.Context, lastResult *SystemInfo) (err error) {
	s.DisksIO, err = disk.IOCountersWithContext(ctx)
	if err != nil {
		return err
	}
	if lastResult != nil {
		interval := float64(time.Now().Unix() - lastResult.Timestamp)
		for name, disk := range s.DisksIO {
			if lastUsage, ok := lastResult.DisksIO[name]; ok {
				disk.ReadSpeed = float64(disk.ReadBytes-lastUsage.ReadBytes) / interval
				disk.WriteSpeed = float64(disk.WriteBytes-lastUsage.WriteBytes) / interval
				disk.Iops = (disk.ReadCount + disk.WriteCount - lastUsage.ReadCount - lastUsage.WriteCount) / uint64(interval)
			}
		}
	}

	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return err
	}
	s.Disks = make(map[string]*disk.UsageStat, len(partitions))
	errs := gperr.NewBuilder("failed to get disks info")
	for _, partition := range partitions {
		diskUsage, err := disk.UsageWithContext(ctx, partition.Mountpoint)
		if err != nil {
			errs.Add(err)
			continue
		}
		s.Disks[partition.Device] = diskUsage
	}

	if errs.HasError() {
		if len(s.Disks) == 0 {
			return errs.Error()
		}
		logging.Warn().Msg(errs.String())
	}
	return nil
}

func (s *SystemInfo) collectNetworkInfo(ctx context.Context, lastResult *SystemInfo) error {
	networkIO, err := net.IOCountersWithContext(ctx, false)
	if err != nil {
		return err
	}
	s.Network = networkIO[0]
	if lastResult != nil {
		interval := float64(time.Now().Unix() - lastResult.Timestamp)
		s.Network.UploadSpeed = float64(networkIO[0].BytesSent-lastResult.Network.BytesSent) / interval
		s.Network.DownloadSpeed = float64(networkIO[0].BytesRecv-lastResult.Network.BytesRecv) / interval
	}
	return nil
}

func (s *SystemInfo) collectSensorsInfo(ctx context.Context) error {
	sensorsInfo, err := sensors.TemperaturesWithContext(ctx)
	s.Sensors = sensorsInfo
	return err
}

// explicitly implement MarshalJSON to avoid reflection
func (s *SystemInfo) MarshalJSONTo(b []byte) []byte {
	b = append(b, '{')

	// timestamp
	b = append(b, `"timestamp":`...)
	b = strconv.AppendInt(b, s.Timestamp, 10)

	// cpu_average
	b = append(b, `,"cpu_average":`...)
	if s.CPUAverage != nil {
		b = strconv.AppendFloat(b, *s.CPUAverage, 'f', 2, 64)
	} else {
		b = append(b, "null"...)
	}

	// memory
	b = append(b, `,"memory":`...)
	if s.Memory != nil {
		b = fmt.Appendf(b,
			`{"total":%d,"available":%d,"used":%d,"used_percent":%s}`,
			s.Memory.Total,
			s.Memory.Available,
			s.Memory.Used,
			strconv.FormatFloat(s.Memory.UsedPercent, 'f', 2, 64),
		)
	} else {
		b = append(b, "null"...)
	}

	// disk
	b = append(b, `,"disks":`...)
	if len(s.Disks) > 0 {
		b = append(b, '{')
		first := true
		for device, disk := range s.Disks {
			if !first {
				b = append(b, ',')
			}
			b = fmt.Appendf(b,
				`"%s":{"device":%q,"path":%q,"fstype":%q,"total":%d,"free":%d,"used":%d,"used_percent":%.2f}`,
				device,
				device,
				disk.Path,
				disk.Fstype,
				disk.Total,
				disk.Free,
				disk.Used,
				disk.UsedPercent,
			)
			first = false
		}
		b = append(b, '}')
	} else {
		b = append(b, "null"...)
	}

	// disks_io
	b = append(b, `,"disks_io":`...)
	if len(s.DisksIO) > 0 {
		b = append(b, '{')
		first := true
		for name, usage := range s.DisksIO {
			if !first {
				b = append(b, ',')
			}
			b = fmt.Appendf(b,
				`"%s":{"name":%q,"read_bytes":%d,"write_bytes":%d,"read_speed":%.2f,"write_speed":%.2f,"iops":%d}`,
				name,
				name,
				usage.ReadBytes,
				usage.WriteBytes,
				usage.ReadSpeed,
				usage.WriteSpeed,
				usage.Iops,
			)
			first = false
		}
		b = append(b, '}')
	} else {
		b = append(b, "null"...)
	}

	// network
	b = append(b, `,"network":`...)
	if s.Network != nil {
		b = fmt.Appendf(b,
			`{"bytes_sent":%d,"bytes_recv":%d,"upload_speed":%.2f,"download_speed":%.2f}`,
			s.Network.BytesSent,
			s.Network.BytesRecv,
			s.Network.UploadSpeed,
			s.Network.DownloadSpeed,
		)
	} else {
		b = append(b, "null"...)
	}

	// sensors
	b = append(b, `,"sensors":`...)
	if len(s.Sensors) > 0 {
		b = append(b, '{')
		first := true
		for _, sensor := range s.Sensors {
			if !first {
				b = append(b, ',')
			}
			b = fmt.Appendf(b,
				`"%s":{"name":%q,"temperature":%.2f,"high":%.2f,"critical":%.2f}`,
				sensor.SensorKey,
				sensor.SensorKey,
				sensor.Temperature,
				sensor.High,
				sensor.Critical,
			)
			first = false
		}
		b = append(b, '}')
	} else {
		b = append(b, "null"...)
	}

	b = append(b, '}')
	return b
}

// recharts friendly
func aggregate(entries []*SystemInfo, query url.Values) (total int, result Aggregated) {
	n := len(entries)
	aggregated := make(Aggregated, 0, n)
	switch query.Get("aggregate") {
	case queryCPUAverage:
		for _, entry := range entries {
			if entry.CPUAverage != nil {
				aggregated = append(aggregated, map[string]any{
					"timestamp":   entry.Timestamp,
					"cpu_average": *entry.CPUAverage,
				})
			}
		}
	case queryMemoryUsage:
		for _, entry := range entries {
			if entry.Memory != nil {
				aggregated = append(aggregated, map[string]any{
					"timestamp":    entry.Timestamp,
					"memory_usage": entry.Memory.Used,
				})
			}
		}
	case queryMemoryUsagePercent:
		for _, entry := range entries {
			if entry.Memory != nil {
				aggregated = append(aggregated, map[string]any{
					"timestamp":            entry.Timestamp,
					"memory_usage_percent": entry.Memory.UsedPercent,
				})
			}
		}
	case queryDisksReadSpeed:
		for _, entry := range entries {
			if entry.DisksIO == nil {
				continue
			}
			m := make(map[string]any, len(entry.DisksIO)+1)
			for name, usage := range entry.DisksIO {
				m[name] = usage.ReadSpeed
			}
			m["timestamp"] = entry.Timestamp
			aggregated = append(aggregated, m)
		}
	case queryDisksWriteSpeed:
		for _, entry := range entries {
			if entry.DisksIO == nil {
				continue
			}
			m := make(map[string]any, len(entry.DisksIO)+1)
			for name, usage := range entry.DisksIO {
				m[name] = usage.WriteSpeed
			}
			m["timestamp"] = entry.Timestamp
			aggregated = append(aggregated, m)
		}
	case queryDisksIOPS:
		for _, entry := range entries {
			if entry.DisksIO == nil {
				continue
			}
			m := make(map[string]any, len(entry.DisksIO)+1)
			for name, usage := range entry.DisksIO {
				m[name] = usage.Iops
			}
			m["timestamp"] = entry.Timestamp
			aggregated = append(aggregated, m)
		}
	case queryDiskUsage:
		for _, entry := range entries {
			if entry.Disks == nil {
				continue
			}
			m := make(map[string]any, len(entry.Disks)+1)
			for name, disk := range entry.Disks {
				m[name] = disk.Used
			}
			m["timestamp"] = entry.Timestamp
			aggregated = append(aggregated, m)
		}
	case queryNetworkSpeed:
		for _, entry := range entries {
			if entry.Network == nil {
				continue
			}
			aggregated = append(aggregated, map[string]any{
				"timestamp": entry.Timestamp,
				"upload":    entry.Network.UploadSpeed,
				"download":  entry.Network.DownloadSpeed,
			})
		}
	case queryNetworkTransfer:
		for _, entry := range entries {
			if entry.Network == nil {
				continue
			}
			aggregated = append(aggregated, map[string]any{
				"timestamp": entry.Timestamp,
				"upload":    entry.Network.BytesSent,
				"download":  entry.Network.BytesRecv,
			})
		}
	case querySensorTemperature:
		for _, entry := range entries {
			if entry.Sensors == nil {
				continue
			}
			m := make(map[string]any, len(entry.Sensors)+1)
			for _, sensor := range entry.Sensors {
				m[sensor.SensorKey] = sensor.Temperature
			}
			m["timestamp"] = entry.Timestamp
			aggregated = append(aggregated, m)
		}
	default:
		return -1, nil
	}
	return len(aggregated), aggregated
}
