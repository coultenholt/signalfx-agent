// +build windows

package top

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
)

const (
	// Windows Access Control Entities
	// PSAPI permissions
	PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
	PROCESS_VM_READ                   = 0x00000010
	// Kernel32 permissions
	TH32CS_SNAPPROCESS = 0x00000002
	//
	READ_CONTROL         = 0x00020000
	STANDARD_RIGHTS_READ = READ_CONTROL
)

// Windows DLLs
var kernel32DLL = windows.NewLazyDLL("kernel32.dll")
var psapi = windows.NewLazyDLL("psapi.dll")

// // Windows API
// var enumProcesses = psapi.NewProc("EnumProcesses")

// Process Snapshot
var createToolhelp32Snapshot = kernel32DLL.NewProc("CreateToolhelp32Snapshot") // creates the snapshot
var process32FirstW = kernel32DLL.NewProc("Process32FirstW")                   // starts iterating the snapshot from the beginning
var process32NextW = kernel32DLL.NewProc("Process32NextW")                     // advances the snapshot iterator
var getProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")

// WinProc -
type WinProc struct {
	*windows.ProcessEntry32
}

func newEntry() *windows.ProcessEntry32 {
	// Process first process
	entry := &windows.ProcessEntry32{}
	entry.Size = uint32(unsafe.Sizeof(*entry))
	return entry
}

// uint8SliceToByteArray converts an []unt16 to []byte
func uint16SliceToByteArray(in []uint16) []byte {
	bts := make([]byte, len(in))
	for i, c := range in {
		bts[i] = byte(c)
	}
	return bytes.Trim(bts, "\x00")
}

// getUsername - retrieves a username from an open process handle
func getUsername(h windows.Handle) (string, error) {
	var token windows.Token
	defer token.Close()
	// the windows api docs suggest that windows.TOKEN_READ is a super set of windows.TOKEN_QUERY,
	// but in practice windows.TOKEN_READ seems to be less permissive for the admin user
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return "unknown", fmt.Errorf("unable to retrieve process token %v", err)
	}

	user, err := token.GetTokenUser()
	if err != nil {
		return "unknown", fmt.Errorf("unable to get token user %v", err)
	}

	username, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return "unknown", fmt.Errorf("unable to look up user account from Sid %v", err)
	}

	return fmt.Sprintf("%s\\%s", domain, username), nil
}

func getMemory(h windows.Handle) (*process.PROCESS_MEMORY_COUNTERS, error) {
	memInfo := &process.PROCESS_MEMORY_COUNTERS{}
	getProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(memInfo)), uintptr(unsafe.Sizeof(*memInfo)))
	return memInfo, nil
}

func getCPUTimes(h windows.Handle) (float64, float64, error) {
	rusage := windows.Rusage{}
	err := windows.GetProcessTimes(h, &rusage.CreationTime, &rusage.ExitTime, &rusage.KernelTime, &rusage.UserTime)
	if err != nil {
		return 0, 0, err
	}
	// windows cpu times are in FILETIME not seconds.  We need to convert this to seconds active.
	// github.com/shirou/gopsutil and github.com/giampaolo/psutil refer to Modules/posixmodule.c
	// in github.com/python/cpython for the conversion
	userTime := float64(rusage.UserTime.HighDateTime)*429.4967296 + float64(rusage.UserTime.LowDateTime)*1e-7
	kernelTime := float64(rusage.KernelTime.HighDateTime)*429.4967296 + float64(rusage.KernelTime.LowDateTime)*1e-7
	totalTime := userTime + kernelTime
	// unixtimestamp that the process was created
	createTime := time.Unix(0, rusage.CreationTime.Nanoseconds())

	// calculate cpu percent using total time spent by the process compared to create time
	cpuPercent := 100 * totalTime / float64(time.Since(createTime).Seconds())
	return totalTime, cpuPercent, nil
}

func toTime(secs float64) (response string) {
	minutes := int(secs / 60)
	seconds := int(math.Mod(secs, 60.0))
	sec := seconds
	dec := (seconds - sec) * 100
	response = fmt.Sprintf("%02d:%02d.%02d", minutes, sec, dec)
	return
}

// buildProcessString
func getProcessTopInfo(handle uintptr, entry *windows.ProcessEntry32, virtualMemory *mem.VirtualMemoryStat, builder *strings.Builder) error {
	processHandle, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(entry.ProcessID))
	defer windows.CloseHandle(processHandle)
	if err != nil {
		fmt.Println(entry.ProcessID)
		return err
	}

	username, err := getUsername(processHandle)
	if err != nil {
		fmt.Println(err)
	}

	memory, err := getMemory(processHandle)
	if err != nil {
		fmt.Println(err)
	}

	memPercent := 100 * (float64(memory.WorkingSetSize) / float64(virtualMemory.Total))

	totalTime, cpuPercent, err := getCPUTimes(processHandle)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%s: %.2f\n", windows.UTF16ToString(entry.ExeFile[:]), cpuPercent)

	//example process "3":["root",20,"0",0,0,0,"S",0.0,0.0,"01:28.31","[ksoftirqd/0]"]
	fmt.Fprintf(builder, "\"%d\":[\"%s\",%d,\"%s\",%d,%d,%d,\"%s\",%.2f,%.2f,\"%s\",\"%s\"]",
		entry.ProcessID,    // pid
		username,           // username
		entry.PriClassBase, // priority
		"N/A",              // nice value is not available on windows
		memory.PagefileUsage/1024,               // virual memory size in kb?
		memory.WorkingSetSize/1024,              // resident memory size in kb?
		0/1024,                                  // shared memory
		"status",                                // status
		cpuPercent,                              // % cpu, float
		memPercent,                              // % mem, float
		toTime(totalTime),                       // cpu time
		windows.UTF16ToString(entry.ExeFile[:]), // command/executable
	)
	return nil
}

// TopInfo takes a snapshot and iterates over it collecting process information
func TopInfo() (processes *strings.Builder, err error) {
	processes = &strings.Builder{}
	processes.WriteString("{")
	defer processes.WriteString("}") // always close the associative array

	// take a process snapshot
	snapshot, _, _ := createToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	defer windows.CloseHandle(windows.Handle(snapshot))
	if snapshot < 0 {
		err = windows.GetLastError()
		return processes, err
	}

	var count int64

	var ret uintptr

	// get the first process in the snapshot
	entry := newEntry()
	ret, _, _ = process32FirstW.Call(snapshot, uintptr(unsafe.Pointer(entry)))
	if ret == 0 {
		err = fmt.Errorf("Error unable to retrieve process info")
		return processes, err
	}
	count++
	// get virtual memory for the system.  It will be passed to getProcessTopInfo for each process.
	virtualMemory, err := mem.VirtualMemory()
	if err != nil {
		fmt.Println(err)
	}

	minorError := getProcessTopInfo(snapshot, entry, virtualMemory, processes)
	if minorError != nil {
		fmt.Println(minorError)
	}

	// Iterate through snapshot adding all of the other processes
	for {
		entry := newEntry()
		ret, _, _ := process32NextW.Call(snapshot, uintptr(unsafe.Pointer(entry)))
		if ret == 0 {
			break
		}
		count++

		// add a comma to the string builderif there is a "next" process handle and the previous entry was added error free add a comma to the string builder
		if minorError == nil {
			processes.WriteString(",")
		}

		minorError = getProcessTopInfo(snapshot, entry, virtualMemory, processes)
		if minorError != nil {
			fmt.Println(minorError)
		}
	}
	fmt.Println(count)
	return processes, err
}
