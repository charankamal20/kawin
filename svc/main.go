package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fltLib                             = syscall.NewLazyDLL("fltlib.dll")
	procFilterConnectCommunicationPort = fltLib.NewProc("FilterConnectCommunicationPort")
	procFilterGetMessage               = fltLib.NewProc("FilterGetMessage")
	procFilterReplyMessage             = fltLib.NewProc("FilterReplyMessage")
	procFilterSendMessage              = fltLib.NewProc("FilterSendMessage")
)

const (
	FilterPort = "\\ScannerPort"

	// Buffer sizes
	MessageBufferSize = 4096
	EventChannelSize  = 1024

	// Worker configuration
	ReaderGoroutines = 2
	WorkerGoroutines = 4

	// from fltUser.h
	FLT_PORT_FLAG_SYNC_HANDLE = 0x00000001
)

// FILTER_MESSAGE_HEADER matches the kernel FILTER_MESSAGE_HEADER structure
// This is required by the filter manager
type FILTER_MESSAGE_HEADER struct {
	ReplyLength uint32
	MessageId   uint64
}

// FILTER_REPLY_HEADER for sending replies back to the filter
type FILTER_REPLY_HEADER struct {
	Status    int32  // NTSTATUS value
	MessageId uint64 // Must match the MessageId from the received message
}

type Log struct {
	// updated time
	Timestamp   int64  `json:"timestamp"`
	UpdatedTime string `json:"updatedTime"`

	// host
	ClusterName string `json:"clusterName,omitempty"`
	HostName    string `json:"hostName"`
	NodeID      string `json:"nodeID,omitempty"`

	// common
	HostPPID int32 `json:"hostPPid"`
	HostPID  int32 `json:"hostPid"`
	PPID     int32 `json:"ppid"`
	PID      int32 `json:"pid"`
	UID      int32 `json:"uid"`

	// process
	ParentProcessName string `json:"parentProcessName"`
	ProcessName       string `json:"processName"`

	// enforcer
	Enforcer string `json:"enforcer,omitempty"`

	// policy
	PolicyName string `json:"policyName,omitempty"`

	// KubeArmor Version
	KubeArmorVersion string `json:"kubeArmorVersion,omitempty"`

	// severity, tags, message
	Severity string   `json:"severity,omitempty"`
	Tags     string   `json:"tags,omitempty"`
	ATags    []string `json:"atags"`
	Message  string   `json:"message,omitempty"`

	// log
	Type                   string            `json:"type"`
	Source                 string            `json:"source"`
	Operation              string            `json:"operation"`
	Resource               string            `json:"resource"`
	Cwd                    string            `json:"cwd"`
	TTY                    string            `json:"tty,omitempty"`
	OID                    int32             `json:"oid"`
	Data                   string            `json:"data,omitempty"`
	EventData              map[string]string `json:"eventData,omitempty"`
	ProcessHash            string            `json:"processHash,omitempty"`
	ParentHash             string            `json:"parentHash,omitempty"`
	ResourceHash           string            `json:"resourceHash,omitempty"`
	HashAlgo               string            `json:"hashAlgo,omitempty"`
	Action                 string            `json:"action,omitempty"`
	Result                 string            `json:"result"`
	MaxAlertsPerSec        int32             `json:"MaxAlertsPerSec,omitempty"`
	DroppingAlertsInterval int32             `json:"DroppingAlertsInterval,omitempty"`
	// == //

	PolicyEnabled int `json:"policyEnabled,omitempty"`

	ProcessVisibilityEnabled      bool `json:"processVisibilityEnabled,omitempty"`
	FileVisibilityEnabled         bool `json:"fileVisibilityEnabled,omitempty"`
	NetworkVisibilityEnabled      bool `json:"networkVisibilityEnabled,omitempty"`
	CapabilitiesVisibilityEnabled bool `json:"capabilitiesVisibilityEnabled,omitempty"`
}

type FilterService struct {
	// filter port
	portHandle windows.Handle

	// channels
	eventChan chan *Log
	stopCh    chan struct{}

	// sync waitgroup
	wg sync.WaitGroup

	// configurations
	maxRetries int
	retryDelay time.Duration

	// statistics
	messageReceived  atomic.Uint64
	messageProcessed atomic.Uint64
	messageDropped   atomic.Uint64

	running atomic.Bool
}

type Config struct {
	MaxRetries int
	RetryDelay time.Duration
}

func defaultConig() *Config {
	return &Config{
		MaxRetries: 3,
		RetryDelay: 1 * time.Second,
	}
}

func NewFilterService(cfg *Config) *FilterService {
	if cfg == nil {
		cfg = defaultConig()
	}

	s := &FilterService{
		portHandle: windows.InvalidHandle,
		eventChan:  make(chan *Log, EventChannelSize),
		stopCh:     make(chan struct{}),
		maxRetries: cfg.MaxRetries,
		retryDelay: cfg.RetryDelay,
	}

	return s
}

func (s *FilterService) Start() error {
	if !s.running.CompareAndSwap(false, true) {
		return fmt.Errorf("service already running!")
	}

	var portHandle windows.Handle
	var err error

	for i := 0; i < s.maxRetries; i++ {
		portHandle, err = s.openFilterPort()
		if err == nil {
			break
		}
		log.Printf("Attempt %d/%d: Failed to open filter port: %v", i+1, s.maxRetries, err)
		if i < s.maxRetries-1 {
			time.Sleep(s.retryDelay)
		}
	}

	if err != nil {
		s.running.Store(false)
		return fmt.Errorf("failed to open filter port after %d attempts: %w", s.maxRetries, err)
	}
	s.portHandle = portHandle

	log.Println("Filter service started!")

	// start reader goroutines
	for i := 0; i < ReaderGoroutines; i++ {
		s.wg.Add(1)
		go s.readerWorker(i)
	}

	// start processor goroutines
	for i := 0; i < WorkerGoroutines; i++ {
		s.wg.Add(1)
		go s.processorWorker(i)
	}

	// statistics reporter
	s.wg.Add(1)
	go s.statsReporter()

	return nil
}

func (s *FilterService) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return fmt.Errorf("service not started")
	}

	log.Println("stopping filter service")
	close(s.stopCh)

	// close port handle
	if s.portHandle != windows.InvalidHandle {
		windows.CloseHandle(s.portHandle)
	}

	s.wg.Wait()
	close(s.eventChan)

	log.Printf("filter service stopped. Stats - Received: %d Processed: %d Dropped: %d",
		s.messageReceived.Load(), s.messageProcessed.Load(), s.messageDropped.Load())

	return nil
}

func (s *FilterService) openFilterPort() (windows.Handle, error) {
	portName, err := windows.UTF16PtrFromString(FilterPort)
	if err != nil {
		return windows.InvalidHandle, err
	}

	var handle windows.Handle

	// This is calling FilterConnectCommunicationPort - NO CreateFile here!
	ret, _, _ := procFilterConnectCommunicationPort.Call(
		uintptr(unsafe.Pointer(portName)), // LPCWSTR converted to uintptr
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&handle)),
	)

	if ret != 0 {
		return windows.InvalidHandle, fmt.Errorf("FilterConnectCommunicationPort failed: 0x%X", ret)
	}

	return handle, nil
}

func (s *FilterService) readerWorker(id int) {
	defer s.wg.Done()

	log.Printf("Reader worker %d started", id)
	buffer := make([]byte, MessageBufferSize)

	for {
		select {
		case <-s.stopCh:
			log.Printf("Reader worker %d stopped gracefully", id)
			return
		default:
		}

		ret, _, lastErr := procFilterGetMessage.Call(
			uintptr(s.portHandle),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(0), // lpOverlapped (NULL for synchronous op)
		)

		if ret != 0 {
			switch ret {
			case uintptr(windows.ERROR_NO_MORE_ITEMS):
				log.Println("Filter port closed (ERROR_NO_MORE_ITEMS)")
				return
			case uintptr(windows.RPC_S_SERVER_UNAVAILABLE):
				log.Println("Filter driver unavailable (RPC_S_SERVER_UNAVAILABLE)")
				return
			case uintptr(windows.ERROR_ACCESS_DENIED):
				log.Println("access denied (ERROR_ACCESS_DENIED)")
				return
			default:
				log.Printf("FilterGetMessage failed with HRESULT: 0x%X, lastErr: %v", ret, lastErr)
				return
			}
		}

		// log.Printf("buffer data: %x\n", buffer)

		msg, err := s.parseFilterMessage(buffer)
		if err != nil {
			log.Printf("Reader %d: Parse error (non-fatal): %v", id, err)
			continue
		}
		log.Printf("====parsed message====\n%+v", msg)

		msg.UpdatedTime = time.Now().String()

		s.messageReceived.Add(1)

		select {
		case s.eventChan <- msg:
		case <-s.stopCh:
			return
		default:
			s.messageDropped.Add(1)
		}
	}
}

func getOperationType(op uint32) string {
	switch op {
	case 1:
		return "Process"
	case 2:
		return "File"
	case 3:
		return "Network"
	default:
		return "INVALID_OPERATION_TYPE"
	}
}

func getLogType(tp uint32) string {
	switch tp {
	case 1:
		return "HostLog"
	case 2:
		return "MatchHostPolicy"
	default:
		return "INVALID_LOG_TYPE"
	}
}

func getResult(res bool) string {
	if res {
		return "Passed"
	}
	return "Permission denied"
}

func getAction(blocked bool) string {
	if blocked {
		return "Block"
	}
	return "Audit"
}

func getFileOperation(op uint32) string {
	switch op {
	case 0:
		return "Create"
	case 1:
		return "Read"
	case 2:
		return "Write"
	case 3:
		return "Delete"
	default:
		return "INVALID_FILE_OPERATION"
	}
}

func handleFileEvent(buf *bytes.Buffer, log_ *Log) {
	// operation
	var op uint32
	err := binary.Read(buf, binary.LittleEndian, &op)
	if err != nil {
		return
	}
	// process id
	var pid uint32
	err = binary.Read(buf, binary.LittleEndian, &pid)
	if err != nil {
		return
	}
	// process path offset
	var p_path_offset uint32
	err = binary.Read(buf, binary.LittleEndian, &p_path_offset)
	if err != nil {
		return
	}
	// process path length
	var p_path_length uint32
	err = binary.Read(buf, binary.LittleEndian, &p_path_length)
	if err != nil {
		return
	}
	// file path offset
	var f_path_offset uint32
	err = binary.Read(buf, binary.LittleEndian, &f_path_offset)
	if err != nil {
		return
	}
	// file path length
	var f_path_length uint32
	err = binary.Read(buf, binary.LittleEndian, &f_path_length)
	if err != nil {
		return
	}

	log.Printf("File event:\n Operation: %d, Pid: %d, ProcessPathOffset: %d, ProcessPathLength: %d, FilePathOffset: %d, FilePathLength: %d",
		op, pid, p_path_offset, p_path_length, f_path_offset, f_path_length)

	// process path string
	var p_path_str string
	if p_path_length > 0 {
		p_path_u16_str := make([]uint16, p_path_length/2)
		err = binary.Read(buf, binary.LittleEndian, &p_path_u16_str)
		if err != nil {
			return
		}
		p_path_str = windows.UTF16ToString(p_path_u16_str)
	}

	// file path string
	var f_path_str string
	if f_path_length > 0 {
		f_path_u16_str := make([]uint16, f_path_length/2)
		err = binary.Read(buf, binary.LittleEndian, &f_path_u16_str)
		if err != nil {
			return
		}
		f_path_str = windows.UTF16ToString(f_path_u16_str)
	}

	log_.PID = int32(pid)
	log_.ProcessName = p_path_str
	log_.Resource = f_path_str
	log_.Data = getFileOperation(op)

}

func (s *FilterService) parseFilterMessage(buf []byte) (*Log, error) {

	headerSize := 32 + 64

	if len(buf) < headerSize {
		return nil, fmt.Errorf("invalid message, header too short")
	}

	dataBuf := bytes.NewBuffer(buf)

	// read header
	var header FILTER_MESSAGE_HEADER
	// header->replyLength
	var replyLength uint32
	err := binary.Read(dataBuf, binary.LittleEndian, &replyLength)
	if err != nil {
		return nil, err
	}

	// padding bits
	var padding uint32
	err = binary.Read(dataBuf, binary.LittleEndian, &padding)
	if err != nil {
		return nil, err
	}

	// header->messageId
	var messageId uint64
	err = binary.Read(dataBuf, binary.LittleEndian, &messageId)
	if err != nil {
		return nil, err
	}

	header.ReplyLength = replyLength
	header.MessageId = messageId

	log.Printf("header: %+v", header)

	// timestamp uint64
	var ts uint64
	err = binary.Read(dataBuf, binary.LittleEndian, &ts)
	if err != nil {
		return nil, err
	}
	// type uint32
	var tp uint32
	err = binary.Read(dataBuf, binary.LittleEndian, &tp)
	if err != nil {
		return nil, err
	}
	// operation uint32
	var op uint32
	err = binary.Read(dataBuf, binary.LittleEndian, &op)
	if err != nil {
		return nil, err
	}
	// result
	var blocked bool
	err = binary.Read(dataBuf, binary.LittleEndian, &blocked)
	if err != nil {
		return nil, err
	}

	action := ""
	if tp == 2 {
		action = getAction(blocked)
	}

	log_ := &Log{
		Timestamp: int64(ts),
		Type:      getLogType(tp),
		Operation: getOperationType(op),
		Result:    getResult(blocked),
		Action:    action,
	}

	switch op {
	case 1:
		// handle process operation
	case 2:
		// handle file operation
		handleFileEvent(dataBuf, log_)
	case 3:
		// handle network operation
	default:
		log.Printf("Invalid operation type")
	}

	return log_, nil
}

func (s *FilterService) processorWorker(id int) {
	defer s.wg.Done()

	log.Printf("Processor worker %d started", id)

	var localProcessed uint64

	lastStatsLog := time.Now()

	for {
		select {
		case <-s.stopCh:
			log.Printf("Processor worker %d stopped (processed: %d)", id, localProcessed)
			return
		case msg, ok := <-s.eventChan:
			if !ok {
				log.Printf("Processor worker %d event channel closed", id)
				return
			}

			err := s.processMessage(id, msg)

			if err == nil {
				localProcessed++
			}

			if time.Since(lastStatsLog) > 30*time.Second {
				log.Printf("Worker %d stats: processed=%d", id, localProcessed)
				lastStatsLog = time.Now()
			}
		}

	}
}

func (s *FilterService) processMessage(id int, msg *Log) error {
	switch msg.Type {
	case "1":
		log.Printf("====Log====\n%v", msg)
	default:
		log.Println("invalid log type")
	}

	return nil
}

func (s *FilterService) statsReporter() {
	defer s.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:

			log.Printf("====Stats====\n%v", s.GetServiceStats())
		}
	}
}

func (s *FilterService) GetServiceStats() map[string]interface{} {
	pending := uint64(len(s.eventChan))

	return map[string]interface{}{
		"received":  s.messageReceived.Load(),
		"processed": s.messageProcessed.Load(),
		"pending":   pending,
		"dropped":   s.messageDropped.Load(),
	}

}

func main() {
	svc := NewFilterService(nil)

	if err := svc.Start(); err != nil {
		log.Fatalf("Failed to start service: %v", err)
	}

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-svc.stopCh:
				return
			case <-ticker.C:
				stats := svc.GetServiceStats()
				log.Printf("Service stats: \n%+v", stats)
			}
		}
	}()

	log.Println("Service Running, Press Ctrl+C to stop...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("graceful service shutdown...")
	if err := svc.Stop(); err != nil {
		log.Printf("Error shutting down service: %v", err)
	}

	finalStats := svc.GetServiceStats()
	log.Printf("Final statistics: %+v", finalStats)

	log.Println("service terminated successfully")
}
