package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const FrontendScanTaskSource = "frontend"

const (
	ScanTaskQueued    = "queued"
	ScanTaskRunning   = "running"
	ScanTaskStopping  = "stopping"
	ScanTaskCompleted = "completed"
	ScanTaskStopped   = "stopped"
	ScanTaskFailed    = "failed"
)

// ScanTaskInfo is the reconnectable state of a frontend-created scan.
// Targets are retained in memory for the lifetime of the task and are also
// persisted by StreamTargets in the normal target store.
type ScanTaskInfo struct {
	TaskID     string             `json:"task_id"`
	Source     string             `json:"source"`
	Status     string             `json:"status"`
	CreatedAt  time.Time          `json:"created_at"`
	StartedAt  *time.Time         `json:"started_at,omitempty"`
	FinishedAt *time.Time         `json:"finished_at,omitempty"`
	Init       *InitEventData     `json:"init,omitempty"`
	Progress   *ProgressEventData `json:"progress,omitempty"`
	Targets    []TargetItem       `json:"targets"`
	Done       *DoneEventData     `json:"done,omitempty"`
	Error      string             `json:"error,omitempty"`
}

type scanTaskEventData struct {
	TaskID     string     `json:"task_id"`
	Source     string     `json:"source"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type frontendScanTask struct {
	mu sync.Mutex

	id        string
	source    string
	request   ProvisionRequest
	createdAt time.Time
	startedAt *time.Time
	endedAt   *time.Time
	status    string
	ctx       context.Context

	init     *InitEventData
	progress *ProgressEventData
	targets  []TargetItem
	done     *DoneEventData
	errText  string

	cancel  context.CancelFunc
	subs    map[int]chan ProvisionEvent
	nextSub int
}

func newFrontendScanTask(req ProvisionRequest) (*frontendScanTask, error) {
	var randomID [8]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, fmt.Errorf("create scan task id: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &frontendScanTask{
		id:        "scan_" + hex.EncodeToString(randomID[:]),
		source:    FrontendScanTaskSource,
		request:   req,
		createdAt: time.Now(),
		status:    ScanTaskQueued,
		ctx:       ctx,
		cancel:    cancel,
		subs:      make(map[int]chan ProvisionEvent),
	}, nil
}

func (t *frontendScanTask) snapshotLocked() ScanTaskInfo {
	info := ScanTaskInfo{
		TaskID:     t.id,
		Source:     t.source,
		Status:     t.status,
		CreatedAt:  t.createdAt,
		StartedAt:  t.startedAt,
		FinishedAt: t.endedAt,
		Init:       t.init,
		Progress:   t.progress,
		Done:       t.done,
		Error:      t.errText,
		Targets:    append([]TargetItem(nil), t.targets...),
	}
	return info
}

func (t *frontendScanTask) taskEventLocked() ProvisionEvent {
	return ProvisionEvent{
		Event: "task",
		Data: scanTaskEventData{
			TaskID:     t.id,
			Source:     t.source,
			Status:     t.status,
			CreatedAt:  t.createdAt,
			StartedAt:  t.startedAt,
			FinishedAt: t.endedAt,
		},
	}
}

func (t *frontendScanTask) publish(evt ProvisionEvent) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch evt.Event {
	case "init":
		if data, ok := evt.Data.(InitEventData); ok {
			copy := data
			t.init = &copy
		}
	case "progress":
		if data, ok := evt.Data.(ProgressEventData); ok {
			copy := data
			t.progress = &copy
		}
	case "target":
		if data, ok := evt.Data.(TargetItem); ok {
			t.targets = append(t.targets, data)
		}
	case "done":
		if data, ok := evt.Data.(DoneEventData); ok && t.done == nil {
			copy := data
			t.done = &copy
			now := time.Now()
			t.endedAt = &now
			t.status = scanTaskStatusForDone(data.Reason)
			t.broadcastLocked(evt)
			t.broadcastLocked(t.taskEventLocked())
			for id, ch := range t.subs {
				close(ch)
				delete(t.subs, id)
			}
			return nil
		}
	case "error":
		if data, ok := evt.Data.(map[string]string); ok {
			t.errText = data["error"]
		}
	}

	t.broadcastLocked(evt)
	return nil
}

func scanTaskStatusForDone(reason string) string {
	if reason == "cancelled" {
		return ScanTaskStopped
	}
	if strings.HasPrefix(reason, "scan_error:") {
		return ScanTaskFailed
	}
	return ScanTaskCompleted
}

func (t *frontendScanTask) broadcastLocked(evt ProvisionEvent) {
	for _, ch := range t.subs {
		select {
		case ch <- evt:
		default:
			if evt.Event == "done" {
				// A slow subscriber may have a full replay buffer. The terminal
				// event must not be lost, otherwise the browser remains stuck in
				// "scanning" until it performs another reconnect.
				select {
				case <-ch:
				default:
				}
				select {
				case ch <- evt:
				default:
				}
				continue
			}
			// Progress is deliberately lossy for a slow/disconnected browser;
			// the latest value is part of the task snapshot and can be recovered
			// on reconnect. Target events are retained in the task snapshot too.
		}
	}
}

func (t *frontendScanTask) setRunning() {
	t.mu.Lock()
	if t.status != ScanTaskQueued {
		t.mu.Unlock()
		return
	}
	now := time.Now()
	t.startedAt = &now
	t.status = ScanTaskRunning
	t.broadcastLocked(t.taskEventLocked())
	t.mu.Unlock()
}

func (t *frontendScanTask) finish(status string, done DoneEventData, errText string) {
	t.mu.Lock()
	if t.done != nil {
		t.mu.Unlock()
		return
	}
	now := time.Now()
	t.endedAt = &now
	t.status = status
	copyDone := done
	t.done = &copyDone
	if errText != "" {
		t.errText = errText
	}
	t.broadcastLocked(ProvisionEvent{Event: "done", Data: copyDone})
	t.broadcastLocked(t.taskEventLocked())
	for id, ch := range t.subs {
		close(ch)
		delete(t.subs, id)
	}
	t.mu.Unlock()
}

func (t *frontendScanTask) subscribe() (<-chan ProvisionEvent, func(), ScanTaskInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Reserve room for the replay snapshot so subscribing can never block the
	// scan while the task mutex is held.
	ch := make(chan ProvisionEvent, len(t.targets)+16)
	ch <- t.taskEventLocked()
	if t.init != nil {
		ch <- ProvisionEvent{Event: "init", Data: *t.init}
	}
	for _, target := range t.targets {
		ch <- ProvisionEvent{Event: "target", Data: target}
	}
	if t.progress != nil {
		ch <- ProvisionEvent{Event: "progress", Data: *t.progress}
	}
	if t.done != nil {
		ch <- ProvisionEvent{Event: "done", Data: *t.done}
		close(ch)
		return ch, func() {}, t.snapshotLocked()
	}

	id := t.nextSub
	t.nextSub++
	t.subs[id] = ch
	return ch, func() {
		t.mu.Lock()
		if existing, ok := t.subs[id]; ok {
			delete(t.subs, id)
			close(existing)
		}
		t.mu.Unlock()
	}, t.snapshotLocked()
}

func (t *frontendScanTask) stop() bool {
	t.mu.Lock()
	if t.status == ScanTaskCompleted || t.status == ScanTaskStopped || t.status == ScanTaskFailed {
		t.mu.Unlock()
		return false
	}
	t.status = ScanTaskStopping
	t.broadcastLocked(t.taskEventLocked())
	cancel := t.cancel
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

// StartFrontendScan creates a background scan owned by the frontend.
func (s *ProvisionService) StartFrontendScan(req ProvisionRequest) (*ScanTaskInfo, error) {
	task, err := newFrontendScanTask(req)
	if err != nil {
		return nil, err
	}

	s.tasksMu.Lock()
	if s.tasks == nil {
		s.tasks = make(map[string]*frontendScanTask)
	}
	s.tasks[task.id] = task
	s.tasksMu.Unlock()

	go s.runFrontendScan(task)
	info := task.snapshot()
	return &info, nil
}

func (t *frontendScanTask) snapshot() ScanTaskInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked()
}

func (s *ProvisionService) runFrontendScan(task *frontendScanTask) {
	task.setRunning()
	err := s.StreamTargets(task.context(), task.request, task.publish)

	if err != nil {
		if task.isStopping() {
			task.finish(ScanTaskStopped, DoneEventData{Reason: "cancelled"}, "")
			return
		}
		task.publish(ProvisionEvent{Event: "error", Data: map[string]string{"error": err.Error()}})
		task.finish(ScanTaskFailed, DoneEventData{Reason: "scan_error: " + err.Error()}, err.Error())
		return
	}

	info := task.snapshot()
	if info.Done != nil {
		return
	}
	if task.isStopping() {
		task.finish(ScanTaskStopped, DoneEventData{Reason: "cancelled"}, "")
		return
	}
	task.finish(ScanTaskCompleted, DoneEventData{Reason: "scan_exhausted"}, "")
}

// context returns the context owned by the task rather than the SSE request.
// Closing a browser connection therefore only unsubscribes it.
func (t *frontendScanTask) context() context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ctx
}

func (t *frontendScanTask) isStopping() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status == ScanTaskStopping || t.status == ScanTaskStopped
}

// GetFrontendScanTask returns the current state and retained result events.
func (s *ProvisionService) GetFrontendScanTask(taskID string) (*ScanTaskInfo, error) {
	s.tasksMu.RLock()
	task := s.tasks[strings.TrimSpace(taskID)]
	s.tasksMu.RUnlock()
	if task == nil || task.source != FrontendScanTaskSource {
		return nil, errors.New("frontend scan task not found")
	}
	info := task.snapshot()
	return &info, nil
}

// SubscribeFrontendScan subscribes to a task without affecting its lifetime.
func (s *ProvisionService) SubscribeFrontendScan(taskID string) (<-chan ProvisionEvent, func(), error) {
	s.tasksMu.RLock()
	task := s.tasks[strings.TrimSpace(taskID)]
	s.tasksMu.RUnlock()
	if task == nil || task.source != FrontendScanTaskSource {
		return nil, nil, errors.New("frontend scan task not found")
	}
	ch, unsubscribe, _ := task.subscribe()
	return ch, unsubscribe, nil
}

// StopFrontendScan stops a task created by the frontend. It is intentionally
// scoped to frontend tasks; other task sources cannot be stopped through this
// endpoint.
func (s *ProvisionService) StopFrontendScan(taskID string) error {
	s.tasksMu.RLock()
	task := s.tasks[strings.TrimSpace(taskID)]
	s.tasksMu.RUnlock()
	if task == nil || task.source != FrontendScanTaskSource {
		return errors.New("frontend scan task not found")
	}
	task.stop()
	return nil
}
