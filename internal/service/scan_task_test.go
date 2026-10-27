package service

import "testing"

func TestFrontendScanTaskNeverDropsDoneEvent(t *testing.T) {
	task, err := newFrontendScanTask(ProvisionRequest{IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("newFrontendScanTask failed: %v", err)
	}

	ch, unsubscribe, _ := task.subscribe()
	defer unsubscribe()

	// Fill the subscriber buffer with lossy progress events before publishing
	// the terminal event. A reconnectable task must still notify a live client
	// that scanning has ended.
	for i := 0; i < 100; i++ {
		if err := task.publish(ProvisionEvent{
			Event: "progress",
			Data:  ProgressEventData{ScannedIPs: int64(i)},
		}); err != nil {
			t.Fatalf("publish progress failed: %v", err)
		}
	}
	if err := task.publish(ProvisionEvent{
		Event: "done",
		Data:  DoneEventData{Reason: "scan_exhausted"},
	}); err != nil {
		t.Fatalf("publish done failed: %v", err)
	}

	foundDone := false
	for event := range ch {
		if event.Event == "done" {
			foundDone = true
		}
	}
	if !foundDone {
		t.Fatal("subscriber did not receive terminal done event")
	}
}
