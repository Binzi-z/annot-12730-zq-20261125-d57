package main

import "testing"

// TestRunAllDrills 通过 go test 驱动全部 10 个演练场景，
// 与 `go run ./cmd/drill` 走完全相同的 runAll 代码路径。
func TestRunAllDrills(t *testing.T) {
	if code := runAll(); code != 0 {
		t.Fatalf("演练存在失败断言，退出码 %d", code)
	}
}
