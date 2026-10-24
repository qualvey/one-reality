package cmd

import (
	"flag"
	"os"
	"testing"
)

func TestDaemonFlags(t *testing.T) {
	flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	threads := flags.Int("threads", 500, "扫描并发协程数")
	flags.IntVar(threads, "t", 500, "扫描并发协程数 (缩写)")
	portFlag := flags.Int("port", 8881, "内置 HTTP API 与 Web 控制台监听端口 (0 则禁用 HTTP)")
	hostFlag := flags.String("host", "0.0.0.0", "内置 HTTP 服务监听地址")
	tokenFlag := flags.String("token", "", "API 访问鉴权 Token (留空则不开启鉴权)")
	noHTTP := flags.Bool("no-http", false, "禁用内置 HTTP API 与 Web 控制台")
	cycleIntervalSec := flags.Int("interval", 10, "每轮扫描完成后的等待间隔秒数")

	args := []string{
		"--host", "0.0.0.0",
		"--token", "jjjj",
		"-t", "150",
		"--interval", "10",
	}

	if err := flags.Parse(args); err != nil {
		t.Fatalf("failed to parse daemon args: %v", err)
	}

	if *hostFlag != "0.0.0.0" {
		t.Errorf("expected host 0.0.0.0, got %s", *hostFlag)
	}
	if *tokenFlag != "jjjj" {
		t.Errorf("expected token jjjj, got %s", *tokenFlag)
	}
	if *threads != 150 {
		t.Errorf("expected threads 150, got %d", *threads)
	}
	if *cycleIntervalSec != 10 {
		t.Errorf("expected interval 10, got %d", *cycleIntervalSec)
	}
	if *portFlag != 8881 {
		t.Errorf("expected default port 8881, got %d", *portFlag)
	}
	if *noHTTP {
		t.Errorf("expected noHTTP false, got %v", *noHTTP)
	}
}
