package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Logger struct {
	mu         sync.Mutex
	level      Level
	out        io.Writer
	fileWriter io.WriteCloser
}

var globalLogger *Logger = NewLogger("info", "")

func NewLogger(levelStr string, logFile string) *Logger {
	l := &Logger{
		level: parseLevel(levelStr),
		out:   os.Stdout,
	}
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			l.fileWriter = f
			l.out = io.MultiWriter(os.Stdout, f)
		}
	}
	return l
}

func Init(levelStr string, logFile string) {
	globalLogger = NewLogger(levelStr, logFile)
}

func parseLevel(l string) Level {
	switch strings.ToLower(l) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}


func IsDebug() bool {
	return globalLogger.level <= LevelDebug
}

// safePrint 在打印日志前清掉进度条，打印完毕后让进度条重新出现在下一行
func AboveBar(bar *progressbar.ProgressBar, format string, a ...any) {
	if bar != nil {
		_ = bar.Clear() // 1. 擦除当前行的进度条
	}
	fmt.Printf(format, a...) // 2. 正常打印业务日志（自带换行）
	if bar != nil {
		_ = bar.RenderBlank() // 3. 立即重新在最下方把进度条画出来
	}
}

func Debug(format string, args ...interface{}) {
	if globalLogger.level <= LevelDebug {
		logMsg("DEBUG", format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if globalLogger.level <= LevelInfo {
		logMsg("INFO", format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if globalLogger.level <= LevelWarn {
		logMsg("WARN", format, args...)
	}
}

func Error(format string, args ...interface{}) {
	if globalLogger.level <= LevelError {
		logMsg("ERROR", format, args...)
	}
}

func logMsg(tag string, format string, args ...interface{}) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	timestamp := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(globalLogger.out, "[%s] [%s] %s\n", timestamp, tag, msg)
}

// PrintTimestampedMessage 打印带时间戳的控制台消息（兼容原 ui 包行为并安全输出至 logger 目标）
func PrintTimestampedMessage(format string, args ...interface{}) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	timestamp := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(globalLogger.out, "[%s] %s\n", timestamp, msg)
}

// PrintError 打印错误信息（带空行间距）
func PrintError(message string) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	fmt.Fprintln(globalLogger.out)
	fmt.Fprintln(globalLogger.out, message)
	fmt.Fprintln(globalLogger.out)
}

// PrintErrorWithDetails 打印错误信息和详细说明
func PrintErrorWithDetails(message string, details ...string) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	fmt.Fprintln(globalLogger.out)
	fmt.Fprintln(globalLogger.out, message)
	for _, detail := range details {
		fmt.Fprintln(globalLogger.out, detail)
	}
	fmt.Fprintln(globalLogger.out)
}

