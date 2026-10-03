package storage

import (
	"io"
	"time"

	"RealityChecker/internal/types"
)

// Store 是 REALITY 资产、任务调度与巡检存储引擎的统一接口抽象
type Store interface {
	io.Closer

	// 1. 资产核心操作
	UpsertTarget(record *types.TargetRecord) error
	UpsertTargets(records []*types.TargetRecord) error
	GetTargetsByASN(asn, country string, maxAge time.Duration) ([]*types.TargetRecord, error)
	GetAllTargets() ([]*types.TargetRecord, error)
	QueryTargets(opts types.TargetQueryOptions) ([]*types.TargetRecord, int, error)
	UpdateTargetActive(domain string, active bool) error
	DeleteTarget(domain string) error
	Count() int
	Export(exportPath string) error
	Import(importPath string) (int, error)
	GetStats() (*types.TargetStats, error)

	// 2. 扫描网段断点续传
	GetCheckpoints(taskKey string) (map[string]*CheckpointRecord, error)
	RecordCheckpoint(taskKey, cidr, lastIP string, completed bool) error
	ClearCheckpoints(taskKey string) error

	// 3. 全球 ASN 任务调度与状态机
	UpsertASNRecords(records []*types.ASNRecord) error
	GetNextPendingASN(minPriority int) (*types.ASNRecord, error)
	UpdateASNStatus(asn int, status string, successCountDelta int) error
	UpdateASNPriority(asn int, priority int) error
	GetASN(asn int) (*types.ASNRecord, error)
	CountASNs(status string) (int, error)
	ListASNs(status string, minPriority, limit, offset int) ([]*types.ASNRecord, error)
	ResetScanningASNs() error
	ResetAllASNsStatus() error

	// 4. 存量资产健康巡检与生命周期
	InsertPatrolLog(log *types.PatrolLogRecord) error
	CleanExpiredPatrolLogs(retention time.Duration) (int64, error)
	UpdateTargetPatrolResult(domain, ip string, handshakeMS int64, certDays int, success bool, errStr string) error
	GetTargetsForPatrol(minStars int, olderThan time.Duration, limit int) ([]*types.TargetRecord, error)
	DeleteExpiredInactiveTargets(inactiveDuration time.Duration) (int64, error)

	// 5. 存储引擎自维护 (SQLite: WAL checkpoint; PostgreSQL: ANALYZE / VACUUM)
	RunWALCheckpoint() error
}

// 静态编译断言: 确保 TargetStore 完整实现了 Store 接口
var _ Store = (*TargetStore)(nil)
