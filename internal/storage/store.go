package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/types"

	_ "modernc.org/sqlite"
)

// TargetStore REALITY 目标资产 SQLite 持久化数据库
type TargetStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// NewTargetStore 创建或打开 SQLite 目标资产数据库
func NewTargetStore(dbPath string) (*TargetStore, error) {
	if dbPath == "" {
		dbPath = "data/reality_targets.db"
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 数据库失败: %w", err)
	}

	// 限制单个文件连接池
	db.SetMaxOpenConns(1)

	store := &TargetStore{
		db: db,
	}

	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化数据库表结构失败: %w", err)
	}

	return store, nil
}

// initSchema 创建表和索引
func (s *TargetStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS reality_targets (
		domain TEXT PRIMARY KEY,
		asn TEXT NOT NULL,
		country TEXT NOT NULL,
		ip TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 443,
		handshake_ms INTEGER NOT NULL,
		cert_days INTEGER NOT NULL,
		cert_expire_at DATETIME,
		tags TEXT NOT NULL DEFAULT '',
		status_code INTEGER NOT NULL,
		page_title TEXT,
		is_cdn INTEGER NOT NULL DEFAULT 0,
		is_hot INTEGER NOT NULL DEFAULT 0,
		is_default_page INTEGER NOT NULL DEFAULT 0,
		default_page_type TEXT,
		stars INTEGER NOT NULL DEFAULT 0,
		is_active INTEGER NOT NULL DEFAULT 1,
		check_fail_count INTEGER NOT NULL DEFAULT 0,
		first_seen_at DATETIME,
		last_checked_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_targets_asn ON reality_targets (asn);
	CREATE INDEX IF NOT EXISTS idx_targets_country ON reality_targets (country);
	CREATE INDEX IF NOT EXISTS idx_targets_asn_country ON reality_targets (asn, country);
	CREATE INDEX IF NOT EXISTS idx_targets_last_checked ON reality_targets (last_checked_at);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// 动态检测并平滑升级 reality_targets 旧表列结构
	targetCols := make(map[string]bool)
	if rows, err := s.db.Query("PRAGMA table_info(reality_targets)"); err == nil {
		for rows.Next() {
			var cid, notnull, pk int
			var name, ctype string
			var dfltValue any
			_ = rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
			targetCols[name] = true
		}
		rows.Close()
	}
	if !targetCols["port"] {
		_, _ = s.db.Exec("ALTER TABLE reality_targets ADD COLUMN port INTEGER NOT NULL DEFAULT 443")
	}
	if !targetCols["is_active"] {
		_, _ = s.db.Exec("ALTER TABLE reality_targets ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
	}
	if !targetCols["check_fail_count"] {
		_, _ = s.db.Exec("ALTER TABLE reality_targets ADD COLUMN check_fail_count INTEGER NOT NULL DEFAULT 0")
	}
	if !targetCols["first_seen_at"] {
		_, _ = s.db.Exec("ALTER TABLE reality_targets ADD COLUMN first_seen_at DATETIME")
		_, _ = s.db.Exec("UPDATE reality_targets SET first_seen_at = last_checked_at WHERE first_seen_at IS NULL")
	}
	if !targetCols["cert_expire_at"] {
		_, _ = s.db.Exec("ALTER TABLE reality_targets ADD COLUMN cert_expire_at DATETIME")
		_, _ = s.db.Exec("UPDATE reality_targets SET cert_expire_at = datetime(last_checked_at, '+' || cert_days || ' days') WHERE cert_expire_at IS NULL")
	}
	if !targetCols["tags"] {
		_, _ = s.db.Exec("ALTER TABLE reality_targets ADD COLUMN tags TEXT NOT NULL DEFAULT ''")
	}

	// 创建依赖新列的索引
	if _, err := s.db.Exec("CREATE INDEX IF NOT EXISTS idx_targets_stars_active ON reality_targets (stars DESC, is_active)"); err != nil {
		return err
	}

	// 全球 ASN 任务注册表
	asnSchema := `
	CREATE TABLE IF NOT EXISTS asn_registry (
		asn INTEGER PRIMARY KEY,
		name TEXT NOT NULL DEFAULT '',
		country TEXT NOT NULL DEFAULT '',
		total_ips INTEGER NOT NULL DEFAULT 0,
		priority INTEGER NOT NULL DEFAULT 10,
		scan_status TEXT NOT NULL DEFAULT 'pending',
		last_scanned_at DATETIME,
		success_target_count INTEGER NOT NULL DEFAULT 0,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_asn_priority_status ON asn_registry (priority DESC, scan_status);
	CREATE INDEX IF NOT EXISTS idx_asn_country ON asn_registry (country);
	`
	if _, err := s.db.Exec(asnSchema); err != nil {
		return err
	}

	// 存量资产健康巡检日志表
	patrolSchema := `
	CREATE TABLE IF NOT EXISTS target_patrol_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		ip TEXT NOT NULL,
		handshake_ms INTEGER NOT NULL,
		is_success INTEGER NOT NULL,
		error_msg TEXT,
		checked_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_patrol_domain_checked ON target_patrol_logs (domain, checked_at);
	`
	if _, err := s.db.Exec(patrolSchema); err != nil {
		return err
	}

	// 检查并自动升级 scan_checkpoints 旧表结构
	var hasLastIP bool
	rows, err := s.db.Query("PRAGMA table_info(scan_checkpoints)")
	if err == nil {
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dfltValue any
			_ = rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
			if name == "last_ip" {
				hasLastIP = true
			}
		}
		rows.Close()
	}
	if !hasLastIP {
		_, _ = s.db.Exec("DROP TABLE IF EXISTS scan_checkpoints")
	}

	cpSchema := `
	CREATE TABLE IF NOT EXISTS scan_checkpoints (
		task_key TEXT NOT NULL,
		cidr TEXT NOT NULL,
		last_ip TEXT NOT NULL DEFAULT '',
		completed INTEGER NOT NULL DEFAULT 0,
		updated_at DATETIME NOT NULL,
		PRIMARY KEY (task_key, cidr)
	);
	CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON scan_checkpoints (task_key);
	`
	_, err = s.db.Exec(cpSchema)
	return err
}

// Close 关闭数据库连接
func (s *TargetStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// UpsertTarget 插入或更新单条资产记录
func (s *TargetStore) UpsertTarget(record *types.TargetRecord) error {
	if record == nil || record.Domain == "" {
		return nil
	}
	return s.UpsertTargets([]*types.TargetRecord{record})
}

// UpsertTargets 批量插入或更新资产记录（事务安全）
func (s *TargetStore) UpsertTargets(records []*types.TargetRecord) error {
	if len(records) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT INTO reality_targets (
			domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
			page_title, is_cdn, is_hot, is_default_page, default_page_type,
			stars, is_active, check_fail_count, first_seen_at, last_checked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			asn = excluded.asn,
			country = excluded.country,
			ip = excluded.ip,
			port = excluded.port,
			handshake_ms = excluded.handshake_ms,
			cert_days = excluded.cert_days,
			cert_expire_at = CASE WHEN excluded.cert_expire_at IS NOT NULL THEN excluded.cert_expire_at ELSE reality_targets.cert_expire_at END,
			tags = CASE WHEN excluded.tags != '' THEN excluded.tags ELSE reality_targets.tags END,
			status_code = excluded.status_code,
			page_title = excluded.page_title,
			is_cdn = excluded.is_cdn,
			is_hot = excluded.is_hot,
			is_default_page = excluded.is_default_page,
			default_page_type = excluded.default_page_type,
			stars = excluded.stars,
			is_active = excluded.is_active,
			check_fail_count = excluded.check_fail_count,
			last_checked_at = excluded.last_checked_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now()
	for _, rec := range records {
		if rec == nil || rec.Domain == "" {
			continue
		}
		domainKey := strings.ToLower(strings.TrimSpace(rec.Domain))
		lastChecked := rec.LastCheckedAt
		if lastChecked.IsZero() {
			lastChecked = now
		}
		firstSeen := rec.FirstSeenAt
		if firstSeen.IsZero() {
			firstSeen = lastChecked
		}
		port := rec.Port
		if port <= 0 {
			port = 443
		}

		isCDN := 0
		if rec.IsCDN {
			isCDN = 1
		}
		isHot := 0
		if rec.IsHot {
			isHot = 1
		}
		isDefault := 0
		if rec.IsDefaultPage {
			isDefault = 1
		}
		isActive := 1
		if !rec.IsActive && rec.CheckFailCount > 0 {
			isActive = 0
		}

		var certExpireAtAny any = nil
		if !rec.CertExpireAt.IsZero() {
			certExpireAtAny = rec.CertExpireAt
		} else if rec.CertDays > 0 {
			certExpireAtAny = lastChecked.Add(time.Duration(rec.CertDays) * 24 * time.Hour)
		}
		tagsJoined := strings.Join(rec.Tags, ",")

		_, err := stmt.Exec(
			domainKey,
			strings.ToUpper(strings.TrimSpace(rec.ASN)),
			strings.ToUpper(strings.TrimSpace(rec.Country)),
			rec.IP,
			port,
			rec.HandshakeMS,
			rec.CertDays,
			certExpireAtAny,
			tagsJoined,
			rec.StatusCode,
			rec.PageTitle,
			isCDN,
			isHot,
			isDefault,
			rec.DefaultPageType,
			rec.Stars,
			isActive,
			rec.CheckFailCount,
			firstSeen,
			lastChecked,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func scanTargetRecord(scanner interface{ Scan(dest ...any) error }) (*types.TargetRecord, error) {
	var rec types.TargetRecord
	var port, isCDN, isHot, isDefault, isActive, checkFailCount int
	var pageTitle, defaultPageType, tagsStr sql.NullString
	var firstSeenAt, certExpireAt sql.NullTime

	err := scanner.Scan(
		&rec.Domain,
		&rec.ASN,
		&rec.Country,
		&rec.IP,
		&port,
		&rec.HandshakeMS,
		&rec.CertDays,
		&certExpireAt,
		&tagsStr,
		&rec.StatusCode,
		&pageTitle,
		&isCDN,
		&isHot,
		&isDefault,
		&defaultPageType,
		&rec.Stars,
		&isActive,
		&checkFailCount,
		&firstSeenAt,
		&rec.LastCheckedAt,
	)
	if err != nil {
		return nil, err
	}

	rec.Port = port
	if rec.Port <= 0 {
		rec.Port = 443
	}
	rec.IsCDN = (isCDN == 1)
	rec.IsHot = (isHot == 1)
	rec.IsDefaultPage = (isDefault == 1)
	rec.IsActive = (isActive == 1)
	rec.CheckFailCount = checkFailCount
	if firstSeenAt.Valid {
		rec.FirstSeenAt = firstSeenAt.Time
	} else {
		rec.FirstSeenAt = rec.LastCheckedAt
	}
	if certExpireAt.Valid {
		rec.CertExpireAt = certExpireAt.Time
		rec.CertDays = rec.GetRemainingDays()
	}
	if tagsStr.Valid && strings.TrimSpace(tagsStr.String) != "" {
		for _, t := range strings.Split(tagsStr.String, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				rec.Tags = append(rec.Tags, t)
			}
		}
	}
	if pageTitle.Valid {
		rec.PageTitle = pageTitle.String
	}
	if defaultPageType.Valid {
		rec.DefaultPageType = defaultPageType.String
	}

	return &rec, nil
}

// GetTargetsByASN 根据 ASN 和 国家 查询未过期的有效资产
func (s *TargetStore) GetTargetsByASN(asn, country string, maxAge time.Duration) ([]*types.TargetRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	asnNorm := strings.ToUpper(strings.TrimSpace(asn))
	countryNorm := strings.ToUpper(strings.TrimSpace(country))

	asnWithPrefix := asnNorm
	if !strings.HasPrefix(asnWithPrefix, "AS") && asnWithPrefix != "" {
		asnWithPrefix = "AS" + asnWithPrefix
	}
	asnWithoutPrefix := strings.TrimPrefix(asnNorm, "AS")

	query := `
		SELECT domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, is_active, check_fail_count, first_seen_at, last_checked_at
		FROM reality_targets
		WHERE (asn = ? OR asn = ?) AND is_active = 1
	`
	args := []interface{}{asnWithPrefix, asnWithoutPrefix}

	if countryNorm != "" {
		query += " AND (country = ? OR country = '')"
		args = append(args, countryNorm)
	}

	if maxAge > 0 {
		minTime := time.Now().Add(-maxAge)
		query += " AND last_checked_at >= ?"
		args = append(args, minTime)
	}

	query += " ORDER BY stars DESC, handshake_ms ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.TargetRecord
	for rows.Next() {
		rec, err := scanTargetRecord(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}

	return results, rows.Err()
}

// GetAllTargets 获取数据库中全部资产记录
func (s *TargetStore) GetAllTargets() ([]*types.TargetRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, is_active, check_fail_count, first_seen_at, last_checked_at
		FROM reality_targets
		ORDER BY stars DESC, handshake_ms ASC
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.TargetRecord
	for rows.Next() {
		rec, err := scanTargetRecord(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}

	return results, rows.Err()
}

// Export 导出所有资产到指定 JSON 文件
func (s *TargetStore) Export(exportPath string) error {
	list, err := s.GetAllTargets()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(exportPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(exportPath, data, 0644)
}

// Import 从外部 JSON 文件导入资产到 SQLite
func (s *TargetStore) Import(importPath string) (int, error) {
	data, err := os.ReadFile(importPath)
	if err != nil {
		return 0, err
	}

	var list []*types.TargetRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return 0, err
	}

	if err := s.UpsertTargets(list); err != nil {
		return 0, err
	}
	return len(list), nil
}

// Count 获取当前资产总量
func (s *TargetStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM reality_targets").Scan(&count)
	return count
}

// DetectionResultToRecord 将流水线检测结果转化为资产持久化对象
func DetectionResultToRecord(res *types.DetectionResult, asn, country, ip string, stars int) *types.TargetRecord {
	if res == nil {
		return nil
	}

	now := time.Now()
	rec := &types.TargetRecord{
		ASN:           asn,
		Country:       country,
		Domain:        res.Domain,
		IP:            ip,
		Port:          443,
		Stars:         stars,
		IsActive:      true,
		FirstSeenAt:   now,
		LastCheckedAt: now,
	}

	if res.TLS != nil {
		ms := res.TLS.HandshakeTime.Milliseconds()
		if ms == 0 && res.TLS.HandshakeTime > 0 {
			ms = 1
		}
		rec.HandshakeMS = ms
	}

	if res.Certificate != nil {
		rec.CertDays = res.Certificate.DaysUntilExpiry
		rec.CertExpireAt = res.Certificate.NotAfter
	}

	if res.Network != nil {
		rec.StatusCode = res.Network.StatusCode
		rec.PageTitle = res.Network.PageTitle
		rec.IsDefaultPage = res.Network.IsDefaultPage
		rec.DefaultPageType = res.Network.DefaultPageType
	}

	if res.CDN != nil {
		rec.IsCDN = res.CDN.IsCDN
		rec.IsHot = res.CDN.IsHotWebsite
	}

	return rec
}

// RecordToDetectionResult 将资产记录转化为 DetectionResult 供流水线复核或渲染
func RecordToDetectionResult(rec *types.TargetRecord) *types.DetectionResult {
	if rec == nil {
		return nil
	}

	res := &types.DetectionResult{
		Domain:   rec.Domain,
		Suitable: true,
		Network: &types.NetworkResult{
			Accessible:      true,
			StatusCode:      rec.StatusCode,
			PageTitle:       rec.PageTitle,
			IsDefaultPage:   rec.IsDefaultPage,
			DefaultPageType: rec.DefaultPageType,
		},
		TLS: &types.TLSResult{
			SupportsTLS13:  true,
			SupportsX25519: true,
			SupportsHTTP2:  true,
			HandshakeTime:  time.Duration(rec.HandshakeMS) * time.Millisecond,
		},
		Certificate: &types.CertificateResult{
			Valid:           true,
			DaysUntilExpiry: rec.GetRemainingDays(),
			NotAfter:        rec.CertExpireAt,
		},
		CDN: &types.CDNResult{
			IsCDN:        rec.IsCDN,
			IsHotWebsite: rec.IsHot,
		},
		SNI: &types.SNIResult{
			SNIMatch: true,
		},
	}

	if rec.StatusCode >= 200 && rec.StatusCode < 400 {
		res.StatusCodeCategory = types.StatusCodeCategorySafe
	} else {
		res.StatusCodeCategory = types.StatusCodeCategoryExcluded
	}

	return res
}

// CheckpointRecord 扫描断点记录
type CheckpointRecord struct {
	TaskKey   string    `json:"task_key"`
	CIDR      string    `json:"cidr"`
	LastIP    string    `json:"last_ip"`
	Completed bool      `json:"completed"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GetCheckpoints 获取某个任务的所有断点记录
func (s *TargetStore) GetCheckpoints(taskKey string) (map[string]*CheckpointRecord, error) {
	if s == nil || s.db == nil || taskKey == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT cidr, last_ip, completed, updated_at FROM scan_checkpoints WHERE task_key = ?", taskKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	checkpoints := make(map[string]*CheckpointRecord)
	for rows.Next() {
		var cidr, lastIP string
		var completedInt int
		var updatedAt time.Time
		if err := rows.Scan(&cidr, &lastIP, &completedInt, &updatedAt); err == nil {
			checkpoints[cidr] = &CheckpointRecord{
				TaskKey:   taskKey,
				CIDR:      cidr,
				LastIP:    lastIP,
				Completed: completedInt == 1,
				UpdatedAt: updatedAt,
			}
		}
	}
	return checkpoints, nil
}

// RecordCheckpoint 记录某个网段的断点进度（支持指定最后扫描的 IP 和是否完成）
func (s *TargetStore) RecordCheckpoint(taskKey, cidr, lastIP string, completed bool) error {
	if s == nil || s.db == nil || taskKey == "" || cidr == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	completedInt := 0
	if completed {
		completedInt = 1
	}

	_, err := s.db.Exec(`
		INSERT INTO scan_checkpoints (task_key, cidr, last_ip, completed, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(task_key, cidr) DO UPDATE SET 
			last_ip = excluded.last_ip,
			completed = excluded.completed,
			updated_at = excluded.updated_at
	`, taskKey, cidr, lastIP, completedInt, time.Now())
	return err
}

// ClearCheckpoints 清空某个任务的断点记录（如全量扫描已全部成功完成）
func (s *TargetStore) ClearCheckpoints(taskKey string) error {
	if s == nil || s.db == nil || taskKey == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM scan_checkpoints WHERE task_key = ?", taskKey)
	return err
}

// UpsertASNRecords 批量插入或更新 ASN 注册表元数据
func (s *TargetStore) UpsertASNRecords(records []*types.ASNRecord) error {
	if len(records) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT INTO asn_registry (
			asn, name, country, total_ips, priority, scan_status, last_scanned_at, success_target_count, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(asn) DO UPDATE SET
			name = CASE WHEN excluded.name != '' THEN excluded.name ELSE asn_registry.name END,
			country = CASE WHEN excluded.country != '' THEN excluded.country ELSE asn_registry.country END,
			total_ips = CASE WHEN excluded.total_ips > 0 THEN excluded.total_ips ELSE asn_registry.total_ips END,
			priority = excluded.priority,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now()
	for _, rec := range records {
		if rec == nil || rec.ASN <= 0 {
			continue
		}
		status := rec.ScanStatus
		if status == "" {
			status = "pending"
		}
		prio := rec.Priority
		if prio < 0 {
			prio = 0
		}
		updatedAt := rec.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = now
		}
		var lastScanned any
		if !rec.LastScannedAt.IsZero() {
			lastScanned = rec.LastScannedAt
		}

		_, err := stmt.Exec(
			rec.ASN,
			rec.Name,
			strings.ToUpper(strings.TrimSpace(rec.Country)),
			rec.TotalIPs,
			prio,
			status,
			lastScanned,
			rec.SuccessTargetCount,
			updatedAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetNextPendingASN 获取下一个待扫描的 ASN（支持高优先级优先）
func (s *TargetStore) GetNextPendingASN(minPriority int) (*types.ASNRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		SELECT asn, name, country, total_ips, priority, scan_status, last_scanned_at, success_target_count, updated_at
		FROM asn_registry
		WHERE scan_status = 'pending'
	`
	var args []any
	if minPriority > 0 {
		query += " AND priority >= ?"
		args = append(args, minPriority)
	}
	query += " ORDER BY priority DESC, last_scanned_at ASC NULLS FIRST, asn ASC LIMIT 1"

	var rec types.ASNRecord
	var lastScanned sql.NullTime
	err := s.db.QueryRow(query, args...).Scan(
		&rec.ASN,
		&rec.Name,
		&rec.Country,
		&rec.TotalIPs,
		&rec.Priority,
		&rec.ScanStatus,
		&lastScanned,
		&rec.SuccessTargetCount,
		&rec.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lastScanned.Valid {
		rec.LastScannedAt = lastScanned.Time
	}

	return &rec, nil
}

// UpdateASNStatus 更新指定 ASN 的扫描状态及命中数增量
func (s *TargetStore) UpdateASNStatus(asn int, status string, successCountDelta int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if status == "completed" {
		_, err := s.db.Exec(`
			UPDATE asn_registry
			SET scan_status = ?,
			    success_target_count = success_target_count + ?,
			    last_scanned_at = ?,
			    updated_at = ?
			WHERE asn = ?
		`, status, successCountDelta, now, now, asn)
		return err
	}

	_, err := s.db.Exec(`
		UPDATE asn_registry
		SET scan_status = ?,
		    success_target_count = success_target_count + ?,
		    updated_at = ?
		WHERE asn = ?
	`, status, successCountDelta, now, asn)
	return err
}

// UpdateASNPriority 更新指定 ASN 的调度优先级
func (s *TargetStore) UpdateASNPriority(asn int, priority int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE asn_registry SET priority = ?, updated_at = ? WHERE asn = ?", priority, time.Now(), asn)
	return err
}

// GetASN 获取单个 ASN 信息
func (s *TargetStore) GetASN(asn int) (*types.ASNRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rec types.ASNRecord
	var lastScanned sql.NullTime
	err := s.db.QueryRow(`
		SELECT asn, name, country, total_ips, priority, scan_status, last_scanned_at, success_target_count, updated_at
		FROM asn_registry
		WHERE asn = ?
	`, asn).Scan(
		&rec.ASN,
		&rec.Name,
		&rec.Country,
		&rec.TotalIPs,
		&rec.Priority,
		&rec.ScanStatus,
		&lastScanned,
		&rec.SuccessTargetCount,
		&rec.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lastScanned.Valid {
		rec.LastScannedAt = lastScanned.Time
	}
	return &rec, nil
}

// CountASNs 统计 ASN 总数（支持按状态过滤）
func (s *TargetStore) CountASNs(status string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT COUNT(*) FROM asn_registry"
	var args []any
	if status != "" {
		query += " WHERE scan_status = ?"
		args = append(args, status)
	}

	var count int
	err := s.db.QueryRow(query, args...).Scan(&count)
	return count, err
}

// ListASNs 查询 ASN 列表
func (s *TargetStore) ListASNs(status string, minPriority, limit, offset int) ([]*types.ASNRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT asn, name, country, total_ips, priority, scan_status, last_scanned_at, success_target_count, updated_at
		FROM asn_registry
		WHERE 1=1
	`
	var args []any
	if status != "" {
		query += " AND scan_status = ?"
		args = append(args, status)
	}
	if minPriority > 0 {
		query += " AND priority >= ?"
		args = append(args, minPriority)
	}
	query += " ORDER BY priority DESC, asn ASC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
		if offset > 0 {
			query += " OFFSET ?"
			args = append(args, offset)
		}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*types.ASNRecord
	for rows.Next() {
		var rec types.ASNRecord
		var lastScanned sql.NullTime
		if err := rows.Scan(
			&rec.ASN,
			&rec.Name,
			&rec.Country,
			&rec.TotalIPs,
			&rec.Priority,
			&rec.ScanStatus,
			&lastScanned,
			&rec.SuccessTargetCount,
			&rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if lastScanned.Valid {
			rec.LastScannedAt = lastScanned.Time
		}
		list = append(list, &rec)
	}
	return list, rows.Err()
}

// ResetScanningASNs 将所有异常残留的 scanning 状态重置为 pending
func (s *TargetStore) ResetScanningASNs() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE asn_registry SET scan_status = 'pending' WHERE scan_status = 'scanning'")
	return err
}

// ResetAllASNsStatus 将全部非 CDN ASN 状态重置为 pending（保留 priority=0 纯商业 CDN 为 completed）
func (s *TargetStore) ResetAllASNsStatus() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE asn_registry SET scan_status = 'pending' WHERE priority > 0")
	return err
}

// InsertPatrolLog 写入一条存量资产健康巡检日志
func (s *TargetStore) InsertPatrolLog(log *types.PatrolLogRecord) error {
	if log == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	checkedAt := log.CheckedAt
	if checkedAt.IsZero() {
		checkedAt = time.Now()
	}
	isSuccess := 0
	if log.IsSuccess {
		isSuccess = 1
	}

	_, err := s.db.Exec(`
		INSERT INTO target_patrol_logs (domain, ip, handshake_ms, is_success, error_msg, checked_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, log.Domain, log.IP, log.HandshakeMS, isSuccess, log.ErrorMsg, checkedAt)
	return err
}

// CleanExpiredPatrolLogs 清理超期巡检日志（默认仅保留最近 7 天）
func (s *TargetStore) CleanExpiredPatrolLogs(retention time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-retention)
	res, err := s.db.Exec("DELETE FROM target_patrol_logs WHERE checked_at <= ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UpdateTargetPatrolResult 根据巡检探测结果更新目标资产状态并记录日志
func (s *TargetStore) UpdateTargetPatrolResult(domain, ip string, handshakeMS int64, certDays int, success bool, errStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	isSuccessInt := 0
	if success {
		isSuccessInt = 1
		// 巡检成功：重置连续失败次数为 0，确保 is_active=1，平滑加权计算握手延迟，更新证书天数
		_, err = tx.Exec(`
			UPDATE reality_targets
			SET is_active = 1,
			    check_fail_count = 0,
			    handshake_ms = CASE WHEN handshake_ms > 0 THEN (handshake_ms + ?) / 2 ELSE ? END,
			    cert_days = CASE WHEN ? > 0 THEN ? ELSE cert_days END,
			    last_checked_at = ?
			WHERE domain = ?
		`, handshakeMS, handshakeMS, certDays, certDays, now, strings.ToLower(domain))
	} else {
		// 巡检失败：失败计数+1，连续失败3次及以上则标记下架 is_active=0，并执行降星（最小为0）
		_, err = tx.Exec(`
			UPDATE reality_targets
			SET check_fail_count = check_fail_count + 1,
			    is_active = CASE WHEN check_fail_count + 1 >= 3 THEN 0 ELSE is_active END,
			    stars = CASE WHEN stars > 0 THEN stars - 1 ELSE 0 END,
			    last_checked_at = ?
			WHERE domain = ?
		`, now, strings.ToLower(domain))
	}
	if err != nil {
		return err
	}

	// 记录巡检明细日志
	_, err = tx.Exec(`
		INSERT INTO target_patrol_logs (domain, ip, handshake_ms, is_success, error_msg, checked_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, domain, ip, handshakeMS, isSuccessInt, errStr, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetTargetsForPatrol 获取需要复测巡检的目标资产列表
func (s *TargetStore) GetTargetsForPatrol(minStars int, olderThan time.Duration, limit int) ([]*types.TargetRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-olderThan)
	query := `
		SELECT domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, is_active, check_fail_count, first_seen_at, last_checked_at
		FROM reality_targets
		WHERE is_active = 1 AND stars >= ? AND last_checked_at <= ?
		ORDER BY stars DESC, last_checked_at ASC
	`
	var args []any
	args = append(args, minStars, cutoff)
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.TargetRecord
	for rows.Next() {
		rec, err := scanTargetRecord(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	return results, rows.Err()
}

// DeleteExpiredInactiveTargets 物理删除连续失效超过指定时长的僵尸资产
func (s *TargetStore) DeleteExpiredInactiveTargets(inactiveDuration time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-inactiveDuration)
	res, err := s.db.Exec("DELETE FROM reality_targets WHERE is_active = 0 AND last_checked_at <= ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RunWALCheckpoint 执行 SQLite WAL 检查点整理，截断归档日志，释放磁盘空间
func (s *TargetStore) RunWALCheckpoint() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

// QueryTargets 分页与多维度条件检索目标资产
func (s *TargetStore) QueryTargets(opts types.TargetQueryOptions) ([]*types.TargetRecord, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	whereClauses := []string{"1=1"}
	args := []any{}

	if kw := strings.TrimSpace(opts.Keyword); kw != "" {
		likePattern := "%" + kw + "%"
		whereClauses = append(whereClauses, "(domain LIKE ? OR ip LIKE ? OR page_title LIKE ?)")
		args = append(args, likePattern, likePattern, likePattern)
	}

	if asn := strings.TrimSpace(opts.ASN); asn != "" {
		asnNorm := strings.ToUpper(asn)
		withAS := asnNorm
		if !strings.HasPrefix(withAS, "AS") {
			withAS = "AS" + withAS
		}
		withoutAS := strings.TrimPrefix(asnNorm, "AS")
		whereClauses = append(whereClauses, "(asn = ? OR asn = ?)")
		args = append(args, withAS, withoutAS)
	}

	if country := strings.TrimSpace(opts.Country); country != "" {
		whereClauses = append(whereClauses, "country = ?")
		args = append(args, strings.ToUpper(country))
	}

	if opts.MinStars > 0 {
		whereClauses = append(whereClauses, "stars >= ?")
		args = append(args, opts.MinStars)
	}

	if opts.IsActive != nil {
		activeInt := 0
		if *opts.IsActive {
			activeInt = 1
		}
		whereClauses = append(whereClauses, "is_active = ?")
		args = append(args, activeInt)
	}

	if opts.RequireNoCDN != nil {
		cdnVal := 0
		if !*opts.RequireNoCDN {
			cdnVal = 1
		}
		whereClauses = append(whereClauses, "is_cdn = ?")
		args = append(args, cdnVal)
	}

	if opts.RequireNoHot != nil {
		hotVal := 0
		if !*opts.RequireNoHot {
			hotVal = 1
		}
		whereClauses = append(whereClauses, "is_hot = ?")
		args = append(args, hotVal)
	}

	if opts.RequireNoDefaultPage != nil {
		defaultVal := 0
		if !*opts.RequireNoDefaultPage {
			defaultVal = 1
		}
		whereClauses = append(whereClauses, "is_default_page = ?")
		args = append(args, defaultVal)
	}

	if opts.MaxHandshakeMS > 0 {
		whereClauses = append(whereClauses, "handshake_ms > 0 AND handshake_ms <= ?")
		args = append(args, opts.MaxHandshakeMS)
	}

	if opts.MinCertDays > 0 {
		whereClauses = append(whereClauses, "cert_days >= ?")
		args = append(args, opts.MinCertDays)
	}

	if len(opts.ExcludeStatus) > 0 {
		placeholders := make([]string, len(opts.ExcludeStatus))
		for i, code := range opts.ExcludeStatus {
			placeholders[i] = "?"
			args = append(args, code)
		}
		whereClauses = append(whereClauses, fmt.Sprintf("status_code NOT IN (%s)", strings.Join(placeholders, ",")))
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	// 1. 查询符合条件的总数
	countQuery := "SELECT COUNT(*) FROM reality_targets WHERE " + whereSQL
	var total int
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// 2. 排序方式
	orderSQL := "ORDER BY stars DESC, handshake_ms ASC"
	switch opts.SortBy {
	case "handshake_asc":
		orderSQL = "ORDER BY handshake_ms ASC, stars DESC"
	case "recent_desc":
		orderSQL = "ORDER BY last_checked_at DESC"
	case "stars_desc":
		orderSQL = "ORDER BY stars DESC, handshake_ms ASC"
	}

	// 3. 分页
	limit := opts.PageSize
	if limit <= 0 {
		limit = 20
	}
	page := opts.Page
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	dataQuery := fmt.Sprintf(`
		SELECT domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, is_active, check_fail_count, first_seen_at, last_checked_at
		FROM reality_targets
		WHERE %s
		%s
		LIMIT ? OFFSET ?
	`, whereSQL, orderSQL)

	dataArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.db.Query(dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []*types.TargetRecord
	for rows.Next() {
		rec, err := scanTargetRecord(rows)
		if err != nil {
			return nil, 0, err
		}
		results = append(results, rec)
	}

	return results, total, rows.Err()
}

// UpdateTargetActive 快速切换资产的激活/禁用状态
func (s *TargetStore) UpdateTargetActive(domain string, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	activeInt := 0
	if active {
		activeInt = 1
	}

	_, err := s.db.Exec("UPDATE reality_targets SET is_active = ? WHERE domain = ?", activeInt, strings.ToLower(strings.TrimSpace(domain)))
	return err
}

// DeleteTarget 物理删除单条资产
func (s *TargetStore) DeleteTarget(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM reality_targets WHERE domain = ?", strings.ToLower(strings.TrimSpace(domain)))
	return err
}

// GetStats 获取资产全景统计指标
func (s *TargetStore) GetStats() (*types.TargetStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &types.TargetStats{
		CountryCounts: make(map[string]int),
		StarCounts:    make(map[int]int),
	}

	// 总数与活跃数、五星数
	_ = s.db.QueryRow(`
		SELECT 
			COUNT(*),
			COALESCE(SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN stars >= 5 THEN 1 ELSE 0 END), 0),
			COALESCE(AVG(CASE WHEN is_active = 1 AND handshake_ms > 0 THEN handshake_ms END), 0)
		FROM reality_targets
	`).Scan(&stats.TotalTargets, &stats.ActiveTargets, &stats.FiveStarTargets, &stats.AvgHandshakeMS)

	// 去重 ASN 总数
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT asn) FROM reality_targets WHERE asn != ''").Scan(&stats.TotalASNs)

	// 国家分布
	if rows, err := s.db.Query("SELECT country, COUNT(*) FROM reality_targets WHERE country != '' GROUP BY country ORDER BY COUNT(*) DESC LIMIT 20"); err == nil {
		for rows.Next() {
			var country string
			var count int
			if err := rows.Scan(&country, &count); err == nil {
				stats.CountryCounts[country] = count
			}
		}
		rows.Close()
	}

	// 星级分布
	if rows, err := s.db.Query("SELECT stars, COUNT(*) FROM reality_targets GROUP BY stars"); err == nil {
		for rows.Next() {
			var stars, count int
			if err := rows.Scan(&stars, &count); err == nil {
				stats.StarCounts[stars] = count
			}
		}
		rows.Close()
	}

	return stats, nil
}

// UpdateTargetCertRenewal 更新目标资产的证书续期探测状态与标签
func (s *TargetStore) UpdateTargetCertRenewal(domain string, certExpireAt time.Time, certDays int, tags []string, handshakeMS int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	tagsStr := strings.Join(tags, ",")

	var expireVal any = nil
	if !certExpireAt.IsZero() {
		expireVal = certExpireAt
	}

	_, err := s.db.Exec(`
		UPDATE reality_targets
		SET cert_expire_at = ?,
		    cert_days = ?,
		    tags = ?,
		    handshake_ms = CASE WHEN ? > 0 THEN ? ELSE handshake_ms END,
		    last_checked_at = ?
		WHERE domain = ?
	`, expireVal, certDays, tagsStr, handshakeMS, handshakeMS, now, strings.ToLower(strings.TrimSpace(domain)))
	return err
}




