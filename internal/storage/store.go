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
		handshake_ms INTEGER NOT NULL,
		cert_days INTEGER NOT NULL,
		status_code INTEGER NOT NULL,
		page_title TEXT,
		is_cdn INTEGER NOT NULL DEFAULT 0,
		is_hot INTEGER NOT NULL DEFAULT 0,
		is_default_page INTEGER NOT NULL DEFAULT 0,
		default_page_type TEXT,
		stars INTEGER NOT NULL DEFAULT 0,
		last_checked_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_targets_asn ON reality_targets (asn);
	CREATE INDEX IF NOT EXISTS idx_targets_country ON reality_targets (country);
	CREATE INDEX IF NOT EXISTS idx_targets_asn_country ON reality_targets (asn, country);
	CREATE INDEX IF NOT EXISTS idx_targets_last_checked ON reality_targets (last_checked_at);

	CREATE TABLE IF NOT EXISTS scan_checkpoints (
		task_key TEXT NOT NULL,
		cidr TEXT NOT NULL,
		completed_at DATETIME NOT NULL,
		PRIMARY KEY (task_key, cidr)
	);
	CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON scan_checkpoints (task_key);
	`
	_, err := s.db.Exec(schema)
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
			domain, asn, country, ip, handshake_ms, cert_days, status_code,
			page_title, is_cdn, is_hot, is_default_page, default_page_type,
			stars, last_checked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			asn = excluded.asn,
			country = excluded.country,
			ip = excluded.ip,
			handshake_ms = excluded.handshake_ms,
			cert_days = excluded.cert_days,
			status_code = excluded.status_code,
			page_title = excluded.page_title,
			is_cdn = excluded.is_cdn,
			is_hot = excluded.is_hot,
			is_default_page = excluded.is_default_page,
			default_page_type = excluded.default_page_type,
			stars = excluded.stars,
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

		_, err := stmt.Exec(
			domainKey,
			strings.ToUpper(strings.TrimSpace(rec.ASN)),
			strings.ToUpper(strings.TrimSpace(rec.Country)),
			rec.IP,
			rec.HandshakeMS,
			rec.CertDays,
			rec.StatusCode,
			rec.PageTitle,
			isCDN,
			isHot,
			isDefault,
			rec.DefaultPageType,
			rec.Stars,
			lastChecked,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
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
		SELECT domain, asn, country, ip, handshake_ms, cert_days, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, last_checked_at
		FROM reality_targets
		WHERE (asn = ? OR asn = ?)
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
		var rec types.TargetRecord
		var isCDN, isHot, isDefault int
		var pageTitle, defaultPageType sql.NullString

		err := rows.Scan(
			&rec.Domain,
			&rec.ASN,
			&rec.Country,
			&rec.IP,
			&rec.HandshakeMS,
			&rec.CertDays,
			&rec.StatusCode,
			&pageTitle,
			&isCDN,
			&isHot,
			&isDefault,
			&defaultPageType,
			&rec.Stars,
			&rec.LastCheckedAt,
		)
		if err != nil {
			return nil, err
		}

		rec.IsCDN = (isCDN == 1)
		rec.IsHot = (isHot == 1)
		rec.IsDefaultPage = (isDefault == 1)
		if pageTitle.Valid {
			rec.PageTitle = pageTitle.String
		}
		if defaultPageType.Valid {
			rec.DefaultPageType = defaultPageType.String
		}

		results = append(results, &rec)
	}

	return results, rows.Err()
}

// GetAllTargets 获取数据库中全部资产记录
func (s *TargetStore) GetAllTargets() ([]*types.TargetRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT domain, asn, country, ip, handshake_ms, cert_days, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, last_checked_at
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
		var rec types.TargetRecord
		var isCDN, isHot, isDefault int
		var pageTitle, defaultPageType sql.NullString

		err := rows.Scan(
			&rec.Domain,
			&rec.ASN,
			&rec.Country,
			&rec.IP,
			&rec.HandshakeMS,
			&rec.CertDays,
			&rec.StatusCode,
			&pageTitle,
			&isCDN,
			&isHot,
			&isDefault,
			&defaultPageType,
			&rec.Stars,
			&rec.LastCheckedAt,
		)
		if err != nil {
			return nil, err
		}

		rec.IsCDN = (isCDN == 1)
		rec.IsHot = (isHot == 1)
		rec.IsDefaultPage = (isDefault == 1)
		if pageTitle.Valid {
			rec.PageTitle = pageTitle.String
		}
		if defaultPageType.Valid {
			rec.DefaultPageType = defaultPageType.String
		}

		results = append(results, &rec)
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

	rec := &types.TargetRecord{
		ASN:           asn,
		Country:       country,
		Domain:        res.Domain,
		IP:            ip,
		Stars:         stars,
		LastCheckedAt: time.Now(),
	}

	if res.TLS != nil {
		rec.HandshakeMS = res.TLS.HandshakeTime.Milliseconds()
	}

	if res.Certificate != nil {
		rec.CertDays = res.Certificate.DaysUntilExpiry
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
			DaysUntilExpiry: rec.CertDays,
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

// GetCompletedCIDRs 获取某个任务已完成扫描的 CIDR 集合
func (s *TargetStore) GetCompletedCIDRs(taskKey string) (map[string]bool, error) {
	if s == nil || s.db == nil || taskKey == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT cidr FROM scan_checkpoints WHERE task_key = ?", taskKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	completed := make(map[string]bool)
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err == nil {
			completed[cidr] = true
		}
	}
	return completed, nil
}

// RecordCompletedCIDR 记录单条已完成扫描的 CIDR
func (s *TargetStore) RecordCompletedCIDR(taskKey, cidr string) error {
	if s == nil || s.db == nil || taskKey == "" || cidr == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO scan_checkpoints (task_key, cidr, completed_at)
		VALUES (?, ?, ?)
		ON CONFLICT(task_key, cidr) DO UPDATE SET completed_at = excluded.completed_at
	`, taskKey, cidr, time.Now())
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

