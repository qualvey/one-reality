package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/types"
)

// TargetStore REALITY 目标资产持久化数据库
type TargetStore struct {
	mu       sync.RWMutex
	filePath string
	records  map[string]*types.TargetRecord // key: domainLower
}

// NewTargetStore 创建或载入目标资产数据库
func NewTargetStore(filePath string) (*TargetStore, error) {
	if filePath == "" {
		filePath = "data/reality_targets.json"
	}

	store := &TargetStore{
		filePath: filePath,
		records:  make(map[string]*types.TargetRecord),
	}

	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("载入资产库失败: %w", err)
	}

	return store, nil
}

// load 从文件载入记录
func (s *TargetStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var list []*types.TargetRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	for _, rec := range list {
		if rec != nil && rec.Domain != "" {
			s.records[strings.ToLower(rec.Domain)] = rec
		}
	}
	return nil
}

// Save 保存记录到文件
func (s *TargetStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	list := make([]*types.TargetRecord, 0, len(s.records))
	for _, rec := range s.records {
		list = append(list, rec)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, data, 0644)
}

// UpsertTarget 插入或更新单条资产记录
func (s *TargetStore) UpsertTarget(record *types.TargetRecord) error {
	if record == nil || record.Domain == "" {
		return nil
	}

	s.mu.Lock()
	key := strings.ToLower(record.Domain)
	if record.LastCheckedAt.IsZero() {
		record.LastCheckedAt = time.Now()
	}
	s.records[key] = record
	s.mu.Unlock()

	return s.Save()
}

// UpsertTargets 批量插入或更新资产记录
func (s *TargetStore) UpsertTargets(records []*types.TargetRecord) error {
	if len(records) == 0 {
		return nil
	}

	s.mu.Lock()
	now := time.Now()
	for _, record := range records {
		if record != nil && record.Domain != "" {
			key := strings.ToLower(record.Domain)
			if record.LastCheckedAt.IsZero() {
				record.LastCheckedAt = now
			}
			s.records[key] = record
		}
	}
	s.mu.Unlock()

	return s.Save()
}

// GetTargetsByASN 根据 ASN 和 国家 查询未过期的有效资产
func (s *TargetStore) GetTargetsByASN(asn, country string, maxAge time.Duration) ([]*types.TargetRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*types.TargetRecord
	now := time.Now()

	asnNorm := strings.ToUpper(strings.TrimSpace(asn))
	countryNorm := strings.ToUpper(strings.TrimSpace(country))

	for _, rec := range s.records {
		if rec == nil {
			continue
		}

		// 校验 ASN (忽略大小写与 AS 前缀差异)
		recASN := strings.ToUpper(strings.TrimSpace(rec.ASN))
		if asnNorm != "" && recASN != "" {
			if !strings.EqualFold(recASN, asnNorm) &&
				!strings.EqualFold(strings.TrimPrefix(recASN, "AS"), strings.TrimPrefix(asnNorm, "AS")) {
				continue
			}
		}

		// 校验国家 (若指定)
		if countryNorm != "" && rec.Country != "" && !strings.EqualFold(rec.Country, countryNorm) {
			continue
		}

		// 校验缓存时效
		if maxAge > 0 && now.Sub(rec.LastCheckedAt) > maxAge {
			continue
		}

		result = append(result, rec)
	}

	return result, nil
}

// Export 导出所有资产到指定 JSON 文件
func (s *TargetStore) Export(exportPath string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*types.TargetRecord, 0, len(s.records))
	for _, rec := range s.records {
		list = append(list, rec)
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

// Import 从外部 JSON 文件导入资产
func (s *TargetStore) Import(importPath string) (int, error) {
	data, err := os.ReadFile(importPath)
	if err != nil {
		return 0, err
	}

	var list []*types.TargetRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return 0, err
	}

	count := 0
	s.mu.Lock()
	for _, rec := range list {
		if rec != nil && rec.Domain != "" {
			s.records[strings.ToLower(rec.Domain)] = rec
			count++
		}
	}
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		return count, err
	}
	return count, nil
}

// Count 获取当前资产总量
func (s *TargetStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
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
