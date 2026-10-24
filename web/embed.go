package web

import (
	"embed"
	"io/fs"
)

//go:embed dist/*
var distFS embed.FS

// DistFS 返回静态资源子文件系统
func DistFS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return distFS
	}
	return sub
}

// HasDist 检查内嵌的前端资源是否存在有效 index.html
func HasDist() bool {
	f, err := distFS.Open("dist/index.html")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
