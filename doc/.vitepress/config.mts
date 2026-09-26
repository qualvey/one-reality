import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'RealityChecker Docs',
  description: '全自动高可用 REALITY 伪装目标检测与全网扫描引擎',
  lang: 'zh-CN',
  base: '/',
  themeConfig: {
    nav: [
      { text: '首页', link: '/' },
      { text: '开发计划', link: '/dev/asn-24h-scanner' },
      { text: '维护手册', link: '/version_management' }
    ],
    sidebar: {
      '/dev/': [
        {
          text: '系统演进与开发计划',
          items: [
            { text: '24小时 ASN 全网扫描架构', link: '/dev/asn-24h-scanner' },
            { text: '数据库模型与生命周期', link: '/dev/database-and-lifecycle' }
          ]
        }
      ],
      '/': [
        {
          text: '开发与演进',
          items: [
            { text: '24小时 ASN 全网扫描架构', link: '/dev/asn-24h-scanner' },
            { text: '数据库模型与生命周期', link: '/dev/database-and-lifecycle' }
          ]
        },
        {
          text: '系统运维与问题排查',
          items: [
            { text: '版本发布规范', link: '/version_management' },
            { text: '并发与卡死问题排查', link: '/卡死' }
          ]
        }
      ]
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/V2RaySSR/RealityChecker' }
    ],
    search: {
      provider: 'local'
    },
    outline: {
      level: [2, 3],
      label: '页面导航'
    },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 RealityChecker Team'
    }
  }
})
