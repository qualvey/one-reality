import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(
  defineConfig({
    title: 'RealityChecker Docs',
    description: '全自动高可用 REALITY 伪装目标检测与全网扫描引擎',
    lang: 'zh-CN',
    base: '/',
    themeConfig: {
      nav: [
        { text: '首页', link: '/' },
        { text: '演进历史', link: '/evolution/2026-10-24-cert-expire-and-lazy-recheck' },
        { text: '开发计划', link: '/dev/asn-24h-scanner' },
        { text: '维护手册', link: '/version_management' }
      ],
      sidebar: {
        '/evolution/': [
          {
            text: '架构演进历史',
            items: [
              { text: '证书到期时间与按需懒探测', link: '/evolution/2026-10-24-cert-expire-and-lazy-recheck' },
              { text: '故障复盘：智能推荐 CPU 卡死与 O(N²) 修复', link: '/evolution/2026-10-24-smart-api-cpu-freeze-incident' }
            ]
          }
        ],
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
            text: '演进历史',
            items: [
              { text: '证书到期时间与按需懒探测', link: '/evolution/2026-10-24-cert-expire-and-lazy-recheck' },
              { text: '故障复盘：智能推荐 CPU 卡死与 O(N²) 修复', link: '/evolution/2026-10-24-smart-api-cpu-freeze-incident' }
            ]
          },
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
    },
    vite: {
      optimizeDeps: {
        include: ['dayjs', 'mermaid', '@braintree/sanitize-url']
      }
    },
    mermaid: {
      theme: 'default'
    }
  })
)
