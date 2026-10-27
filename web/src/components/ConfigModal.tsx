import { useState } from 'react';
import type { TargetItem } from '../types';
import { copyText } from '../utils/clipboard';
import { X, Copy, Check, Terminal, ShieldCheck } from 'lucide-react';

interface ConfigModalProps {
  target: TargetItem | null;
  serverIP: string;
  onClose: () => void;
}

export const ConfigModal = ({ target, serverIP, onClose }: ConfigModalProps) => {
  const [format, setFormat] = useState<'singbox' | 'xray' | 'clash'>('singbox');
  const [copied, setCopied] = useState(false);

  if (!target) return null;

  // 辅助随机生成测试用的 UUID 和 8位 short_id
  const randomUUID = '12345678-1234-4321-abcd-123456789abc';
  const randomShortID = 'a1b2c3d4';
  const effectiveIP = serverIP || target.ip || 'YOUR_SERVER_IP';

  const generateConfig = () => {
    switch (format) {
      case 'singbox':
        return JSON.stringify(
          {
            type: 'vless',
            tag: `reality-${target.domain}`,
            server: effectiveIP,
            server_port: 443,
            uuid: randomUUID,
            flow: 'xtls-rprx-vision',
            tls: {
              enabled: true,
              server_name: target.domain,
              utls: {
                enabled: true,
                fingerprint: 'chrome',
              },
              reality: {
                enabled: true,
                public_key: 'YOUR_REALITY_PUBLIC_KEY',
                short_id: randomShortID,
              },
            },
          },
          null,
          2
        );
      case 'xray':
        return JSON.stringify(
          {
            tag: `proxy-${target.domain}`,
            protocol: 'vless',
            settings: {
              vnext: [
                {
                  address: effectiveIP,
                  port: 443,
                  users: [
                    {
                      id: randomUUID,
                      flow: 'xtls-rprx-vision',
                      encryption: 'none',
                    },
                  ],
                },
              ],
            },
            streamSettings: {
              network: 'tcp',
              security: 'reality',
              realitySettings: {
                show: false,
                fingerprint: 'chrome',
                serverName: target.domain,
                publicKey: 'YOUR_REALITY_PUBLIC_KEY',
                shortId: randomShortID,
                spiderX: '/',
              },
            },
          },
          null,
          2
        );
      case 'clash':
        return `
- name: "REALITY-${target.domain}"
  type: vless
  server: ${effectiveIP}
  port: 443
  uuid: ${randomUUID}
  network: tcp
  tls: true
  udp: true
  flow: xtls-rprx-vision
  servername: ${target.domain}
  reality-opts:
    public-key: YOUR_REALITY_PUBLIC_KEY
    short-id: ${randomShortID}
  client-fingerprint: chrome
`.trim();
    }
  };

  const codeStr = generateConfig();

  const handleCopy = async () => {
    if (await copyText(codeStr)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-icon-wrapper" style={{ width: '32px', height: '32px' }}>
              <ShieldCheck size={18} />
            </div>
            <div>
              <h3 className="modal-title">导出客户端 REALITY 配置</h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                伪装域名: <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{target.domain}</span>
              </p>
            </div>
          </div>
          <button className="btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          {(['singbox', 'xray', 'clash'] as const).map((fmt) => (
            <button
              key={fmt}
              className={`btn btn-secondary ${format === fmt ? 'active' : ''}`}
              style={{
                flex: 1,
                borderColor: format === fmt ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                background: format === fmt ? 'rgba(56, 189, 248, 0.15)' : undefined,
                color: format === fmt ? '#ffffff' : 'var(--text-muted)',
              }}
              onClick={() => setFormat(fmt)}
            >
              <Terminal size={14} />
              {fmt === 'singbox' ? 'sing-box' : fmt === 'xray' ? 'Xray' : 'Clash Meta'}
            </button>
          ))}
        </div>

        <div style={{ position: 'relative' }}>
          <pre className="code-preview-block">{codeStr}</pre>
          <button
            className="btn btn-primary"
            style={{
              position: 'absolute',
              top: '12px',
              right: '12px',
              padding: '6px 14px',
              fontSize: '0.8rem',
            }}
            onClick={handleCopy}
          >
            {copied ? <Check size={14} /> : <Copy size={14} />}
            {copied ? '已复制' : '复制配置'}
          </button>
        </div>

        <div style={{ fontSize: '0.78rem', color: 'var(--text-sub)', lineHeight: 1.4 }}>
          💡 提示：请将生成的配置片段粘贴到客户端的 outbounds / proxies 列表中，并替换为您服务端的真实 public_key。
        </div>
      </div>
    </div>
  );
};
