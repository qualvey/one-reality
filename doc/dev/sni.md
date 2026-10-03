
如果扫描器只是“盲连 IP 发起裸握手”（不带任何 SNI，或带 IP 作为 SNI），确实会漏掉大量依赖 SNI 的真实业务域名。

主要会漏掉以下这几种情况：

1. 漏掉同一个 IP 上的其他虚拟主机
现象：一台服务器用 Nginx 托管了 3 个不同域名的站点（比如 site-a.com、site-b.com、site-c.com），分别配置了不同的证书。
结果：直接扫 IP 只能拿到 default_server（比如 site-a.com）的证书，site-b.com 和 site-c.com 会被完全漏掉。
2. 漏掉开启了“SNI 白名单/防扫”的站点（直接判定为离线）
现象：目标启用了现代 Web 防御配置（如 Nginx 的 ssl_reject_handshake on;）。
结果：客户端不带合法 SNI 域名发起握手时，服务器直接断开 TLS 连接（Alert/Reset）。扫描器会误以为该 IP 的 443 端口根本没开服务或握手失败，整个 IP 直接被漏掉。
3. CDN 与云反代节点（彻底失效）
现象：像 Cloudflare、Akamai、各大 CDN 的边缘节点 IP，一个 IP 后面挂着数百万个域名。
结果：裸扫该 IP 要么拿到 CDN 供应商的占位证书（如 *.cloudflare.com），要么直接报错，完全扫不出背后实际解析的业务域名。
常见的弥补与优化方案
如果你想增强扫描器、减少遗漏，业内通常有以下几种补救策略：

① 从已经拿到的证书中挖掘 SAN (Subject Alternative Name)
即使只拿到了 default_server 的证书，也一定要解析该证书的 SAN 扩展：

一张证书往往包含多个子域名（如 example.com、api.example.com、admin.example.com）。
把这些 SAN 域名提取出来，就能顺藤摸瓜发现该 IP 关联的更多有效域名。
② 结合“反查/被动资产库”补充 SNI 字典
先通过 被动 DNS、证书透明度日志（CT Logs 如 crt.sh）、Censys / Shodan 等接口查询：该 IP 历史上解析过哪些域名。
拿到候选域名后，扫描器在 TLS 握手时显式把这些域名填入 ClientHello.ServerName (SNI) 逐一复测，就能拿到被隐藏的其他证书。
③ 针对 Reality 场景的考量
如果你扫描 IP 是为了找 Reality 目标偷跑域名 (Target/ServerNames)：

裸扫 IP 拿到的 default_server 证书里的域名是最稳妥、最容易成功的（因为目标服务器默认就认它）。
但如果目标站设置了 ssl_reject_handshake on，就必须依赖“先知域名（预先准备好的 SNI 字典）”带着 SNI 去探测 IP，才能完成 Reality 的握手偷跑。