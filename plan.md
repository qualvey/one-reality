## 已经落地

1. 接受ip作为参数->根据公开方式获取该ip的asn->根据asn获取cidr（可以加入缓存功能，有效期3天）

```shell
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169" | jq '.data.prefixes[].prefix'
```

2. 参数也接受国家（比如DE代表德国）get一个cidr对应的国家

mmdb,当前代码已经有mmdb的使用

然后就可以过滤出一个asn里面属于某个国家的cidr list
这个list传给扫描器，就实现了根据ip获取reality targets的全自动实现

3. 线路机与落地机解耦优先扫描（已落地）：
- 核心四大线路机国家（美国 US、中国香港 HK、日本 JP、德国 DE）；
- 硬编码精准排除家宽 ISP 与商业 CDN（Anycast 反代）；
- 核心国纯机房 ASN 自动赋予高调度权重（`Priority >= 85`），商业 CDN 赋 0 且预设 completed；
- Daemon 调度器天然以高优双队列优先消耗美/港/日/德机房，大幅提升优质 REALITY 节点发现效率。

## 性能优化

## 设计

在现代布局中，线路机和落地机肯定是要分开的。
而能做线路机的国家，全球就那么几个，而且线路机一定是机房。

美国，香港，日本，德国
所以，daemon优先扫描以上country的纯机房asn，可以大大提高效率。

