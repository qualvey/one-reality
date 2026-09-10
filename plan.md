
## 已经落地

1. 接受ip作为参数->根据公开方式获取该ip的asn->根据asn获取cidr（可以加入缓存功能，有效期3天）

```shell
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169" | jq '.data.prefixes[].prefix'
```

2. 参数也接受国家（比如DE代表德国）get一个cidr对应的国家
  
  mmdb,当前代码已经有mmdb的使用

然后就可以过滤出一个asn里面属于某个国家的cidr list
这个list传给扫描器，就实现了根据ip获取reality targets的全自动实现

## 性能优化
