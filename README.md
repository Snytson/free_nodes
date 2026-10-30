# free_nodes

定时抓取公开的代理节点分享链接，按协议和出口国家写入 `output/` 

## 输出

| 路径 | 内容 |
| --- | --- |
| `output/protocols/vless.txt` | 可用的 VLESS 节点 |
| `output/protocols/vmess.txt` | 可用的 VMess 节点 |
| `output/protocols/trojan.txt` | 可用的 Trojan 节点 |
| `output/protocols/shadowsocks.txt` | 可用的 Shadowsocks 节点 |
| `output/countries/<CC>.txt` | 按出口国家分组的节点 |
| `output/country_shards/<CC>/<NNN>.txt` | 按国家分页（1000 条/页） |
| `output/metadata/*.json` | 目录索引、应用池、国家列表、测速结果 |
| `output/metadata/catalog_manifest.json` + `.sig` | 签名清单，客户端可校验完整性 |


