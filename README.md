# free_nodes

定时抓取公开的代理节点分享链接，用固定版本的 sing-box 逐个验证连通性，**只保留真正可用的节点**，按协议和出口国家写入 `output/` 并自动发布。

## 工作流程

1. **抓取**：每 8 小时自动运行（UTC 00/08/16，北京时间 08:00 / 16:00 / 00:00），读取 `sources/sources.json`、`sources/telegram_channels.json`、V2Nodes，以及 FreeProxyDB、OutlineKeys、ClashXW、ShareDaily、Kort0881、FreeV2rayNodes 等来源。
2. **验证**：候选节点切成 8 个分片并行测试，每个节点单独启动一个 sing-box 进程，通过它真实请求 Cloudflare、Google、Microsoft、example.com；校验 TLS 证书，不跟随重定向。
3. **测速**：连通成功的节点再下载一次 1 MiB 样本，作为排序依据。
4. **发布**：按协议、按国家生成订阅文件并签名，推送到仓库；整轮没有可用节点时保留上一次结果，不会发布空目录。

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

## 运行方式

- **自动**：`.github/workflows/update.yml` 每 8 小时触发一次，无需人工操作。
- **手动**：Actions → Update node catalog → Run workflow。
  - `publish_run_id` 留空 = 完整扫描；
  - 填入某次已完成运行的 ID = 只复用那次保存的候选与分片结果重新发布（用于发布失败后的补救，artifacts 保留 7 天）。

## 需要配置的 Secret

`CATALOG_SIGNING_PRIVATE_KEY_B64`：ECDSA P-256 私钥 PEM 的 Base64（单行）。签名公钥存放在 `data/catalog_signing_public_key.pem`，发布时脚本会用 openssl 自检签名是否与公钥匹配。

## 本地调试

```bash
pip install -r requirements.txt
export SINGBOX_BINARY=/path/to/sing-box
python -m unittest -v tests.test_singbox_pipeline
```

采集与发布链路不依赖 sing-box 的测试：

```bash
python tests/test_share_link_extractor.py
python tests/test_publish_snapshot.py
python tests/test_country_resolver.py
python tests/test_source_freshness.py
```
