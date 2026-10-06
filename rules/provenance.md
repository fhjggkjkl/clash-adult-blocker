# 成人网站域名规则来源

本目录使用 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 官方仓库的 `category-porn` 分类规则，下载日期为 2026-10-04（中国标准时间）。未下载或合并广告、恶意软件、社交网站等其他分类。

- 分支：`meta`。
- 固定提交：`0b354375b24a493049d1f9e0e8517b3b6311702f`。
- 固定原文件：[category-porn.yaml](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/0b354375b24a493049d1f9e0e8517b3b6311702f/geo/geosite/category-porn.yaml)。
- 上游最新文件：[category-porn.yaml](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-porn.yaml)。本地文件是快照，不会自行更新。
- 本地 `adult-domains.yaml` 保留原文件字节，SHA-256：`1cc1105023ef9f3d02f4d4a8b2f6f52bde6e92c4c99bb1867a79f91477eaf946`。
- 规则数量：6,520 项。其中 5 项为精确域名，6,515 项为 `+.` 前缀的域名后缀规则；无重复项。

`adult-domains.yaml` 适用于 Clash/Mihomo 的 `behavior: domain` 规则提供者。`+.example.com` 同时匹配该域名及其子域名；原文件中的精确域名保持精确匹配，避免扩大到共享服务的整个平台。

`adult-rules-legacy.yaml` 是相同快照的普通 `rules` 列表导出：精确项转为 `DOMAIN,域名,REJECT`，后缀项转为 `DOMAIN-SUFFIX,域名,REJECT`。它是用于合并到现有配置的片段，需要把这些规则放在已有放行或代理规则之前；它本身没有代理节点，不是完整的 VPN 配置。

规则分类由社区维护，可能有遗漏、过期域名或误判。共享网站上的成人页面不会因页面内容而自动识别。这里没有访问成人网页或下载成人图片；仅取得维护者提供的域名文本。实际拦截还取决于 Chrome 流量是否经过 Clash、规则模式及规则优先级。

## 许可证与作者归属

保留 MetaCubeX 官方 README 于 `upstream-readme.md`，该 README 明确规则集位于 `meta` 分支，并列出数据来源与致谢。

- MetaCubeX/meta-rules-dat：[官方仓库许可证](https://github.com/MetaCubeX/meta-rules-dat/blob/master/LICENSE)，GNU GPL v3 全文保留于 `LICENSE-MetaCubeX.txt`。这是仓库许可证；不宣称其替代上游数据各自的许可证。
- v2fly/domain-list-community：[项目](https://github.com/v2fly/domain-list-community)、[MIT 许可证](https://github.com/v2fly/domain-list-community/blob/master/LICENSE)，版权所有 © 2018–2019 V2Ray；通知保留于 `LICENSE-v2fly-MIT.txt`。
- Loyalsoldier/domain-list-custom：[项目](https://github.com/Loyalsoldier/domain-list-custom)、[MIT 许可证](https://github.com/Loyalsoldier/domain-list-custom/blob/master/LICENSE)，版权所有 © 2020 Loyalsoldier；通知保留于 `LICENSE-Loyalsoldier-MIT.txt`。

来源清单、原始快照和上述通知一起保留；转换仅改变规则表示方式，没有人工增删成人分类条目。维护者不为本地导出的规则或拦截效果背书。
