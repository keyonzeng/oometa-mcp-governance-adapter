# OOMeta MCP Governance Adapter — 合规策略模板库

本目录包含 OOMeta 预置的治理策略模板，作为 mcp-control-plane 策略引擎的差异化扩展。

## 模板列表

| 模板 | 适用场景 | 默认效果 | 合规框架 |
|------|---------|---------|---------|
| `oometa-soc2.yaml` | SOC 2 合规环境 | deny | SOC 2 CC6/CC7 |
| `oometa-hipaa.yaml` | HIPAA 受保护健康信息 | deny | HIPAA §164.312 |
| `oometa-gdpr.yaml` | GDPR 数据保护 | deny | GDPR Art. 5/25/32 |
| `oometa-financial.yaml` | 金融行业 MCP 治理 | require_approval | PCI DSS + SOX |
| `oometa-iso-42001.yaml` | ISO 42001 AI 管理体系 | deny | ISO 42001 Annex A.7 |
| `oometa-baseline.yaml` | 通用企业基线 | require_approval | NIST AI RMF |
| `oometa-rate-limit.yaml` | 速率限制 | allow | 防滥用/DoS |
| `oometa-cost-tracking.yaml` | 成本追踪 | allow | 预算控制/告警 |
