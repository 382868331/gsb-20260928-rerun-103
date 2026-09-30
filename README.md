# 本地虚构秘密材料服务

这是一个纯本地 Go 服务包，用来给后续示例应用管理虚构秘密材料的版本、短期借用与轮换。

## 当前能力

- 材料经 AES-256-GCM 加密后保存在 `secret-materials.json`。
- 借用凭据保存有效期和 SHA-256 令牌哈希；原始令牌只在签发时返回，文件位置为 `lease-credentials.json`。
- 使用记录单独追加到 `usage-audit.jsonl`，只记录材料名、版本、借用 ID、主密钥 ID、动作、结果和原因。
- 借用必须声明用途（purpose）和访问范围（`material:read`、`metadata:view`、`audit:read`）；借用在签发时固定材料版本，不能拿某用途的借用读取另一版本或执行未授权操作。
- 借用到期、撤销后均无法继续取出材料；重复撤销保持幂等，进程重启后也不会复活。
- 轮换后的新借用自动指向新版本；旧借用支持 `until_expiry`、`grace_period` 或 `batch_end` 三种收尾规则，`EndOldLeaseBatch` 支持逐批结束旧借用。
- `RotateMasterKey` 用新的进程内主密钥重封全部版本（保留版本 ID）；单次原子写入保证重封失败后旧密钥仍可用、撤销状态不回滚。
- 查询接口按范围分流：`Inspect` 只返回非密元数据，`AuditTrail` 只返回该借用自身的审计事件，公开错误和审计内容不含材料原文或可复用凭据。
- 进程重启会保留加密材料、借用和审计，但解密只在仍持有同一把进程内主密钥时有效。

## 主密钥边界

演示主密钥通过 `GenerateDemoMasterKey()` 在进程启动时临时生成，不会写入材料文件、凭据文件或审计日志。

如果进程重启并生成新的主密钥：

- 旧版本仍保留在磁盘上，但调用 `Use` 会得到包含 `ErrMaterialCannotDecrypt` 的错误。
- 可以轮换材料并继续签发新版本借用。
- 旧版本不会也不能被新主密钥“恢复”解密。
- 真实用户密钥、外部 KMS 密钥或任何生产密钥材料都不参与本演示。

## 快速验证

```bash
go test ./...
go vet ./...
```

最小接入方式见 `cmd/demo/main.go`。三个数据文件有意分开，删除或替换其中一个时可以分别观察材料、凭据和审计边界。

```bash
go run ./cmd/demo -dir /tmp/local-materials-demo
```
