# 本地秘密材料服务（secretmat）

用 Go 组织的虚构秘密材料管理服务，供后续示例应用接入。

## 能力

- **版本化秘密**：每个秘密按版本存储，材料以 AES-GCM 加密落盘（`store/state.json`），绝不存明文。
- **短期借用**：`Borrow` 签发限时凭据，`Use` 校验并取回材料；到期（`ErrBorrowExpired`）或主动撤销（`ErrBorrowRevoked`）后不再有效，重复撤销返回 `ErrAlreadyRevoked`。
- **轮换**：`Rotate` 声明收尾规则——`DrainOld`（旧借用保留至到期）或 `RevokeOld`（旧借用立即撤销）；新借用一律使用新版本。
- **存储与使用记录分离**：审计写入独立的 `audit.log`，只含事件类型、秘密 ID、版本号与凭据哈希，不含材料明文。
- **临时主密钥**：`GenerateMasterKey` 仅在演示时生成于内存，不落盘；丢失后重开返回 `ErrUndecryptable`，材料明确不可解密。
- **真实密钥不参与**：服务只接受调用方传入的虚构材料字节。

## 使用

```go
key, _ := secretmat.GenerateMasterKey()      // 演示临时主密钥
audit, _ := secretmat.OpenAuditLog("data/audit.log")
svc, _ := secretmat.Open("data/store", key, audit)

svc.CreateSecret("db", fakeMaterial)        // 虚构材料
tok, _ := svc.Borrow("db", 5*time.Minute)   // 短期借用
material, err := svc.Use(tok)               // 校验并取用
svc.Rotate("db", newFake, secretmat.DrainOld)
svc.Revoke(tok)                             // 主动撤销
```

## 运行

```sh
go test ./...    # 覆盖重启、过期、重复撤销、轮换策略、密钥丢失、审计无明文
go run ./cmd/demo
```
