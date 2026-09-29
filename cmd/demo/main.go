// 演示：临时生成主密钥，创建虚构秘密，短期借用、轮换与撤销。
// 主密钥仅存在于内存，进程退出后材料即不可解密。
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"secretmat/secretmat"
)

func main() {
	dir := "./demo-data"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatal(err)
	}
	key, err := secretmat.GenerateMasterKey() // 演示临时主密钥，不保存
	if err != nil {
		log.Fatal(err)
	}
	audit, err := secretmat.OpenAuditLog(dir + "/audit.log")
	if err != nil {
		log.Fatal(err)
	}
	svc, err := secretmat.Open(dir+"/store", key, audit)
	if err != nil {
		log.Fatal(err)
	}

	fake := make([]byte, 32) // 虚构材料，非真实密钥
	rand.Read(fake)
	if err := svc.CreateSecret("demo-db", fake); err != nil {
		log.Fatal(err)
	}
	tok, err := svc.Borrow("demo-db", 5*time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("已签发 5 分钟借用凭据")
	if _, err := svc.Use(tok); err != nil {
		log.Fatal(err)
	}
	fmt.Println("凭据使用成功")

	if _, err := svc.Rotate("demo-db", fake, secretmat.DrainOld); err != nil {
		log.Fatal(err)
	}
	fmt.Println("已轮换到版本 2（drain：旧借用到期前仍可用）")

	if err := svc.Revoke(tok); err != nil {
		log.Fatal(err)
	}
	fmt.Println("已撤销旧凭据；审计见", dir+"/audit.log（不含明文）")
}
