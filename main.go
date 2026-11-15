// ssh-mcp-go：全量重写的 SSH MCP 服务（Go）。
// 相比原 ssh-mcp，重点增强了"对话式审批"：命令/路径被策略拦截时，
// 不再直接失败，而是提示用户用 approve_last / deny_last 工具决定是否放宽，
// 放宽后自动写入配置（热重载）并重试。原服务不修改，本程序为完整替代实现。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"ssh-mcp-go/internal/approval"
	"ssh-mcp-go/internal/config"
	"ssh-mcp-go/internal/mcp"
	"ssh-mcp-go/internal/ssh"
)

func main() {
	configPath := flag.String("config", "ssh-mcp.toml", "配置文件路径")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	stop, err := cfg.Watch()
	if err != nil {
		// 配置文件尚不存在时无法监听，属正常情况（由向导生成后 EnsureWatch 补上）
		log.Printf("提示: 热重载监听暂未启动（%v）", err)
	} else {
		defer stop()
	}
	if cfg.NeedsSetup {
		log.Printf("提示: 未找到有效配置（%s），请先调用 setup-wizard 工具完成配置。", *configPath)
	}

	pool := ssh.NewPool(cfg)
	mgr := approval.NewManager()
	handler := mcp.NewHandler(cfg, pool, mgr)
	server := mcp.NewServer(handler.Dispatch)

	fmt.Fprintln(os.Stderr, "ssh-mcp-go 已启动，监听 stdio (MCP)")
	if err := server.Serve(os.Stdin); err != nil {
		log.Fatalf("服务异常: %v", err)
	}
}
