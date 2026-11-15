// Package mcp 实现一个最小但正确的 MCP stdio 服务（JSON-RPC 2.0）。
// 仅覆盖本服务所需的方法：initialize / notifications/initialized / ping /
// tools/list / tools/call。无需外部 MCP SDK，依赖更少、可控。
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Request 是入站 JSON-RPC 请求。
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response 是出站 JSON-RPC 响应。
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError 是 JSON-RPC 错误对象。
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server 持有 MCP 服务及其依赖，并负责分发请求。
type Server struct {
	dispatch func(req Request) (any, *RPCError)
	out      *bufio.Writer
	mu       chan struct{} // 串行化 stdout 写入
}

// NewServer 创建并初始化 MCP 服务。
func NewServer(dispatch func(req Request) (any, *RPCError)) *Server {
	return &Server{
		dispatch: dispatch,
		out:      bufio.NewWriter(os.Stdout),
		mu:       make(chan struct{}, 1),
	}
}

// Serve 从 stdin 逐行读取 JSON-RPC 请求并处理，直到 EOF。
func (s *Server) Serve(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	// 单条 JSON-RPC 消息最大 64MB。若命令输出过大导致单行超此上限，
	// Scanner 会返回 ErrTooLong 并使 Serve 退出、整个 MCP 进程崩溃，故上限取较大值。
	scanner.Buffer(make([]byte, 0, 4*1024*1024), 64*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			continue // 忽略无法解析的行
		}
		s.handle(req)
	}
	return scanner.Err()
}

func (s *Server) handle(req Request) {
	// 通知类（无 id）无需回复
	if len(req.ID) == 0 {
		if req.Method == "notifications/initialized" {
			return
		}
		// 其他通知忽略
		return
	}
	result, rpcErr := s.dispatch(req)
	resp := Response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rpcErr}
	s.write(resp)
}

func (s *Server) write(resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	s.mu <- struct{}{}
	defer func() { <-s.mu }()
	fmt.Fprintln(s.out, string(data))
	s.out.Flush()
}
