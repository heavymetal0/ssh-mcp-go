// Package mcp 实现一个最小但正确的 MCP stdio 服务（JSON-RPC 2.0）。
// 仅覆盖本服务所需的方法：initialize / notifications/initialized / ping /
// tools/list / tools/call。无需外部 MCP SDK，依赖更少、可控。
package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sync"
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

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server 持有 MCP 服务及其依赖，并负责分发请求。
type Server struct {
	dispatch func(req Request) (any, *RPCError)
	out      *bufio.Writer
	mu       sync.Mutex // 串行化 stdout 写入（转发等后台 goroutine 未来也可能写）
}

func NewServer(dispatch func(req Request) (any, *RPCError)) *Server {
	return &Server{
		dispatch: dispatch,
		out:      bufio.NewWriter(os.Stdout),
	}
}

// Serve 从 stdin 逐行读取 JSON-RPC 请求并处理，直到 EOF。
// scanner 上限约束的是"入站请求行"（例如超长的 command 参数），
// 命令输出由 defaults.max_output_bytes 在 ssh 层截断，两者互不相干。
func (s *Server) Serve(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 256*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			// 不能静默丢弃：客户端会一直等响应直到超时。
			// 无法从坏帧里取到 id，按规范回 id:null + -32700。
			s.write(Response{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &RPCError{Code: -32700, Message: "parse error: " + err.Error()},
			})
			continue
		}
		s.handle(req)
	}
	return scanner.Err()
}

func (s *Server) handle(req Request) {
	// 通知类（无 id）无需回复
	if len(req.ID) == 0 {
		return
	}
	result, rpcErr := s.dispatch(req)
	resp := Response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rpcErr}
	s.write(resp)
}

func (s *Server) write(resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		// 结果无法序列化时也必须给客户端一个明确响应
		data, _ = json.Marshal(Response{
			JSONRPC: "2.0",
			ID:      resp.ID,
			Error:   &RPCError{Code: -32603, Message: "internal error: 结果序列化失败"},
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.out.Write(data)
	_ = s.out.WriteByte('\n')
	_ = s.out.Flush()
}
