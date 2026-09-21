# ===== 阶段 1：编译（纯 Go + modernc sqlite，无需 CGO）=====
FROM golang:1.25-alpine AS builder
WORKDIR /workspace
# 先拷贝清单利用层缓存
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/quota-mcp ./cmd/quota-mcp

# ===== 阶段 2：运行时 =====
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 quotamcp
WORKDIR /app
COPY --from=builder /out/quota-mcp /usr/local/bin/quota-mcp
RUN mkdir -p /data && chown quotamcp:quotamcp /data
USER quotamcp
EXPOSE 8780
VOLUME ["/data"]
# 默认绑全部网口（容器内），库落 /data 卷；主密钥务必通过 -e 注入
ENV QUOTA_MCP_DB=/data/quota-mcp.db
ENTRYPOINT ["/usr/local/bin/quota-mcp"]
CMD ["-listen", "0.0.0.0:8780"]
