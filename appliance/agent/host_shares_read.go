package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"syscall"
)

// readBytes negotiates a raw bounded body with new hosts. Older hosts (including
// forwarded shares) answer the original JSON contract to the SAME request. An
// authorization, transport or framing failure never retries through another path.
func (n *hostFileNode) readBytes(ctx context.Context, dest []byte, off int64) ([]byte, syscall.Errno) {
	if off < 0 {
		return nil, syscall.EINVAL
	}
	const maxRead = 256 * 1024
	if len(dest) > maxRead {
		dest = dest[:maxRead]
	}
	body, err := json.Marshal(map[string]interface{}{
		"operation": "read", "path": n.relative, "offset": off, "length": len(dest),
	})
	if err != nil {
		return nil, syscall.EIO
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint+"/files", bytes.NewReader(body))
	if err != nil {
		return nil, syscall.EIO
	}
	request.Header.Set("Authorization", "Bearer "+n.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/octet-stream")
	response, err := hostFileClient.Do(request)
	if err != nil {
		return nil, syscall.EIO
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, syscall.ENOENT
	case http.StatusForbidden:
		return nil, syscall.EACCES
	case http.StatusConflict:
		return nil, syscall.EEXIST
	default:
		return nil, syscall.EIO
	}
	kind, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		return nil, syscall.EIO
	}
	if kind == "application/octet-stream" {
		// Require the exact body frame. Truncated/oversized/chunked replies cannot
		// become a successful short read or poison the next pooled response.
		if response.ContentLength < 0 || response.ContentLength > int64(len(dest)) || len(response.TransferEncoding) != 0 {
			return nil, syscall.EIO
		}
		data := dest[:int(response.ContentLength)]
		if _, err = io.ReadFull(response.Body, data); err != nil {
			return nil, syscall.EIO
		}
		var extra [1]byte
		if count, err := response.Body.Read(extra[:]); count != 0 || err != io.EOF {
			return nil, syscall.EIO
		}
		return data, 0
	}
	if kind != "application/json" {
		return nil, syscall.EIO
	}
	// The original bounded read is at most 256 KiB plus base64 and JSON framing.
	const maxJSON = 4*(maxRead/3+1) + 4096
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxJSON+1))
	if err != nil || len(encoded) > maxJSON {
		return nil, syscall.EIO
	}
	var reply hostFileReply
	if json.Unmarshal(encoded, &reply) != nil || reply.Error != "" {
		return nil, syscall.EIO
	}
	if base64.StdEncoding.DecodedLen(len(reply.Data)) > len(dest)+2 {
		return nil, syscall.EIO
	}
	// Decode into a bounded temporary for old hosts: DecodedLen includes padding
	// and may exceed the actual count by two bytes when dest is an exact fit.
	data, err := base64.StdEncoding.DecodeString(reply.Data)
	if err != nil || len(data) > len(dest) {
		return nil, syscall.EIO
	}
	return dest[:copy(dest, data)], 0
}
