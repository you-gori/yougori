package main

import (
	"encoding/binary"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// Close-and-replace broadcasts changes without losing a wakeup between taking
// the output snapshot and waiting. All access is under session.mu.
func (session *terminalSession) notifyLocked() {
	if session.changed != nil {
		close(session.changed)
	}
	session.changed = make(chan struct{})
}

func (session *terminalSession) appendOutput(data []byte) bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	for !session.done && session.streamOffset != nil && len(session.output)+len(data) > 1024*1024 {
		consumed := *session.streamOffset - session.base
		if consumed > 0 && consumed <= uint64(len(session.output)) {
			copy(session.output, session.output[consumed:])
			session.output = session.output[:uint64(len(session.output))-consumed]
			session.base += consumed
		} else {
			changed := session.changed
			session.mu.Unlock()
			<-changed
			session.mu.Lock()
		}
	}
	if session.done {
		return false
	}
	session.output = append(session.output, data...)
	if len(session.output) > 1024*1024 {
		// Polling-only terminals retain their bounded recent-output window.
		excess := len(session.output) - 512*1024
		copy(session.output, session.output[excess:])
		session.output = session.output[:len(session.output)-excess]
		session.base += uint64(excess)
	}
	session.notifyLocked()
	return true
}

var terminalUpgrader = websocket.Upgrader{
	ReadBufferSize: 16 * 1024, WriteBufferSize: 16 * 1024,
	CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
}

func (s *server) terminalStream(w http.ResponseWriter, r *http.Request) {
	connection, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	connection.SetReadLimit(16*1024 + 1)
	connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	var request terminalRequest
	if connection.ReadJSON(&request) != nil {
		return
	}
	value, ok := s.terminals.Load(request.SessionID)
	if !ok {
		terminalStreamError(connection, "terminal is closed")
		return
	}
	session := value.(*terminalSession)
	if session.environment != request.ID {
		terminalStreamError(connection, "terminal belongs to another environment")
		return
	}
	progress := new(uint64)
	*progress = request.Offset
	session.mu.Lock()
	if session.streamOffset != nil {
		session.mu.Unlock()
		terminalStreamError(connection, "terminal already has a stream")
		return
	}
	session.streamOffset = progress
	session.mu.Unlock()
	defer func() { session.mu.Lock(); session.streamOffset = nil; session.notifyLocked(); session.mu.Unlock() }()
	connection.SetReadDeadline(time.Time{})
	if connection.WriteJSON(map[string]int{"terminalStreamVersion": 1}) != nil {
		return
	}
	stopped := make(chan struct{})
	// One reader and one writer, so a blocking PTY write cannot delay output.
	go func() {
		defer close(stopped)
		defer connection.Close()
		for {
			kind, data, err := connection.ReadMessage()
			if err != nil || kind != websocket.BinaryMessage || len(data) == 0 {
				return
			}
			switch data[0] {
			case 1:
				if len(data) < 2 || len(data) > 16*1024+1 {
					return
				}
				// Bound stalled input as well as output. Disconnects cannot leave
				// a handler blocked forever on a guest that stopped reading.
				if session.master.SetWriteDeadline(time.Now().Add(15*time.Second)) != nil {
					return
				}
				if _, err := session.master.Write(data[1:]); err != nil {
					return
				}
			case 2:
				if len(data) != 5 {
					return
				}
				cols, rows := binary.BigEndian.Uint16(data[1:3]), binary.BigEndian.Uint16(data[3:5])
				if cols == 0 || rows == 0 {
					return
				}
				resizePTY(session.master, cols, rows)
			default:
				return
			}
		}
	}()
	offset := request.Offset
	for {
		session.mu.Lock()
		if session.changed == nil {
			session.changed = make(chan struct{})
		}
		changed := session.changed
		end := session.base + uint64(len(session.output))
		if offset < session.base || offset > end {
			session.mu.Unlock()
			terminalStreamError(connection, "terminal output cursor expired; reconnect")
			return
		}
		limit := offset + 64*1024
		if limit > end {
			limit = end
		}
		var frame []byte
		if limit > offset {
			frame = make([]byte, 9+int(limit-offset))
			frame[0] = 3
			binary.BigEndian.PutUint64(frame[1:9], limit)
			copy(frame[9:], session.output[offset-session.base:limit-session.base])
		}
		done := session.done && limit == end
		session.mu.Unlock()
		connection.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if len(frame) > 0 {
			if connection.WriteMessage(websocket.BinaryMessage, frame) != nil {
				return
			}
			offset = limit
			session.mu.Lock()
			*progress = limit
			session.notifyLocked()
			session.mu.Unlock()
		}
		if done {
			connection.WriteMessage(websocket.BinaryMessage, []byte{4})
			return
		}
		if len(frame) > 0 {
			continue
		}
		select {
		case <-changed:
		case <-stopped:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func terminalStreamError(connection *websocket.Conn, message string) {
	connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	connection.WriteMessage(websocket.BinaryMessage, append([]byte{5}, []byte(message)...))
}
