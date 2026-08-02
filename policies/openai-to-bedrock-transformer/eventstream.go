/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package openaitobedrock

import "encoding/binary"

// AWS event-stream ("application/vnd.amazon.eventstream") binary framing.
//
// Each message on the wire is laid out as:
//
//	 0      4          8            12                12+H            N-4     N
//	+------+----------+------------+----------------+---------------+-------+
//	|total | headers  | prelude    |  headers (H)   |  payload      |  msg  |
//	|length| length   | CRC32      |                |               |  CRC32|
//	+------+----------+------------+----------------+---------------+-------+
//	  u32      u32         u32          H bytes         P bytes        u32
//
// All integers are big-endian. total length counts every byte of the frame,
// so payload length = total - headersLen - 16 (4 prelude ints of 4 bytes +
// the trailing message CRC). CRCs are not validated here because the gateway
// transport already guarantees byte integrity of the upstream stream.
//
// Headers are a packed sequence of:
//
//	nameLen u8 | name (nameLen bytes) | valueType u8 | value...
//
// The headers we care about are string headers (valueType 7): ":event-type"
// (messageStart, contentBlockDelta, …), ":message-type" ("event" or
// "exception"), and ":exception-type". Other AWS event-stream header types
// are skipped according to their defined widths.

const (
	preludeLen        = 8  // totalLen(4) + headersLen(4)
	preludeWithCRCLen = 12 // prelude(8) + preludeCRC(4)
	frameOverhead     = 16 // prelude(8) + preludeCRC(4) + messageCRC(4)
	minFrameLen       = frameOverhead
	// maxFrameLen guards against treating non-event-stream bytes as a frame with
	// an absurd advertised length. Matches the kernel's stream accumulator cap.
	maxFrameLen = 16 * 1024 * 1024

	headerTypeTrue      = 0
	headerTypeFalse     = 1
	headerTypeByte      = 2
	headerTypeShort     = 3
	headerTypeInteger   = 4
	headerTypeLong      = 5
	headerTypeByteArray = 6
	headerTypeString    = 7
	headerTypeTimestamp = 8
	headerTypeUUID      = 9
)

// eventStreamFrame is one decoded message: its wire headers plus the raw
// (usually JSON) payload bytes.
type eventStreamFrame struct {
	EventType     string
	MessageType   string
	ExceptionType string
	Payload       []byte
}

// decodeEventStreamFrames parses every complete frame at the start of data and
// returns them together with the number of bytes consumed. Trailing bytes that
// form only a partial frame are left unconsumed so the caller can prepend them
// to the next chunk. Returns ok=false when the leading bytes are not a
// plausible event-stream frame (advertised length out of range).
func decodeEventStreamFrames(data []byte) (frames []eventStreamFrame, consumed int, ok bool) {
	offset := 0
	for {
		frame, frameLen, status := decodeOneFrame(data[offset:])
		switch status {
		case frameOK:
			frames = append(frames, frame)
			offset += frameLen
		case frameIncomplete:
			return frames, offset, true
		case frameInvalid:
			// Only signal "not event-stream" when we haven't decoded anything;
			// otherwise report progress and stop on the garbage boundary.
			return frames, offset, offset > 0
		}
	}
}

// eventStreamBoundary reports the number of leading bytes of data that form
// whole frames and whether a partial (incomplete) frame trails them. It is the
// cheap check used by NeedsMoreResponseData to align kernel flushes to frame
// boundaries without decoding payloads.
func eventStreamBoundary(data []byte) (completeLen int, hasPartial bool, ok bool) {
	offset := 0
	for {
		if len(data)-offset == 0 {
			return offset, false, true
		}
		_, frameLen, status := decodeOneFrame(data[offset:])
		switch status {
		case frameOK:
			offset += frameLen
		case frameIncomplete:
			return offset, true, true
		default: // frameInvalid
			return offset, false, offset > 0
		}
	}
}

type frameStatus int

const (
	frameOK frameStatus = iota
	frameIncomplete
	frameInvalid
)

func decodeOneFrame(data []byte) (eventStreamFrame, int, frameStatus) {
	if len(data) < preludeWithCRCLen {
		return eventStreamFrame{}, 0, frameIncomplete
	}
	totalLen := int(binary.BigEndian.Uint32(data[0:4]))
	headersLen := int(binary.BigEndian.Uint32(data[4:8]))
	if totalLen < minFrameLen || totalLen > maxFrameLen ||
		headersLen < 0 || headersLen > totalLen-frameOverhead {
		return eventStreamFrame{}, 0, frameInvalid
	}
	if len(data) < totalLen {
		return eventStreamFrame{}, 0, frameIncomplete
	}

	headerBytes := data[preludeWithCRCLen : preludeWithCRCLen+headersLen]
	payload := data[preludeWithCRCLen+headersLen : totalLen-4]

	frame := eventStreamFrame{Payload: payload}
	for name, value := range parseHeaders(headerBytes) {
		switch name {
		case ":event-type":
			frame.EventType = value
		case ":message-type":
			frame.MessageType = value
		case ":exception-type":
			frame.ExceptionType = value
		}
	}
	return frame, totalLen, frameOK
}

// parseHeaders decodes the packed header block into a name→value map, keeping
// only string-typed (type 7) headers. Malformed trailing bytes stop parsing
// rather than panic.
func parseHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	offset := 0
	for offset < len(data) {
		nameLen := int(data[offset])
		offset++
		if offset+nameLen > len(data) {
			break
		}
		name := string(data[offset : offset+nameLen])
		offset += nameLen
		if offset >= len(data) {
			break
		}
		valueType := data[offset]
		offset++

		var encodedLen int
		switch valueType {
		case headerTypeTrue, headerTypeFalse:
			encodedLen = 0
		case headerTypeByte:
			encodedLen = 1
		case headerTypeShort:
			encodedLen = 2
		case headerTypeInteger:
			encodedLen = 4
		case headerTypeLong, headerTypeTimestamp:
			encodedLen = 8
		case headerTypeUUID:
			encodedLen = 16
		case headerTypeByteArray, headerTypeString:
			if offset+2 > len(data) {
				return headers
			}
			encodedLen = 2 + int(binary.BigEndian.Uint16(data[offset:offset+2]))
		default:
			return headers
		}
		if offset+encodedLen > len(data) {
			return headers
		}
		if valueType == headerTypeString {
			headers[name] = string(data[offset+2 : offset+encodedLen])
		}
		offset += encodedLen
	}
	return headers
}
