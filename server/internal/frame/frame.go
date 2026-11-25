// Package frame decodes and encodes the binary frames described in profiles, including
// length fields and checksums (the Go twin of studio's infer/frames.py).
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"

	"github.com/ide-bloom/modigliani/server/internal/profile"
)

// ErrChecksum reports a frame whose checksum does not verify.
var ErrChecksum = errors.New("frame checksum mismatch")

type fieldType struct {
	width  int
	signed bool
	little bool
}

var fieldTypes = map[string]fieldType{
	"u8": {1, false, false}, "i8": {1, true, false},
	"u16be": {2, false, false}, "u16le": {2, false, true}, "i16be": {2, true, false}, "i16le": {2, true, true},
	"u32be": {4, false, false}, "u32le": {4, false, true}, "i32be": {4, true, false}, "i32le": {4, true, true},
}

// Width returns the byte width of a field type.
func Width(t string) int { return fieldTypes[t].width }

func read(b []byte, off int, t string) (int64, bool) {
	ft, ok := fieldTypes[t]
	if !ok || off < 0 || off+ft.width > len(b) {
		return 0, false
	}
	var order binary.ByteOrder = binary.BigEndian
	if ft.little {
		order = binary.LittleEndian
	}
	// The conversions below reinterpret wire bytes as two's-complement or truncate to the
	// field width on purpose; that is what a binary protocol field means.
	switch ft.width {
	case 1:
		if ft.signed {
			return int64(int8(b[off])), true //nolint:gosec // intended reinterpretation
		}
		return int64(b[off]), true
	case 2:
		v := order.Uint16(b[off:])
		if ft.signed {
			return int64(int16(v)), true //nolint:gosec // intended reinterpretation
		}
		return int64(v), true
	default:
		v := order.Uint32(b[off:])
		if ft.signed {
			return int64(int32(v)), true //nolint:gosec // intended reinterpretation
		}
		return int64(v), true
	}
}

func write(b []byte, off int, t string, v int64) error {
	ft, ok := fieldTypes[t]
	if !ok || off < 0 || off+ft.width > len(b) {
		return fmt.Errorf("field %s at %d does not fit", t, off)
	}
	var order binary.ByteOrder = binary.BigEndian
	if ft.little {
		order = binary.LittleEndian
	}
	switch ft.width {
	case 1:
		b[off] = byte(v) //nolint:gosec // truncation to the field width is intended
	case 2:
		order.PutUint16(b[off:], uint16(v)) //nolint:gosec // truncation to the field width is intended
	default:
		order.PutUint32(b[off:], uint32(v)) //nolint:gosec // truncation to the field width is intended
	}
	return nil
}

// Checksum algorithms.
func sum8(b []byte) uint64 {
	var s uint64
	for _, c := range b {
		s += uint64(c)
	}
	return s & 0xFF
}

func xor8(b []byte) uint64 {
	var s byte
	for _, c := range b {
		s ^= c
	}
	return uint64(s)
}

func crc8(b []byte) uint64 {
	var crc byte
	for _, c := range b {
		crc ^= c
		for range 8 {
			if crc&0x80 != 0 {
				crc = crc<<1 ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return uint64(crc)
}

func sum16(b []byte) uint64 {
	var s uint64
	for _, c := range b {
		s += uint64(c)
	}
	return s & 0xFFFF
}

func crc16CCITT(b []byte) uint64 {
	crc := uint16(0xFFFF)
	for _, c := range b {
		crc ^= uint16(c) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return uint64(crc)
}

func crc16Modbus(b []byte) uint64 {
	crc := uint16(0xFFFF)
	for _, c := range b {
		crc ^= uint16(c)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return uint64(crc)
}

var algorithms = map[string]struct {
	fn    func([]byte) uint64
	width int
}{
	"sum8": {sum8, 1}, "xor8": {xor8, 1}, "crc8": {crc8, 1}, "sum16": {sum16, 2},
	"crc16_ccitt": {crc16CCITT, 2}, "crc16_modbus": {crc16Modbus, 2},
	"crc32": {func(b []byte) uint64 { return uint64(crc32.ChecksumIEEE(b)) }, 4},
}

func span(n int, ck *profile.Checksum) (int, int) {
	end := ck.End
	if end <= 0 {
		end = n + end
	}
	return ck.Start, end
}

func position(n int, ck *profile.Checksum) int {
	if ck.Offset < 0 {
		return n + ck.Offset
	}
	return ck.Offset
}

// ComputeChecksum computes a frame's checksum over its covered bytes.
func ComputeChecksum(b []byte, ck *profile.Checksum) (uint64, error) {
	alg, ok := algorithms[ck.Algorithm]
	if !ok {
		return 0, fmt.Errorf("unknown checksum %q", ck.Algorithm)
	}
	s, e := span(len(b), ck)
	if s < 0 || e > len(b) || s > e {
		return 0, errors.New("checksum span out of range")
	}
	return alg.fn(b[s:e]), nil
}

func readChecksum(b []byte, ck *profile.Checksum) (uint64, error) {
	w := algorithms[ck.Algorithm].width
	pos := position(len(b), ck)
	if pos < 0 || pos+w > len(b) {
		return 0, errors.New("checksum position out of range")
	}
	var v uint64
	for i := range w {
		if ck.Endian == "little" {
			v |= uint64(b[pos+i]) << (8 * i)
		} else {
			v = v<<8 | uint64(b[pos+i])
		}
	}
	return v, nil
}

func writeChecksum(b []byte, ck *profile.Checksum, v uint64) {
	w := algorithms[ck.Algorithm].width
	pos := position(len(b), ck)
	for i := range w {
		if ck.Endian == "little" {
			b[pos+i] = byte(v >> (8 * i)) //nolint:gosec // byte extraction
		} else {
			b[pos+w-1-i] = byte(v >> (8 * i)) //nolint:gosec // byte extraction
		}
	}
}

// Verify checks a frame's checksum (true when the layout has none).
func Verify(b []byte, layout profile.Frame) bool {
	if layout.Checksum == nil {
		return true
	}
	want, err := ComputeChecksum(b, layout.Checksum)
	if err != nil {
		return false
	}
	got, err := readChecksum(b, layout.Checksum)
	return err == nil && got == want
}

// Decode reads every field (scaled) and checks length and checksum.
func Decode(b []byte, layout profile.Frame) (map[string]any, error) {
	if layout.Length != nil && len(b) != *layout.Length {
		return nil, fmt.Errorf("frame %s: length %d, want %d", layout.ID, len(b), *layout.Length)
	}
	if !Verify(b, layout) {
		return nil, ErrChecksum
	}
	out := map[string]any{}
	for _, f := range layout.Fields {
		raw, ok := read(b, f.Offset, f.Type)
		if !ok {
			return nil, fmt.Errorf("frame %s: field %s out of range", layout.ID, f.Name)
		}
		if f.Const != nil {
			if raw != *f.Const {
				return nil, fmt.Errorf("frame %s: constant %s is %d, want %d", layout.ID, f.Name, raw, *f.Const)
			}
			continue
		}
		scale := f.Scale
		if scale == 0 {
			scale = 1
		}
		if scale == 1 {
			out[f.Name] = float64(raw)
		} else {
			out[f.Name] = math.Round(float64(raw)*scale*1e6) / 1e6
		}
	}
	return out, nil
}

// Size returns the encoded size of a layout.
func Size(layout profile.Frame) int {
	if layout.Length != nil {
		return *layout.Length
	}
	n := 0
	for _, f := range layout.Fields {
		n = max(n, f.Offset+Width(f.Type))
	}
	if layout.Checksum != nil && layout.Checksum.Offset < 0 {
		n += -layout.Checksum.Offset
	}
	return n
}

// Encode builds a frame from field values (in state units; the field scale is applied),
// filling constants, the length field and the checksum.
func Encode(layout profile.Frame, values map[string]any) ([]byte, error) {
	b := make([]byte, Size(layout))
	for _, f := range layout.Fields {
		var raw int64
		if f.Const != nil {
			raw = *f.Const
		} else {
			v, err := toFloat(values[f.Name])
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", f.Name, err)
			}
			scale := f.Scale
			if scale == 0 {
				scale = 1
			}
			raw = int64(math.Round(v / scale))
		}
		if err := write(b, f.Offset, f.Type, raw); err != nil {
			return nil, err
		}
	}
	if lf := layout.LengthField; lf != nil {
		if err := write(b, lf.Offset, lf.Type, int64(len(b)-lf.Adjust)); err != nil {
			return nil, err
		}
	}
	if ck := layout.Checksum; ck != nil {
		v, err := ComputeChecksum(b, ck)
		if err != nil {
			return nil, err
		}
		writeChecksum(b, ck, v)
	}
	return b, nil
}

func toFloat(v any) (float64, error) {
	switch t := v.(type) {
	case nil:
		return 0, nil
	case float64:
		return t, nil
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	case bool:
		if t {
			return 1, nil
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("not a number: %v", v)
	}
}

// Split cuts a byte stream into frames according to a framing description. It returns the
// frames and the unconsumed remainder (a partial frame still being received).
func Split(stream []byte, f profile.Framing) ([][]byte, []byte) {
	var out [][]byte
	switch f.Kind {
	case "delimiter":
		delim, err := hexDecode(f.Delimiter)
		if err != nil || len(delim) == 0 {
			return [][]byte{stream}, nil
		}
		for {
			i := indexOf(stream, delim)
			if i < 0 {
				return out, stream
			}
			out = append(out, stream[:i])
			stream = stream[i+len(delim):]
		}
	case "fixed":
		if f.RecordSize == nil || *f.RecordSize <= 0 {
			return [][]byte{stream}, nil
		}
		n := *f.RecordSize
		for len(stream) >= n {
			out = append(out, stream[:n])
			stream = stream[n:]
		}
		return out, stream
	case "length_prefixed":
		lf := f.LengthField
		if lf == nil {
			return [][]byte{stream}, nil
		}
		for {
			v, ok := read(stream, lf.Offset, lf.Type)
			if !ok {
				return out, stream
			}
			total := int(v) + lf.Adjust
			if total < lf.Offset+Width(lf.Type) {
				return out, nil // corrupt stream: drop it
			}
			if total > len(stream) {
				return out, stream
			}
			out = append(out, stream[:total])
			stream = stream[total:]
		}
	default:
		if len(stream) == 0 {
			return nil, nil
		}
		return [][]byte{stream}, nil
	}
}

// Join adds framing (the delimiter) to an outgoing frame.
func Join(frame []byte, f profile.Framing) []byte {
	if f.Kind == "delimiter" {
		if d, err := hexDecode(f.Delimiter); err == nil {
			return append(append([]byte{}, frame...), d...)
		}
	}
	return frame
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var v byte
		if _, err := fmt.Sscanf(s[i:i+2], "%02x", &v); err != nil {
			return nil, err
		}
		out[i/2] = v
	}
	return out, nil
}

// MatchRule reports whether a frame satisfies a rule's layout length and constant fields.
func MatchRule(b []byte, layout profile.Frame, match map[string]int64) bool {
	if layout.Length != nil && len(b) != *layout.Length {
		return false
	}
	for _, f := range layout.Fields {
		want, ok := match[f.Name]
		if !ok {
			continue
		}
		got, ok := read(b, f.Offset, f.Type)
		if !ok || got != want {
			return false
		}
	}
	return true
}
