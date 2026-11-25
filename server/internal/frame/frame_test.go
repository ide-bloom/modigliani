package frame

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func TestChecksumVectors(t *testing.T) {
	data := []byte("123456789")
	cases := map[string]uint64{"crc8": 0xF4, "crc16_ccitt": 0x29B1, "crc16_modbus": 0x4B37, "crc32": 0xCBF43926, "sum8": 0xDD, "xor8": 0x31}
	for alg, want := range cases {
		got, err := ComputeChecksum(data, &profile.Checksum{Algorithm: alg, Start: 0, End: len(data)})
		if err != nil || got != want {
			t.Errorf("%s = %#x (%v), want %#x", alg, got, err, want)
		}
	}
}

func TestDecodeEncodeRoundTrip(t *testing.T) {
	p := testutil.Profile(t)
	up, _ := p.Frame("up")
	raw := testutil.UpFrame(21.6, 1, 7)
	fields, err := Decode(raw, up)
	if err != nil {
		t.Fatal(err)
	}
	if fields["temp"] != 21.6 || fields["led"] != 1.0 || fields["level"] != 7.0 {
		t.Fatalf("fields = %v", fields)
	}
	enc, err := Encode(up, fields)
	if err != nil || !bytes.Equal(enc, raw) {
		t.Fatalf("encode = %x (%v), want %x", enc, err, raw)
	}
	bad := append([]byte(nil), raw...)
	bad[3] ^= 0xFF
	if _, err := Decode(bad, up); !errors.Is(err, ErrChecksum) {
		t.Errorf("tampered frame: %v", err)
	}
	down, _ := p.Frame("down")
	out, err := Encode(down, map[string]any{"led": true})
	if err != nil || !bytes.Equal(out, []byte{0xA5, 1, 1, testutil.CRC8([]byte{1, 1})}) {
		t.Errorf("down = %x %v", out, err)
	}
}

func TestSplitFramings(t *testing.T) {
	lp := profile.Framing{Kind: "length_prefixed", LengthField: &profile.LengthField{Offset: 1, Type: "u8", Adjust: 3}}
	a, b := testutil.UpFrame(20, 0, 1), testutil.UpFrame(21, 1, 2)
	frames, rest := Split(append(append(append([]byte{}, a...), b...), a[:3]...), lp)
	if len(frames) != 2 || !bytes.Equal(frames[1], b) || !bytes.Equal(rest, a[:3]) {
		t.Errorf("length-prefixed: %x rest %x", frames, rest)
	}
	frames, rest = Split([]byte("a=1\nb=2\npart"), profile.Framing{Kind: "delimiter", Delimiter: "0a"})
	if len(frames) != 2 || string(frames[1]) != "b=2" || string(rest) != "part" {
		t.Errorf("delimiter: %q %q", frames, rest)
	}
	size := 3
	frames, rest = Split([]byte{1, 2, 3, 4, 5, 6, 7}, profile.Framing{Kind: "fixed", RecordSize: &size})
	if len(frames) != 2 || len(rest) != 1 {
		t.Errorf("fixed: %v %v", frames, rest)
	}
	if string(Join([]byte("x"), profile.Framing{Kind: "delimiter", Delimiter: "0d0a"})) != "x\r\n" {
		t.Error("join")
	}
}

func TestMatchRule(t *testing.T) {
	up, _ := testutil.Profile(t).Frame("up")
	if !MatchRule(testutil.UpFrame(20, 0, 1), up, map[string]int64{"magic": 165}) {
		t.Error("should match")
	}
	if MatchRule(testutil.UpFrame(20, 0, 1), up, map[string]int64{"magic": 1}) || MatchRule([]byte{1, 2}, up, nil) {
		t.Error("should not match")
	}
}
