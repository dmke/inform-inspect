package inform

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
	"testing/iotest"

	"github.com/klauspost/compress/snappy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// header returns a packet header with valid magic and the given payload
// length; all other fields are zero.
func header(length int) []byte {
	head := make([]byte, headerLength)
	copy(head, "TNBU")
	binary.BigEndian.PutUint32(head[headerLength-4:], uint32(length))
	return head
}

// zlibCompress returns data compressed with zlib.
func zlibCompress(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	z := zlib.NewWriter(&buf)
	_, err := z.Write(data)
	require.NoError(t, err)
	require.NoError(t, z.Close())
	return buf.Bytes()
}

func TestInvalidPacket(t *testing.T) {
	t.Parallel()

	_, err := ReadPacket(bytes.NewReader(nil))
	assert.EqualError(t, err, "EOF")

	_, err = ReadPacket(bytes.NewReader([]byte("hello")))
	assert.EqualError(t, err, "insufficient data: header too short")

	_, err = ParsePacket([]byte("hello"))
	assert.EqualError(t, err, "insufficient data: header too short")

	_, err = ParsePacket(bytes.Repeat([]byte("x"), headerLength))
	assert.EqualError(t, err, "invalid packet: must begin with 'TNBU'")

	_, err = ReadPacket(bytes.NewReader(bytes.Repeat([]byte("x"), headerLength)))
	assert.EqualError(t, err, "invalid packet: must begin with 'TNBU'")

	_, err = ParsePacket(header(0))
	assert.EqualError(t, err, "insufficient data: header does not define payload length")
}

func TestTruncatedPayload(t *testing.T) {
	t.Parallel()

	dat, err := os.ReadFile("testdata/aes_snappy.dat")
	require.NoError(t, err)
	dat = dat[:len(dat)-1]

	_, err = ParsePacket(dat)
	assert.EqualError(t, err, "insufficient data: payload too short")

	_, err = ReadPacket(bytes.NewReader(dat))
	assert.EqualError(t, err, "insufficient data: payload too short")

	_, err = ReadPacket(bytes.NewReader(dat[:headerLength]))
	assert.EqualError(t, err, "insufficient data: payload too short", "missing payload")

	// other read errors pass through, e.g. for HTTP handlers to tell a
	// timeout from a broken packet
	r := io.MultiReader(
		bytes.NewReader(dat[:headerLength]),
		iotest.ErrReader(os.ErrDeadlineExceeded),
	)
	_, err = ReadPacket(r)
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded, "read error lost")
}

type decodeTestcase struct {
	datFile string
	hexKey  string

	flags        flags
	mac          string
	firmware     string
	model        string
	modelDisplay string
}

// Run executes a decodeTestcase and allows chosing the reader/parser
// method. The parse argument receives the tc.datFile read from disk
// needs to construct a Packet from it. See TestDecode for usage below.
func (tc *decodeTestcase) Run(t *testing.T, parse func([]byte) (*Packet, error)) {
	t.Helper()

	assert, require := assert.New(t), require.New(t)

	dat, err := os.ReadFile(tc.datFile)
	require.NoError(err)

	packet, err := parse(dat)
	require.NoError(err)
	require.NotNil(packet)

	assert.Equal(tc.mac, packet.MAC.String())
	assert.EqualValues(0, packet.PacketVersion)
	assert.EqualValues(1, packet.PayloadVersion)
	assert.Equal(tc.flags, packet.Flags)

	invalidKey, err := hex.DecodeString("11111111111111111111111111111111")
	require.NoError(err)
	_, err = packet.Data(invalidKey)
	if tc.flags&GCMMode != 0 {
		assert.EqualError(err, "cipher: message authentication failed")
	} else {
		assert.EqualError(err, "invalid padding: structure invalid")
	}

	validKey, err := hex.DecodeString(tc.hexKey)
	require.NoError(err)
	data, err := packet.Data(validKey)
	require.NoError(err)

	jsonData := make(map[string]any)
	assert.NoError(json.Unmarshal(data, &jsonData))
	assert.Equal(tc.firmware, jsonData["version"])
	assert.Equal(tc.model, jsonData["model"])
	assert.Equal(tc.modelDisplay, jsonData["model_display"])
}

func TestDecode(t *testing.T) {
	t.Parallel()

	tt := []decodeTestcase{{
		datFile: "testdata/aes_snappy.dat",
		hexKey:  "e2c930683af3945e4d0d58d37a78c2a6",

		flags:        AESEncrypted | SnappyCompressed,
		mac:          "f0:9f:c2:79:63:90",
		firmware:     "3.9.27.8537",
		model:        "U7PG2",
		modelDisplay: "UAP-AC-Pro-Gen2",
	}, {
		datFile: "testdata/gcm_zlib.dat",
		hexKey:  "05223125e6b44aca0a0599551168d766",

		flags:        AESEncrypted | GCMMode | ZlibCompressed,
		mac:          "fc:ec:da:fc:c5:35",
		firmware:     "4.0.66.10832",
		model:        "U7PG2",
		modelDisplay: "UAP-AC-Pro-Gen2",
	}}

	for _, tc := range tt { //nolint:paralleltest
		// wrap file contents in a reader and test ReadPacket
		t.Run(tc.datFile+"_ReadPacket", func(t *testing.T) {
			t.Parallel()
			tc.Run(t, func(dat []byte) (*Packet, error) {
				return ReadPacket(bytes.NewReader(dat))
			})
		})

		// pass file contents directly to ParsePacket
		t.Run(tc.datFile+"_ParsePacket", func(t *testing.T) {
			t.Parallel()
			tc.Run(t, ParsePacket)
		})
	}
}

func TestData(t *testing.T) {
	t.Parallel()

	plain := []byte(`{"model":"U7PG2"}`)

	zlibbed := zlibCompress(t, plain)
	snappied := snappy.Encode(nil, plain)

	key := make([]byte, 16)

	for name, tc := range map[string]struct {
		pkt     Packet
		key     []byte
		want    []byte
		wantErr error
	}{
		"plain":          {Packet{Payload: plain}, nil, plain, nil},
		"zlib":           {Packet{Flags: ZlibCompressed, Payload: zlibbed}, nil, plain, nil},
		"snappy":         {Packet{Flags: SnappyCompressed, Payload: snappied}, nil, plain, nil},
		"short key":      {Packet{Flags: AESEncrypted, Payload: key}, key[:15], nil, errInvalidKey},
		"unaligned CBC":  {Packet{Flags: AESEncrypted, Payload: key[:15]}, key, nil, errInvalidPadding("data is not padded")},
		"short CBC IV":   {Packet{Flags: AESEncrypted, IV: key[:8], Payload: key}, key, nil, errInvalidIV},
		"zlib header":    {Packet{Flags: ZlibCompressed, Payload: plain}, nil, nil, zlib.ErrHeader},
		"zlib truncated": {Packet{Flags: ZlibCompressed, Payload: zlibbed[:len(zlibbed)-6]}, nil, nil, io.ErrUnexpectedEOF},
		"snappy corrupt": {Packet{Flags: SnappyCompressed, Payload: plain}, nil, nil, snappy.ErrCorrupt},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.pkt.Data(tc.key)
			assert.ErrorIs(t, err, tc.wantErr, "unexpected error")
			assert.Equal(t, tc.want, got, "unexpected data")
		})
	}
}

func TestPayloadLimit(t *testing.T) {
	t.Parallel()

	atLimit := make([]byte, defaultMaxPayloadSize)
	overLimit := make([]byte, defaultMaxPayloadSize+1)

	_, err := ParsePacket(append(header(len(atLimit)), atLimit...))
	assert.NoError(t, err, "payload at limit rejected")

	// rejected before allocating the payload buffer
	_, err = ParsePacket(header(len(overLimit)))
	assert.ErrorIs(t, err, errPayloadTooLarge, "payload over limit accepted")

	for name, tc := range map[string]struct {
		flags    flags
		compress func(*testing.T, []byte) []byte
	}{
		"snappy": {SnappyCompressed, func(_ *testing.T, b []byte) []byte { return snappy.Encode(nil, b) }},
		"zlib":   {ZlibCompressed, zlibCompress},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pkt := Packet{Flags: tc.flags, Payload: tc.compress(t, atLimit)}
			got, err := pkt.Data(nil)
			require.NoError(t, err, "decompressed payload at limit rejected")
			assert.Equal(t, len(atLimit), len(got), "decompressed payload truncated")

			pkt.Payload = tc.compress(t, overLimit)
			_, err = pkt.Data(nil)
			assert.ErrorIs(t, err, errPayloadTooLarge, "decompressed payload over limit accepted")
		})
	}
}

// not parallel, it changes the limit for the whole package
func TestSetMaxPayloadSize(t *testing.T) {
	SetMaxPayloadSize(8)
	t.Cleanup(func() { SetMaxPayloadSize(defaultMaxPayloadSize) })

	_, err := ParsePacket(append(header(8), make([]byte, 8)...))
	assert.NoError(t, err, "payload at lowered limit rejected")

	_, err = ParsePacket(append(header(9), make([]byte, 9)...))
	assert.ErrorIs(t, err, errPayloadTooLarge, "payload over lowered limit accepted")
}

func TestPKCS7Unpad(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		in      []byte
		want    []byte
		wantErr error
	}{
		"one pad byte":   {[]byte{7, 7, 1}, []byte{7, 7}, nil},
		"only padding":   {[]byte{2, 2}, []byte{}, nil},
		"empty":          {nil, nil, errInvalidPadding("no data")},
		"zero pad byte":  {[]byte{7, 7, 0}, nil, errInvalidPadding("structure invalid")},
		"pad over data":  {[]byte{7, 3}, nil, errInvalidPadding("structure invalid")},
		"pad over block": {bytes.Repeat([]byte{17}, 17), nil, errInvalidPadding("structure invalid")},
		"pad mismatched": {[]byte{7, 3, 2}, nil, errInvalidPadding("structure invalid")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := pkcs7unpad(tc.in)
			assert.ErrorIs(t, err, tc.wantErr, "unexpected error")
			assert.Equal(t, tc.want, got, "unexpected data")
		})
	}
}
