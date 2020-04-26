package inform

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvalidPacket(t *testing.T) {
	assert := assert.New(t)

	_, err := ReadPacket(bytes.NewReader(nil))
	assert.EqualError(err, "EOF")

	_, err = ReadPacket(bytes.NewReader([]byte("hello")))
	assert.EqualError(err, "insufficient data: header too short")
}

func TestDecode(t *testing.T) {
	tt := []struct {
		datFile string
		hexKey  string

		flags        flags
		mac          string
		firmware     string
		model        string
		modelDisplay string
	}{
		{
			datFile: "testdata/aes_snappy.dat",
			hexKey:  "e2c930683af3945e4d0d58d37a78c2a6",

			flags:        AESEncrypted | SnappyCompressed,
			mac:          "f0:9f:c2:79:63:90",
			firmware:     "3.9.27.8537",
			model:        "U7PG2",
			modelDisplay: "UAP-AC-Pro-Gen2",
		},
	}

	for i := range tt {
		tc := tt[i]
		t.Run(tc.datFile, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			dat, err := ioutil.ReadFile(tc.datFile)
			require.NoError(err)

			packet, err := ReadPacket(bytes.NewReader(dat))
			require.NoError(err)
			require.NotNil(packet)

			assert.Equal(tc.mac, packet.MAC.String())
			assert.EqualValues(0, packet.PacketVersion)
			assert.EqualValues(1, packet.PayloadVersion)
			assert.Equal(tc.flags, packet.Flags)

			invalidKey, err := hex.DecodeString("11111111111111111111111111111111")
			require.NoError(err)
			_, err = packet.Data(invalidKey)
			assert.EqualError(err, "invalid padding: structure invalid")

			validKey, err := hex.DecodeString(tc.hexKey)
			require.NoError(err)
			data, err := packet.Data(validKey)
			require.NoError(err)

			jsonData := make(map[string]interface{})
			assert.NoError(json.Unmarshal(data, &jsonData))
			assert.Equal(tc.firmware, jsonData["version"])
			assert.Equal(tc.model, jsonData["model"])
			assert.Equal(tc.modelDisplay, jsonData["model_display"])
		})
	}
}
