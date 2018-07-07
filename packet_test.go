package inform

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidPacket(t *testing.T) {
	assert := assert.New(t)

	_, err := ReadPacket(bytes.NewReader(nil))
	assert.EqualError(err, "EOF")

	_, err = ReadPacket(bytes.NewReader([]byte("hello")))
	assert.EqualError(err, "insufficient data: header too short")
}

func TestDecode(t *testing.T) {
	assert := assert.New(t)
	mac := "f0:9f:c2:79:63:90"
	key, _ := hex.DecodeString("e2c930683af3945e4d0d58d37a78c2a6")

	dat, err := ioutil.ReadFile("testdata/request")
	assert.NoError(err)

	packet, err := ReadPacket(bytes.NewReader(dat))
	assert.NoError(err)
	assert.NotNil(packet)

	assert.Equal(mac, packet.MAC.String())
	assert.EqualValues(0, packet.PacketVersion)
	assert.EqualValues(1, packet.PayloadVersion)

	invalidKey, _ := hex.DecodeString("11111111111111111111111111111111")
	_, err = packet.Data(invalidKey)
	assert.EqualError(err, "invalid padding: structure invalid")

	data, err := packet.Data(key)
	assert.NoError(err)

	jsonData := make(map[string]interface{})
	assert.NoError(json.Unmarshal(data, &jsonData))
	assert.Equal("3.9.27.8537", jsonData["version"])
	assert.Equal("U7PG2", jsonData["model"])
	assert.Equal("UAP-AC-Pro-Gen2", jsonData["model_display"])
}
