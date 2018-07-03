# inform-inspect

Inspector for Ubiquiti Unifi Inform Pakets. Useful for debugging or
creating external statistics.


## Setup

You need access to two things:

1. Incoming inform packets. These are Application Layer packets (HTTP)
   directed to the controller (usually "http://unifi:8080/inform").

2. The controller's MongoDB, which holds the encryption key for the
   inform packets. By default, this is a local child process of the
   controller application, running on a non-standard port.

3. The `inform-inspect` binary for your platform.

Whether you setup `iptables` port mirroring ("TEE"), inject a MitM TCP
proxy and selectively divert the inform packages, or capture packets
with `tcpdump` (for later analysis) is up to you. The sample command
included in this package only deals with offline data (for now).

To get to the AES encryption/decryption key, you can perform this query
against MongoDB:

```js
db.collection("device")
  .find({ mac: "<mac address>" }, { _id: 0, x_authkey: 1 })
```

where `<mac address>` is the MAC address of the device in question (in
lower-case colon-notation, like `aa:00:11:dd:ee:ff`).

Alternatively, you can SSH into the device (using the Site's SSH
credentials) and look for a line `mgmt.authkey=<32 hex digits>` in
`/var/etc/persisted/cfg/mgmt`. Note: each device has a different key.

The binary is easuly obtained with this command (assuming you have the
Go toolchain installed):

```
go get github.com/dmke/inform-inspect/cmd/inform-inspect
```

This puts `inform-inspect` into `$GOPATH/bin`, which is then called
with the AES key and the path to a filename containing the HTTP
body of the inform request:

```
$GOPATH/bin/inform-inspect abcdef0123456789abcdef0123456789 /path/to/inform.dat
```

The program call can have one of three results:

1. Decoding (parsing, decrypting or decompression) failse. The error is
   logged to stderr, and the program exits with status 1.
2. Decoding succeedes and contains JSON. The data is then printed to
   stdout and the program exists with status 0.
3. Decoding succeedes, but the data is not JSON. A hexdump is then
   printed to stdout and the program exits with 0.

Please file a bug report in the last case (and in the first case, if you
believe the error message is wrong). Don't forget to attach the packet
BLOB.


## Next steps

Technically, you don't need to know the password in advance. This package
is built around a two-step decoding model: first parse the raw byte
stream into a data structure and then decrypt/decompress its payload.

Since the device's MAC address is embedded in plain text in the byte
stream's header, one could easily retrieve the necessary AES key
on-demand from the MongoDB (PR welcome).

After that, a MitM between the Unifi Controller and the device would
be handy.


## Thanks

This builds upon protocol details gathered by [Mike Crute][mcrute] and
[Jeffrey Kog][jk-5]:

- <https://github.com/mcrute/ubntmfi/blob/master/inform_protocol.md>
- <https://github.com/jk-5/unifi-inform-protocol>

I'd also like to thank Redditor [/u//CornerAssignment][CornerAssignment]
for pointing me in the right direction when I was stuck identifying the
compression mechanism and not realizing the padding was still attached
to the cleartext stream.

[jk-5]: https://github.com/jk-5
[mcrute]: https://github.com/mcrute
[CornerAssignment]: https://www.reddit.com/user/CornerAssignment