> **Note: With the release of Unifi SDN Controller version 5.12.x the
> inform package format has changed. As of now, the encryption scheme is
> unknown and hence this package is considered defunkt.**
>
> This basically affects all firmwares since at least v4.0.20 (maybe
> even earlier versions).
>
> Feel free to [open a new issue][] if you find clues on how to decipher
> current inform packages.

[open a new issue]: https://github.com/dmke/inform-inspect/issues/new


# inform-inspect

Inspector for Ubiquiti Unifi Inform Pakets. Useful for debugging or
creating external statistics.


## Setup

You need access to a few things:

1. Incoming inform packets. These are Application Layer packets (HTTP)
   directed to the controller (usually <http://unifi:8080/inform>).

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

## Installation

The binary is easily obtained with this command (assuming you have the
Go toolchain installed):

```
go get github.com/dmke/inform-inspect/cmd/inform-inspect
```

This puts `inform-inspect` into `$GOPATH/bin`, which then can be called
with the AES key and the path to a file containing the HTTP body of the
inform request:


```
$GOPATH/bin/inform-inspect abcdef0123456789abcdef0123456789 /path/to/inform.dat
```

The program call can have one of three results:

| Exit code | Output |   |
|:----------|:-------|:--|
| 0 | JSON to `stdout`    | only if decrypted data is recognized as JSON |
| 0 | hexdump to `stdout` | decoding succeeds, but is not recognized as JSON |
| 1 | error message to `stderr` | decoding failed for some reason |

Please file a [bug report][issues] if you get a hexdump or if you believe
the error message to be incorrect. Don't forget to attach a BLOB for
reproduction.

[issues]: https://github.com/dmke/inform-inspect/issues

## Next steps

Technically, you don't need to know the password in advance. This
package is built around a two-step decoding model: first parse the raw
byte stream into a data structure and then decrypt/decompress its
payload.

Since the device's MAC address is embedded in plain text in the byte
stream's header, one could easily retrieve the necessary AES key
on-demand from the MongoDB (PR welcome).

After that, a MitM sitting between the Unifi Controller and the device
would be handy.


## Thanks

This builds upon protocol details gathered by [Mike Crute][mcrute] and
[Jeffrey Kog][jk-5]:

- <https://github.com/mcrute/ubntmfi/blob/master/inform_protocol.md>
- <https://github.com/jk-5/unifi-inform-protocol>

I'd also like to thank Redditor [/u/CornerAssignment][CornerAssignment]
for pointing me in the right direction when I was stuck identifying the
compression mechanism and not realizing the padding was still attached
to the cleartext stream.

[jk-5]: https://github.com/jk-5
[mcrute]: https://github.com/mcrute
[CornerAssignment]: https://www.reddit.com/user/CornerAssignment
