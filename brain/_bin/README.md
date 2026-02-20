Bundled Go tool binaries are placed here during wheel builds.

Expected layout:

- `_bin/linux-x86_64/probe`
- `_bin/linux-x86_64/http_verify`
- `_bin/linux-x86_64/dns_enum`
- `_bin/darwin-arm64/...`
- `_bin/windows-x86_64/*.exe`

The runtime resolver loads binaries from this directory first, then falls back to
`hands/bin`, cache, and optional download.
