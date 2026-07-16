# Third-Party Notices

Mitoriq Collector includes the following third-party Go modules in its compiled binary. Required license and attribution texts are bundled under `THIRD_PARTY_LICENSES/` and are included in release archives.

The Go standard library is distributed under the BSD-3-Clause license. Its license is bundled at `THIRD_PARTY_LICENSES/go.dev/standard-library/LICENSE`; the exact toolchain version is defined by `go.mod`.

| Module                             | Version                              | License                                       |
| ---------------------------------- | ------------------------------------ | --------------------------------------------- |
| `github.com/dustin/go-humanize`    | `v1.0.1`                             | MIT                                           |
| `github.com/google/uuid`           | `v1.6.0`                             | BSD-3-Clause                                  |
| `github.com/mattn/go-isatty`       | `v0.0.20`                            | MIT                                           |
| `github.com/ncruces/go-strftime`   | `v1.0.0`                             | MIT                                           |
| `github.com/remyoudompheng/bigfft` | `v0.0.0-20230129092748-24d4a6f8daec` | BSD-3-Clause                                  |
| `golang.org/x/exp`                 | `v0.0.0-20251023183803-a4bb9ffd2546` | BSD-3-Clause                                  |
| `golang.org/x/sys`                 | `v0.37.0`                            | BSD-3-Clause                                  |
| `modernc.org/libc`                 | `v1.67.6`                            | BSD-3-Clause with bundled third-party notices |
| `modernc.org/mathutil`             | `v1.7.1`                             | BSD-3-Clause                                  |
| `modernc.org/memory`               | `v1.11.0`                            | BSD-3-Clause with bundled additional notices  |
| `modernc.org/sqlite`               | `v1.45.0`                            | BSD-3-Clause                                  |

The inventory was generated for `./cmd/mitoriq-collector` with `google/go-licenses` v1.6.0. `modernc.org/mathutil` was classified manually from the license texts shipped in that module because the tool did not classify it automatically.
