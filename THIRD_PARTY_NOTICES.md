# Third-party notices

This project is a second-development (fork-style) build based on the following
open-source projects. Their license notices are retained here as required.
One project (Deadpool, GPLv3) is referenced for design facts only: **no source
code from it was copied into this build**.

## easy_proxies

- Source: https://github.com/jasonwong1991/easy_proxies
- Version used: v3.3.0 (`9f6ccf9`)
- License: MIT License (declared in the upstream `README.md`; the upstream
  repository does not ship a standalone LICENSE file)

> MIT License
>
> Copyright (c) easy_proxies contributors
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## proxy_pool (design reference only)

- Source: https://github.com/jhao104/proxy_pool
- Version referenced: 2.4.0 (`9cc0cad`)
- License: MIT License, Copyright (c) 2017 J_hao104
- No Python source from this project is included in this build. Only the
  architectural idea (BaseFetcher-style pluggable free proxy sources, periodic
  fetch + verify + pool) is reimplemented in Go.

## Deadpool (design reference only, GPLv3)

- Source: https://github.com/thinkoaa/Deadpool
- Version referenced: v1.8 (`0341e8f`)
- License: **GNU General Public License v3.0** (upstream `LICENSE`)
- Attribution: upstream `main.go` prints `By:thinkoaa GitHub:https://github.com/thinkoaa/Deadpool`.

**No Deadpool source code is included in this build.** Only publicly observable
API integration facts were used to design our own configuration templates:

- FOFA / Hunter / Quake endpoint URLs, HTTP methods, auth parameter names,
  query parameter names, pagination behaviour and response field paths
  (upstream `utils/netspace.go`).
- The idea of a keyword/response-body liveness check and a bounded concurrency
  probe loop (upstream `utils/utils.go`).

All implementation here (`internal/source/presets.go`,
`internal/source/mapping.go`, `internal/verify/probe.go`, etc.) was written
independently. In particular, Deadpool sets
`tls.Config{InsecureSkipVerify: true}` and contains **no MITM detection**; our
malicious-MITM detection is original work and does not derive from Deadpool.

GPLv3 is a strong copyleft license. This notice acknowledges the reference and
does not grant any rights to relicense Deadpool itself.

> MIT License
>
> Copyright (c) 2017 J_hao104
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
