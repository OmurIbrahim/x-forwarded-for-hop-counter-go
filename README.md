# x-forwarded-for-hop-counter-go

Parses an `X-Forwarded-For` header, trims it to a trusted proxy hop count, and returns the originating client IP.

```go
package main

import (
	"fmt"

	xff "x-forwarded-for-hop-counter-go"
)

func main() {
	header := "203.0.113.7, 198.51.100.4, 192.0.2.9"

	client, err := xff.ClientIP(header, 2)
	if err != nil {
		panic(err)
	}
	fmt.Println(client) // 203.0.113.7
}
```

## Why this exists

A server behind a load balancer sees the balancer's address as the peer, not the client's. The `X-Forwarded-For` header carries the chain, but the chain is user-controllable: a client can send its own header, and each proxy appends to it. The safe way to read it is to count how many proxies you actually trust and ignore everything to their left.

This library does exactly that one job. The trade-off is that it does not try to guess the hop count from the header itself, and it does not validate the addresses you have chosen to trust. You pass the number of trusted hops; it returns the address at that position. If you get the number wrong, you get the wrong address, and that is a configuration problem rather than a parsing problem.

## Awkward edge

Empty entries are an error, not something to skip. A header like `203.0.113.7,,198.51.100.4` is rejected with `ErrEmptyHeader`. Skipping the empty entry would shift every position to its right and could silently return a proxy address as the client. The same applies to a trailing comma.

## API

- `ClientIP(header string, trustedHops int) (string, error)`
- `ErrEmptyHeader`
- `ErrTrustedHopsTooLarge`
- `ErrInvalidClientIP`

`trustedHops` is the number of proxies between the client and the server that you control. `0` returns the rightmost entry, `1` returns the entry to its left, and so on. A negative `trustedHops` is rejected with `ErrTrustedHopsTooLarge` because there is no sensible meaning for it.
