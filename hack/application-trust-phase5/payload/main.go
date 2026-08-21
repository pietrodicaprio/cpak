/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

// phase5-payload is the static headless command stored in the lifecycle OCI
// layer. Keeping it separate from the server proves execution without relying
// on a shell or any other binary in the image.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	args := os.Args[1:]
	switch {
	case len(args) == 0:
		fmt.Println("phase5 fixture executed")
	case len(args) == 1 && args[0] == "service":
		fmt.Println("phase5 service ready")
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
	default:
		fmt.Fprintf(os.Stderr, "phase5: unknown arguments: %v\n", args)
		os.Exit(1)
	}
}
