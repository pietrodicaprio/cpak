/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

// phase5-payload is the static headless command stored in the lifecycle OCI
// layer. Keeping it separate from the server proves execution without relying
// on a shell or any other binary in the image.
package main

import "fmt"

func main() {
	fmt.Println("phase5 fixture executed")
}
