package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

func main() {
	var windowText string
	var x, y int
	flag.StringVar(&windowText, "window", "", "X11 window ID (decimal or 0x-prefixed hexadecimal)")
	flag.IntVar(&x, "x", -1, "window-relative X coordinate")
	flag.IntVar(&y, "y", -1, "window-relative Y coordinate")
	flag.Parse()

	windowValue, err := strconv.ParseUint(windowText, 0, 32)
	if err != nil || windowValue == 0 {
		exitf("invalid window ID %q", windowText)
	}
	if x < 0 || x > math.MaxInt16 || y < 0 || y > math.MaxInt16 {
		exitf("invalid window coordinates %d,%d", x, y)
	}

	connection, err := xgb.NewConn()
	if err != nil {
		exitf("connect to X11 display: %v", err)
	}
	defer connection.Close()

	window := xproto.Window(windowValue)
	geometry, err := xproto.GetGeometry(connection, xproto.Drawable(window)).Reply()
	if err != nil {
		exitf("read window geometry: %v", err)
	}
	if x >= int(geometry.Width) || y >= int(geometry.Height) {
		exitf("coordinates %d,%d are outside %dx%d window", x, y, geometry.Width, geometry.Height)
	}
	for attempt := 0; ; attempt++ {
		attributes, attributeErr := xproto.GetWindowAttributes(connection, window).Reply()
		if attributeErr != nil {
			exitf("read window attributes: %v", attributeErr)
		}
		if attributes.MapState == xproto.MapStateViewable {
			break
		}
		if attempt == 99 {
			exitf("window did not become viewable")
		}
		time.Sleep(10 * time.Millisecond)
	}

	setup := xproto.Setup(connection)
	root := setup.DefaultScreen(connection).Root
	if err := xtest.Init(connection); err != nil {
		exitf("initialize XTEST: %v", err)
	}
	if err := xproto.WarpPointerChecked(
		connection, xproto.WindowNone, window, 0, 0, 0, 0, int16(x), int16(y),
	).Check(); err != nil {
		exitf("move pointer into window: %v", err)
	}
	pointer, err := xproto.QueryPointer(connection, window).Reply()
	if err != nil {
		exitf("query pointer position: %v", err)
	}
	if !pointer.SameScreen || pointer.WinX != int16(x) || pointer.WinY != int16(y) {
		exitf("pointer reached %d,%d instead of %d,%d", pointer.WinX, pointer.WinY, x, y)
	}
	if err := xtest.FakeInputChecked(
		connection, xproto.ButtonPress, 1, xproto.TimeCurrentTime,
		root, pointer.RootX, pointer.RootY, 0,
	).Check(); err != nil {
		exitf("press button through XTEST: %v", err)
	}
	if err := xtest.FakeInputChecked(
		connection, xproto.ButtonRelease, 1, xproto.TimeCurrentTime,
		root, pointer.RootX, pointer.RootY, 0,
	).Check(); err != nil {
		exitf("release button through XTEST: %v", err)
	}
	connection.Sync()
	fmt.Printf("x11-click: delivered verified pointer input to window %s at %d,%d\n", windowText, x, y)
}

func exitf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "x11-click: "+format+"\n", arguments...)
	os.Exit(2)
}
