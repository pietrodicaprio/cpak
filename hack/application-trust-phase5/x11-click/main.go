package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
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

	setup := xproto.Setup(connection)
	root := setup.DefaultScreen(connection).Root
	translated, err := xproto.TranslateCoordinates(connection, window, root, 0, 0).Reply()
	if err != nil {
		exitf("translate window coordinates: %v", err)
	}

	press := xproto.ButtonPressEvent{
		Detail:     1,
		Time:       xproto.TimeCurrentTime,
		Root:       root,
		Event:      window,
		RootX:      translated.DstX + int16(x),
		RootY:      translated.DstY + int16(y),
		EventX:     int16(x),
		EventY:     int16(y),
		SameScreen: true,
	}
	if err := xproto.SendEventChecked(
		connection, false, window, xproto.EventMaskButtonPress, string(press.Bytes()),
	).Check(); err != nil {
		exitf("send button press: %v", err)
	}

	release := xproto.ButtonReleaseEvent(press)
	if err := xproto.SendEventChecked(
		connection, false, window, xproto.EventMaskButtonRelease, string(release.Bytes()),
	).Check(); err != nil {
		exitf("send button release: %v", err)
	}
	connection.Sync()
}

func exitf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "x11-click: "+format+"\n", arguments...)
	os.Exit(2)
}
