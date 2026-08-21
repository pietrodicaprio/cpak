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

	// PointerMotion is a non-exclusive selection, so observing it confirms the
	// server routes pointer input to the target window without contending with
	// the owner. ButtonPress is exclusive in X11: selecting it here would either
	// fail with BadAccess or steal the click from the real dialog.
	eventMask := uint32(xproto.EventMaskPointerMotion)
	if err := xproto.ChangeWindowAttributesChecked(
		connection, window, xproto.CwEventMask, []uint32{eventMask},
	).Check(); err != nil {
		exitf("observe pointer motion on window: %v", err)
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
	motion := waitForEvent(connection, "pointer motion", func(event xgb.Event) bool {
		notification, ok := event.(xproto.MotionNotifyEvent)
		return ok && notification.Event == window && notification.EventX == int16(x) && notification.EventY == int16(y)
	})
	if motion == nil {
		exitf("X server did not deliver pointer motion to the target window")
	}
	if err := xtest.FakeInputChecked(
		connection, xproto.ButtonPress, 1, xproto.TimeCurrentTime,
		root, pointer.RootX, pointer.RootY, 0,
	).Check(); err != nil {
		exitf("press button through XTEST: %v", err)
	}
	// The checked request forced a round trip, so the server has already applied
	// the synthetic press. Query the root because it always exists: the target
	// window may be unmapped the instant the dialog acts on the click. The button
	// mask reflects real core pointer state, which changes only if the injected
	// input actually took effect rather than merely being accepted.
	pressed, err := xproto.QueryPointer(connection, root).Reply()
	if err != nil {
		exitf("query pointer state after press: %v", err)
	}
	if pressed.Mask&xproto.KeyButMaskButton1 == 0 {
		exitf("XTEST press did not register in the core pointer button state")
	}
	if err := xtest.FakeInputChecked(
		connection, xproto.ButtonRelease, 1, xproto.TimeCurrentTime,
		root, pointer.RootX, pointer.RootY, 0,
	).Check(); err != nil {
		exitf("release button through XTEST: %v", err)
	}
	released, err := xproto.QueryPointer(connection, root).Reply()
	if err != nil {
		exitf("query pointer state after release: %v", err)
	}
	if released.Mask&xproto.KeyButMaskButton1 != 0 {
		exitf("XTEST release left button 1 held in the core pointer state")
	}
	fmt.Printf("x11-click: routed motion to window %s at %d,%d and observed a synthetic button-1 press and release in the core pointer state\n", windowText, x, y)
}

func waitForEvent(connection *xgb.Conn, description string, matches func(xgb.Event) bool) xgb.Event {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		event, err := connection.PollForEvent()
		if err != nil {
			exitf("observe %s: %v", description, err)
		}
		if event != nil && matches(event) {
			return event
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

func exitf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "x11-click: "+format+"\n", arguments...)
	os.Exit(2)
}
