/*
 * Copyright (c) 2026 Fabricators
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package desktopui

import (
	"context"
	"image"
	"image/draw"

	"golang.org/x/exp/shiny/driver"
	"golang.org/x/exp/shiny/screen"
	"golang.org/x/mobile/event/key"
	"golang.org/x/mobile/event/lifecycle"
	"golang.org/x/mobile/event/mouse"
	"golang.org/x/mobile/event/paint"
	"golang.org/x/mobile/event/size"
)

type reputationPromptState struct {
	hovered int
	palette desktopPalette
}

type reputationPromptEvent struct{}

func confirmReputationBuiltin(ctx context.Context, request ReputationPrompt) (bool, error) {
	accepted := false
	var windowErr error
	driver.Main(func(display screen.Screen) {
		const width, height = 620, 540
		window, err := display.NewWindow(&screen.NewWindowOptions{Width: width, Height: height, Title: "Publisher reputation"})
		if err != nil {
			windowErr = err
			return
		}
		defer window.Release()
		frame := newDesktopFrame("Publisher reputation")
		if frame != nil {
			defer frame.Close()
		}
		state := &reputationPromptState{hovered: -1, palette: currentDesktopPalette()}
		var dimensions size.Event
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-ctx.Done():
				window.Send(reputationPromptEvent{})
			case <-stop:
			}
		}()
		for {
			event := window.NextEvent()
			switch event := event.(type) {
			case lifecycle.Event:
				if event.To == lifecycle.StageDead {
					return
				}
			case size.Event:
				dimensions = event
				window.Send(paint.Event{})
			case paint.Event:
				renderReputationPrompt(display, window, dimensions, request, state)
			case reputationPromptEvent:
				if ctx.Err() != nil {
					windowErr = ctx.Err()
					return
				}
			case mouse.Event:
				point := image.Pt(int(event.X), int(event.Y))
				state.hovered = reputationActionAt(point, dimensions.WidthPx, dimensions.HeightPx)
				window.Send(paint.Event{})
				if event.Button != mouse.ButtonLeft || event.Direction != mouse.DirPress {
					continue
				}
				switch state.hovered {
				case 0:
					return
				case 1:
					accepted = true
					return
				}
				if point.Y < 54 && frame != nil {
					frame.StartMove()
				}
			case key.Event:
				// Escape is decline. Enter deliberately has no action: accepting a
				// reputation warning requires an explicit click on the risk action.
				if event.Code == key.CodeEscape && event.Direction == key.DirPress {
					return
				}
			}
		}
	})
	return accepted, windowErr
}

func renderReputationPrompt(display screen.Screen, window screen.Window, dimensions size.Event, request ReputationPrompt, state *reputationPromptState) {
	width, height := dimensions.WidthPx, dimensions.HeightPx
	if width <= 0 || height <= 0 {
		return
	}
	canvas := reputationPromptCanvas(width, height, request, state)
	buffer, err := display.NewBuffer(image.Pt(width, height))
	if err != nil {
		return
	}
	defer buffer.Release()
	draw.Draw(buffer.RGBA(), buffer.Bounds(), canvas, image.Point{}, draw.Src)
	window.Upload(image.Point{}, buffer, buffer.Bounds())
	window.Publish()
}

func reputationPromptCanvas(width, height int, request ReputationPrompt, state *reputationPromptState) *image.RGBA {
	palette := state.palette
	canvas := image.NewRGBA(image.Rect(0, 0, width, height))
	drawGrantBackdrop(canvas, palette)
	drawUpdateOutline(canvas, canvas.Bounds(), palette.line)
	drawGrantBrand(canvas, palette, brandIconPNG)
	drawUpdateCentered(canvas, "Reputation requires your decision", width/2, 92, 25, true, palette.text)
	drawUpdateWrapped(canvas, reputationPromptBody(request), image.Rect(46, 122, width-46, height-116), 14, palette.muted)
	drawReputationAction(canvas, reputationAction(width, height, 0), "Leave unenrolled", state.hovered == 0, true, palette)
	drawReputationAction(canvas, reputationAction(width, height, 1), "Enrol this installation", state.hovered == 1, false, palette)
	return canvas
}

func drawReputationAction(target *image.RGBA, bounds image.Rectangle, label string, hovered, recommended bool, palette desktopPalette) {
	style := dialogStyleFromPalette(palette)
	fill, text := style.ActionColors(recommended, hovered, true)
	drawUpdateRounded(target, bounds, bounds.Dy()/2, fill)
	drawUpdateCenteredFitted(target, label, bounds.Min.X+bounds.Dx()/2, bounds.Min.Y+31, bounds.Dx()-16, 16, true, text)
}

func reputationActionAt(point image.Point, width, height int) int {
	for index := 0; index < 2; index++ {
		if point.In(reputationAction(width, height, index)) {
			return index
		}
	}
	return -1
}

func reputationAction(width, height, index int) image.Rectangle {
	const buttonWidth, gap = 220, 18
	left := (width-(buttonWidth*2+gap))/2 + index*(buttonWidth+gap)
	return image.Rect(left, height-84, left+buttonWidth, height-38)
}
