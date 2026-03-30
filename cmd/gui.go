// cmd/gui.go — Terminal GUI dashboard using tview
// Made by Milkyway Intelligence | Author: Sharlix

package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/httpsm7/m7vpn/core"
	"github.com/httpsm7/m7vpn/utils"
	"github.com/rivo/tview"
)

func runGUI() error {
	app := tview.NewApplication()

	// ── widgets ───────────────────────────────────────────────────────────────

	header := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	header.SetBorder(true).SetBorderColor(tcell.ColorTeal)
	fmt.Fprint(header, "\n[teal::b]M7VPN[white] — Multi-Protocol VPN Orchestration Framework\n")
	fmt.Fprint(header, "[yellow]Made by Milkyway Intelligence  |  Author: Sharlix[-]")

	statusView := tview.NewTextView().SetDynamicColors(true)
	statusView.SetTitle(" [ STATUS ] ").SetBorder(true).SetBorderColor(tcell.ColorTeal)

	serverList := tview.NewList().ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(tcell.ColorTeal)
	serverList.SetTitle(" [ SERVERS ] ").SetBorder(true).SetBorderColor(tcell.ColorTeal)

	logsView := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).
		SetChangedFunc(func() { app.Draw() })
	logsView.SetTitle(" [ LOGS ] ").SetBorder(true).SetBorderColor(tcell.ColorTeal)

	protoDrop := tview.NewDropDown().
		SetLabel("Protocol ▸ ").
		SetOptions([]string{"WireGuard", "OpenVPN", "IKEv2", "Shadowsocks"}, nil).
		SetCurrentOption(0)
	protoDrop.SetBorder(true).SetBorderColor(tcell.ColorTeal)

	bar := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	fmt.Fprint(bar, "[teal]Tab[white]:Focus  [teal]C[white]:Connect  [teal]D[white]:Disconnect  [teal]R[white]:Rotate  [teal]Q[white]:Quit")

	// ── layout ────────────────────────────────────────────────────────────────

	leftCol := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(serverList, 0, 3, true).
		AddItem(protoDrop, 3, 0, false)

	rightCol := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(statusView, 14, 0, false).
		AddItem(logsView, 0, 1, false)

	mid := tview.NewFlex().
		AddItem(leftCol, 0, 1, true).
		AddItem(rightCol, 0, 2, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 5, 0, false).
		AddItem(mid, 0, 1, true).
		AddItem(bar, 1, 0, false)

	// ── populate server list ──────────────────────────────────────────────────

	ctrl, err := core.NewController(false)
	if err == nil {
		for _, n := range ctrl.GetNodeManager().GetAll() {
			stat := "○ Offline"
			if n.Online {
				stat = "● Online"
			}
			serverList.AddItem(
				fmt.Sprintf(" %s — %s", cap1(n.Country), n.City),
				fmt.Sprintf("   %s  |  %s  |  %s", n.IP, nodeProtocols(n), stat),
				0, nil,
			)
		}
	}

	// ── initial fill ──────────────────────────────────────────────────────────

	refreshStatus(statusView)
	refreshLogs(logsView)

	// ── auto-refresh goroutine ────────────────────────────────────────────────

	go func() {
		for {
			time.Sleep(3 * time.Second)
			app.QueueUpdateDraw(func() {
				refreshStatus(statusView)
				refreshLogs(logsView)
			})
		}
	}()

	// ── key bindings ──────────────────────────────────────────────────────────

	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Rune() {
		case 'q', 'Q':
			app.Stop()
			return nil

		case 'd', 'D':
			go func() {
				c2, err := core.NewController(false)
				if err != nil {
					return
				}
				msg := "[green]Disconnected"
				if err := c2.Disconnect(); err != nil {
					msg = "[red]" + err.Error()
				}
				app.QueueUpdateDraw(func() {
					guiLog(logsView, msg)
					refreshStatus(statusView)
				})
			}()
			return nil

		case 'r', 'R':
			go func() {
				c2, err := core.NewController(false)
				if err != nil {
					return
				}
				msg := "[green]IP rotated"
				if err := c2.RotateIP(); err != nil {
					msg = "[red]Rotate: " + err.Error()
				}
				app.QueueUpdateDraw(func() {
					guiLog(logsView, msg)
					refreshStatus(statusView)
				})
			}()
			return nil

		case 'c', 'C':
			showConnectModal(app, root, serverList, protoDrop, statusView, logsView)
			return nil
		}
		return ev
	})

	app.SetRoot(root, true).SetFocus(serverList)
	return app.Run()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func refreshStatus(v *tview.TextView) {
	v.Clear()
	sm := core.GetStateManager()
	s := sm.Get()
	if !s.Connected {
		fmt.Fprint(v, "\n  [red]● DISCONNECTED[-]\n\n")
		if ip, err := utils.GetPublicIP(); err == nil {
			fmt.Fprintf(v, "  [white]Real IP:[-]   [yellow]%s[-]\n", ip)
		}
		return
	}
	fmt.Fprint(v, "\n  [green]● CONNECTED[-]\n\n")
	fmt.Fprintf(v, "  [teal]Country:[-]   [white]%s[-]\n", strings.ToUpper(s.Country))
	fmt.Fprintf(v, "  [teal]Protocol:[-]  [white]%s[-]\n", fmtProto(s.Protocol))
	fmt.Fprintf(v, "  [teal]Server:[-]    [white]%s[-]\n", s.ServerIP)
	if s.PublicIP != "" {
		fmt.Fprintf(v, "  [teal]VPN IP:[-]    [green]%s[-]\n", s.PublicIP)
	}
	fmt.Fprintf(v, "  [teal]Interface:[-] [white]%s[-]\n", s.Interface)
	fmt.Fprintf(v, "  [teal]Uptime:[-]    [white]%s[-]\n", sm.GetUptime())
	if s.KillSwitchActive {
		fmt.Fprint(v, "  [teal]Kill Switch:[-] [green]ACTIVE[-]\n")
	}
}

func refreshLogs(v *tview.TextView) {
	lines := utils.TailLog(25)
	if len(lines) == 0 {
		return
	}
	v.Clear()
	for _, line := range lines {
		col := "[gray]"
		switch {
		case strings.Contains(line, "ERROR"):
			col = "[red]"
		case strings.Contains(line, "WARN"):
			col = "[yellow]"
		case strings.Contains(line, "OK"):
			col = "[green]"
		}
		fmt.Fprintf(v, "%s%s[-]\n", col, line)
	}
	v.ScrollToEnd()
}

func guiLog(v *tview.TextView, msg string) {
	fmt.Fprintf(v, "%s  %s[-]\n", time.Now().Format("15:04:05"), msg)
	v.ScrollToEnd()
}

func showConnectModal(app *tview.Application, root tview.Primitive,
	list *tview.List, drop *tview.DropDown,
	statusView, logsView *tview.TextView) {

	ctrl, err := core.NewController(false)
	if err != nil {
		return
	}
	all := ctrl.GetNodeManager().GetAll()
	idx := list.GetCurrentItem()
	if idx >= len(all) {
		return
	}
	node := all[idx]
	_, protoName := drop.GetCurrentOption()
	protoMap := map[string]string{
		"WireGuard": "wg", "OpenVPN": "openvpn",
		"IKEv2": "ikev2", "Shadowsocks": "ss",
	}
	proto := protoMap[protoName]
	if proto == "" {
		proto = "wg"
	}

	modal := tview.NewModal().
		SetText(fmt.Sprintf("Connect to %s (%s)\nvia %s?", cap1(node.Country), node.City, fmtProto(proto))).
		AddButtons([]string{"Connect", "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			app.SetRoot(root, true)
			if label == "Connect" {
				go func() {
					c2, err := core.NewController(false)
					if err != nil {
						return
					}
					msg := fmt.Sprintf("[green]Connected to %s", node.Country)
					if err := c2.Connect(core.ConnectOptions{
						Country: node.Country, Protocol: proto, NodeID: node.ID,
					}); err != nil {
						msg = "[red]" + err.Error()
					}
					app.QueueUpdateDraw(func() {
						guiLog(logsView, msg)
						refreshStatus(statusView)
					})
				}()
			}
		})
	app.SetRoot(modal, false)
}
