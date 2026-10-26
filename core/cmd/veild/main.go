// veild is the desktop development daemon and CLI for the Veil core. The
// HarmonyOS app embeds the same packages through libveilcore.so; veild exists so
// the engine can be exercised on a normal machine.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"veil/internal/config"
	"veil/internal/ctl"
	"veil/internal/logx"
	"veil/internal/supervisor"
	"veil/internal/transport"
	"veil/internal/version"
)

func main() {
	var (
		cfgPath = flag.String("config", defaultConfigPath(), "path to config.json")
		sock    = flag.String("socket", "", "control socket path (default: next to config)")
		tunFD   = flag.Int("tun-fd", -1, "attach an existing tun fd (debugging only)")
		verbose = flag.Bool("v", false, "debug logging")
	)
	flag.Parse()

	if flag.NArg() > 0 {
		os.Exit(runClient(*sock, flag.Args()))
	}

	if *sock == "" {
		*sock = filepath.Join(filepath.Dir(*cfgPath), "veil.sock")
	}
	if _, err := os.Stat(*cfgPath); os.IsNotExist(err) {
		cfg := config.Default()
		if err := config.Save(*cfgPath, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "create config:", err)
			os.Exit(1)
		}
	}

	level := logx.Info
	if *verbose {
		level = logx.Debug
	}
	log := logx.New(level, 1024)
	log.SetSink(func(e logx.Entry) {
		fmt.Fprintf(os.Stderr, "%s %-5s %s\n", time.UnixMilli(e.Time).Format("15:04:05"), e.Level, e.Msg)
	})

	sup, err := supervisor.New(*cfgPath, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	server := ctl.NewServer(sup, *sock, log)
	sup.SetHost(server)
	sup.SetProtector(func(fd uintptr) error { return server.Protect(fd) })
	transport.SetProtector(server.Protect)

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Errorf("control socket: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, *tunFD); err != nil {
		log.Errorf("start: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Infof("shutting down")
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	_ = sup.Stop(sctx)
	_ = server.Close()
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "veil.json"
	}
	return filepath.Join(home, ".veil", "config.json")
}

// runClient implements `veild <method> [json-params]`.
func runClient(sock string, args []string) int {
	if sock == "" {
		sock = os.Getenv("VEIL_SOCKET")
	}
	if sock == "" {
		sock = filepath.Join(filepath.Dir(defaultConfigPath()), "veil.sock")
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: veild [flags] <method> [json]")
		return 2
	}
	c, err := ctl.Dial(sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		return 1
	}
	defer c.Close()
	var params any
	if len(args) > 1 {
		if err := json.Unmarshal([]byte(args[1]), &params); err != nil {
			fmt.Fprintln(os.Stderr, "params:", err)
			return 2
		}
	}
	res, err := c.Call(args[0], params)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	var pretty any
	_ = json.Unmarshal(res, &pretty)
	b, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Println(string(b))
	return 0
}

var _ = version.Version
