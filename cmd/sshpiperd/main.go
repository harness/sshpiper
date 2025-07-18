package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"time"

	"github.com/pires/go-proxyproto"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/plugin"
)

var mainver string = "(devel)"

func version() string {

	var v = mainver

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			v = fmt.Sprintf("%v, %v", v, s.Value[:9])
		case "vcs.time":
			v = fmt.Sprintf("%v, %v", v, s.Value)
		}
	}

	v = fmt.Sprintf("%v, %v", v, bi.GoVersion)

	return v
}

func splitByDash(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}

	return args, nil
}

func createCmdPlugin(args []string) (*plugin.CmdPlugin, error) {
	exe := args[0]

	cmd := exec.Command(exe)
	cmd.Args = args
	setPdeathsig(cmd)

	log.Info("starting child process plugin: ", cmd.Args)

	p, err := plugin.DialCmd(cmd)
	if err != nil {
		return nil, err
	}

	if err := addProcessToJob(cmd); err != nil {
		return nil, err
	}

	p.Name = exe

	return p, nil
}

func isValidLogFormat(logFormat string) bool {
	validFormats := []string{"text", "json"}
	return slices.Contains(validFormats, logFormat)
}

func main() {

	app := &cli.App{
		Name:        "sshpiperd",
		Usage:       "the missing reverse proxy for ssh scp",
		UsageText:   "sshpiperd [options] <plugin1> [plugin options] [-- [plugin2] [plugin options] [-- ...]]",
		Description: "sshpiperd works as a proxy-like ware, and route connections by username, src ip , etc.\nhttps://github.com/tg123/sshpiper",
		Version:     version(),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "address",
				Aliases: []string{"l"},
				Value:   "0.0.0.0",
				Usage:   "listening address",
				EnvVars: []string{"SSHPIPERD_ADDRESS"},
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   2222,
				Usage:   "listening port",
				EnvVars: []string{"SSHPIPERD_PORT"},
			},
			&cli.StringFlag{
				Name:    "server-key",
				Aliases: []string{"i"},
				Usage:   "server key files, support wildcard",
				Value:   "/etc/ssh/ssh_host_ed25519_key",
				EnvVars: []string{"SSHPIPERD_SERVER_KEY"},
			},
			&cli.StringFlag{
				Name:    "server-key-data",
				Usage:   "server key in base64 format, server-key, server-key-generate-mode will be ignored if set",
				EnvVars: []string{"SSHPIPERD_SERVER_KEY_DATA"},
			},
			&cli.StringFlag{
				Name:    "server-key-generate-mode",
				Usage:   "server key generate mode, one of: disable, notexist, always. generated key will be written to `server-key` if notexist or always",
				Value:   "disable",
				EnvVars: []string{"SSHPIPERD_SERVER_KEY_GENERATE_MODE"},
			},
			&cli.DurationFlag{
				Name:    "login-grace-time",
				Value:   30 * time.Second,
				Usage:   "sshpiperd forcely close the connection after this time if the pipe has not successfully established",
				EnvVars: []string{"SSHPIPERD_LOGIN_GRACE_TIME"},
			},
			&cli.StringFlag{
				Name:    "log-level",
				Value:   "info",
				Usage:   "log level, one of: trace, debug, info, warn, error, fatal, panic",
				EnvVars: []string{"SSHPIPERD_LOG_LEVEL"},
			},
			&cli.StringFlag{
				Name:    "log-format",
				Value:   "text",
				Usage:   "log format, one of: text, json",
				EnvVars: []string{"SSHPIPERD_LOG_FORMAT"},
			},
			&cli.StringFlag{
				Name:    "screen-recording-dir",
				Value:   "",
				Usage:   "the directory to save screen recording files",
				EnvVars: []string{"SSHPIPERD_SCREEN_RECORDING_DIR"},
			},
			&cli.StringFlag{
				Name:    "screen-recording-format",
				Value:   "asciicast",
				Usage:   "the format of screen recording files, one of: typescript (https://linux.die.net/man/1/script), asciicast (https://docs.asciinema.org/manual/asciicast/v2)",
				EnvVars: []string{"SSHPIPERD_SCREEN_RECORDING_FORMAT"},
			},
			&cli.BoolFlag{
				Name:    "username-as-recorddir",
				Value:   false,
				Usage:   "use the username as the directory name for saving screen recording files",
				EnvVars: []string{"SSHPIPERD_USERNAME_AS_RECORDDIR"},
			},
			&cli.StringFlag{
				Name:    "banner-text",
				Value:   "",
				Usage:   "display a banner before authentication, would be ignored if banner file was set",
				EnvVars: []string{"SSHPIPERD_BANNERTEXT"},
			},
			&cli.StringFlag{
				Name:    "banner-file",
				Value:   "",
				Usage:   "display a banner from file before authentication",
				EnvVars: []string{"SSHPIPERD_BANNERFILE"},
			},
			&cli.BoolFlag{
				Name:    "drop-hostkeys-message",
				Value:   false,
				Usage:   "filter out hostkeys-00@openssh.com which cause client side warnings",
				EnvVars: []string{"SSHPIPERD_DROP_HOSTKEYS_MESSAGE"},
			},
			&cli.StringSliceFlag{
				Name:    "allowed-proxy-addresses",
				Value:   cli.NewStringSlice(),
				Usage:   "allowed proxy addresses, only connections from these ip ranges are allowed to send a proxy header based on the PROXY protocol, empty will disable the PROXY protocol support",
				EnvVars: []string{"SSHPIPERD_ALLOWED_PROXY_ADDRESSES"},
			},
		},
		Action: func(ctx *cli.Context) error {
			level, err := log.ParseLevel(ctx.String("log-level"))
			if err != nil {
				return err
			}

			log.SetLevel(level)
			log.SetFormatter(&log.JSONFormatter{
				FieldMap: log.FieldMap{
					log.FieldKeyTime:  "timestamp",
					log.FieldKeyLevel: "severity",
					log.FieldKeyMsg:   "message",
				},
				TimestampFormat: time.RFC3339Nano,
			})
			logFormat := ctx.String("log-format")
			if !isValidLogFormat(logFormat) {
				return fmt.Errorf("not a valid log-format: %v", logFormat)
			}
			if logFormat == "json" {
				log.SetFormatter(&log.JSONFormatter{})
			}

			log.Info("starting sshpiperd version: ", version())
			d, err := newDaemon(ctx)

			if err != nil {
				return err
			}

			quit := make(chan error)

			allowedproxyaddresses := ctx.StringSlice("allowed-proxy-addresses")

			if len(allowedproxyaddresses) > 0 {
				proxypolicy, err := proxyproto.LaxWhiteListPolicy(allowedproxyaddresses)
				if err != nil {
					return err
				}

				d.lis = &proxyproto.Listener{Listener: d.lis, Policy: proxypolicy}
			}

			var plugins []*plugin.GrpcPlugin

			args := ctx.Args().Slice()
			remain := args

			for {
				if len(remain) <= 0 {
					break
				}

				args, remain = splitByDash(remain)

				if len(args) <= 0 {
					continue
				}

				var p *plugin.GrpcPlugin

				switch args[0] {
				case "grpc":
					log.Info("starting net grpc plugin: ")

					grpcplugin, err := createNetGrpcPlugin(args)
					if err != nil {
						return err
					}

					p = grpcplugin

				default:
					cmdplugin, err := createCmdPlugin(args)
					if err != nil {
						return err
					}

					go func() {
						quit <- <-cmdplugin.Quit
					}()

					p = &cmdplugin.GrpcPlugin
				}

				go func() {
					if err := p.RecvLogs(log.StandardLogger().Out); err != nil {
						log.Errorf("plugin %v recv logs error: %v", p.Name, err)
					}
				}()
				plugins = append(plugins, p)
			}

			if err := d.install(plugins...); err != nil {
				return err
			}

			d.recorddir = ctx.String("screen-recording-dir")
			d.recordfmt = ctx.String("screen-recording-format")
			d.usernameAsRecorddir = ctx.Bool("username-as-recorddir")
			d.filterHostkeysReqeust = ctx.Bool("drop-hostkeys-message")

			if d.recordfmt != "typescript" && d.recordfmt != "asciicast" {
				return fmt.Errorf("invalid screen recording format: %v", d.recordfmt)
			}

			go func() {
				quit <- d.run()
			}()

			return <-quit
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
