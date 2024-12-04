package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/plugin/internal/remotecall"
	"github.com/urfave/cli/v2"
)

func createRemoteCaller(c *cli.Context) (*remotecall.RemoteCall, error) {
	remoteCall, err := remotecall.InitRemoteCall(
		c.String(userClusterEndpoint),
		c.String(userClusterEndpointToken),
		c.Generic(remoteAuthEndpoints).(*remotecall.StringMapFlag).Value,
		c.Generic(remoteAuthEndpointsSecret).(*remotecall.StringMapFlag).Value,
		c.Generic(remoteEndpoints).(*remotecall.StringMapFlag).Value,
		c.Path(mappingKeyPath),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating remote caller: %w", err)
	}

	return remoteCall, nil
}

func generateUpstreamUserName(response *remotecall.UserKeyAuthResponse) string {
	return "user" + "." + response.Data.UUID
}

const (
	remoteAuthEndpoints       = "remote-auth-endpoint"
	remoteAuthEndpointsSecret = "remote-auth-endpoint-secret"
	remoteEndpoints           = "remote-endpoint"
	userClusterEndpoint       = "user-cluster-endpoint"
	userClusterEndpointToken  = "user-cluster-endpoint-token"
	mappingKeyPath            = "mapping-key-path"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "remote call",
		Usage: "sshpiperd remote plugin",
		Flags: []cli.Flag{
			&cli.GenericFlag{
				Name:     remoteAuthEndpoints,
				Usage:    "cluster-url map for remote endpoint for retrieving user's private key(given as prod1=url)",
				EnvVars:  []string{"SSHPIPERD_PRIVATE_KEY_ENDPOINTS"},
				Value:    &remotecall.StringMapFlag{},
				Required: true,
			},
			&cli.GenericFlag{
				Name:     remoteAuthEndpointsSecret,
				Usage:    "cluster-secret map for cluster-url for auth(given as prod1=token)",
				EnvVars:  []string{"SSHPIPERD_PRIVATE_KEY_ENDPOINTS"},
				Value:    &remotecall.StringMapFlag{},
				Required: true,
			},
			&cli.GenericFlag{
				Name:     remoteEndpoints,
				Usage:    "path to remote endpoint for forwarding traffic",
				EnvVars:  []string{"SSHPIPERD_IN_CLUSTER_ENDPOINTS"},
				Value:    &remotecall.StringMapFlag{},
				Required: true,
			},
			&cli.StringFlag{
				Name:    userClusterEndpoint,
				Usage:   "endpoint for getting user to cluster mapping",
				EnvVars: []string{"SSHPIPERD_USER_MAPPING_ENDPOINT"},
			},
			&cli.StringFlag{
				Name:    userClusterEndpointToken,
				Usage:   "auth token(added to header) for getting user to cluster mapping",
				EnvVars: []string{"SSHPIPERD_USER_MAPPING_ENDPOINT_TOKEN"},
			},
			&cli.PathFlag{
				Name:    mappingKeyPath,
				Usage:   "mapping key for upstream",
				EnvVars: []string{"SSHPIPERD_MAPPING_KEY_PATH"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			return createConfig(c)
		},
	})
}

func createConfig(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
	caller, err := createRemoteCaller(c)
	if err != nil {
		return nil, fmt.Errorf("error creating remote caller: %w", err)
	}

	return &libplugin.SshPiperPluginConfig{
		PublicKeyCallbackNew: func(conn libplugin.ConnMetadata, key []byte, keytype string) (*libplugin.Upstream, error) {
			clusterName, err := caller.GetClusterName(conn.User())
			log.Debugf("username %s", conn.User())
			if err != nil {
				return nil, fmt.Errorf("error getting cluster name from user: %w", err)
			}

			clusterAuthnURL, err := caller.GetUpstreamAuthenticatorURL(clusterName)
			if err != nil {
				return nil, fmt.Errorf("error getting authenticator url from cluster name: %w", err)
			}
			clusterAuthnToken, err := caller.GetUpstreamAuthenticatorAuthToken(clusterName)
			if err != nil {
				return nil, fmt.Errorf("error getting authenticator token from cluster name: %w", err)
			}

			authResponse, err := caller.AuthenticateKey(key, keytype, clusterAuthnURL, clusterAuthnToken, conn.User())
			if err != nil {
				return nil, fmt.Errorf("error authenticating to clusterUrl %q: %w", clusterAuthnURL, err)
			}

			k := caller.MapKey()

			inClusterSvcUrl, err := caller.GetUpstreamSvcURL(clusterName)
			if err != nil {
				return nil, fmt.Errorf("error getting upstream url for cluster %q: %w", clusterName, err)
			}

			host, port, err := libplugin.SplitHostPortForSSH(inClusterSvcUrl)
			if err != nil {
				return nil, fmt.Errorf("error getting host port for in cluster svc url %q: %w",
					inClusterSvcUrl, err)
			}

			return &libplugin.Upstream{
				Host:          host,
				Port:          int32(port),
				UserName:      generateUpstreamUserName(authResponse),
				Auth:          libplugin.CreatePrivateKeyAuth(k),
				IgnoreHostKey: true,
			}, nil
		},
	}, nil
}
