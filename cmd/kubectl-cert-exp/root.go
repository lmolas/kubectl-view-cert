package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/lmolas/kubectl-cert-exp/internal/parse"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // combined authprovider import
	"k8s.io/klog"
)

const (
	allNamespacesFlag = "all-namespaces"
	expiredFlag       = "expired"
	// expiredDateFlag   = "expired-date"
)

var cf *genericclioptions.ConfigFlags

// This variable is populated by goreleaser
var version string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:          "kubectl cert-exp",
	SilenceUsage: true, // for when RunE returns an error
	Short:        "Show sub-resources of the Kubernetes object",
	Example: "  kubectl tree deployment my-app\n" +
		"  kubectl tree kservice.v1.serving.knative.dev my-app", // TODO add more examples about disambiguation etc
	// Args:    cobra.MinimumNArgs(1),
	RunE:    run,
	Version: versionString(),
}

// versionString returns the version prefixed by 'v'
// or an empty string if no version has been populated by goreleaser.
// In this case, the --version flag will not be added by cobra.
func versionString() string {
	if len(version) == 0 {
		return ""
	}
	return "v" + version
}

func init() {
	klog.InitFlags(nil)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	// hide all glog flags except for -v
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name != "v" {
			pflag.Lookup(f.Name).Hidden = true
		}
	})

	cf = genericclioptions.NewConfigFlags(true)

	rootCmd.Flags().BoolP(allNamespacesFlag, "A", false, "query all objects in all API groups, both namespaced and non-namespaced")
	rootCmd.Flags().BoolP(expiredFlag, "E", false, "show only expired certificates")
	// rootCmd.Flags().DurationP(expireInFlag, "D", 10*24*time.Hour, "")

	cf.AddFlags(rootCmd.Flags())
	if err := flag.Set("logtostderr", "true"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set logtostderr flag: %v\n", err)
		os.Exit(1)
	}
}

func getNamespace() string {
	if v := *cf.Namespace; v != "" {
		return v
	}
	clientConfig := cf.ToRawKubeConfigLoader()
	defaultNamespace, _, err := clientConfig.Namespace()
	if err != nil {
		defaultNamespace = "default"
	}
	return defaultNamespace
}

func main() {
	defer klog.Flush()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(command *cobra.Command, args []string) error {
	klog.V(1).Info("Run kubectl cert-exp")

	allNs, err := command.Flags().GetBool(allNamespacesFlag)
	if err != nil {
		allNs = false
	}

	expired, err := command.Flags().GetBool(expiredFlag)
	if err != nil {
		expired = false
	}

	restConfig, err := cf.ToRESTConfig()
	if err != nil {
		return err
	}
	restConfig.QPS = 1000
	restConfig.Burst = 1000
	dyn, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to construct dynamic client: %w", err)
	}

	ns := getNamespace()
	klog.V(2).Infof("namespace=%s allNamespaces=%v", ns, allNs)

	var secretName string
	if len(args) > 0 {
		secretName = args[0]
	}

	if secretName != "" && ns == "" {
		klog.Info("Specify namespace and secret name")
		return nil
	}

	secretGroupVersionResource := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	klog.V(1).Infof("Secret group version resource Group=%s Resource=%s Version=%s", secretGroupVersionResource.Group, secretGroupVersionResource.Resource, secretGroupVersionResource.Version)

	var ri dynamic.ResourceInterface
	if allNs && secretName == "" {
		ri = dyn.Resource(secretGroupVersionResource)
	} else {
		ri = dyn.Resource(secretGroupVersionResource).Namespace(ns)
	}

	if secretName != "" {
		klog.V(1).Infof("Get secret name %s in namespace %s", secretName, ns)

		secret, err := ri.Get(secretName, v1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get secret with name %s: %w", secretName, err)
		}

		displaySecret(ns, secretName, secret.Object, nil)
	} else {
		klog.V(1).Info("Scanning secrets in namespace ", ns)
		tlsSecrets, err := ri.List(v1.ListOptions{FieldSelector: "type=kubernetes.io/tls"})
		if err != nil {
			return fmt.Errorf("failed to get secrets: %w", err)
		}

		for _, tlsSecret := range tlsSecrets.Items {
			now := time.Now().UTC()
			if expired {
				displaySecret(tlsSecret.GetNamespace(), tlsSecret.GetName(), tlsSecret.Object, &now)
			} else {
				displaySecret(tlsSecret.GetNamespace(), tlsSecret.GetName(), tlsSecret.Object, nil)
			}
		}
	}

	return nil
}

func displaySecret(ns, secretName string, data map[string]interface{}, date *time.Time) {
	secretType := fmt.Sprintf("%v", data["type"])
	klog.V(1).Infof("secret type %s", secretType)

	klog.V(1).Infof("%s/%s", ns, secretName)

	certData, err := parse.NewCertificateData(ns, secretName, data)
	if err != nil {
		klog.Errorf("failed to parse secret with name %s in namespace %s", secretName, ns)
		klog.V(2).Infof("failed to parse secret with name %s: %w", secretName, err)
		return
	}

	parsedCerts, err := certData.ParseCertificates()
	if err != nil {
		klog.Errorf("unable to parse certificates for secret %s in namespace %s", secretName, ns)
		klog.V(2).Infof("unable to parse certificates for secret %s %w", secretName, err)
		return
	}

	parsedCerts.Output(date)
}
