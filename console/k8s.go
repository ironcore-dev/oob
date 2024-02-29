package main

import (
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	oobv1alpha1 "github.com/ironcore-dev/oob/api/v1alpha1"
	"github.com/ironcore-dev/oob/internal/log"
)

func getInClusterNamespace() (string, error) {
	ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot determine in-cluster namespace: %w", err)
	}
	return string(ns), nil
}

type k8sClients struct {
	coreClient     *rest.RESTClient
	oobClient      *rest.RESTClient
	parameterCodec runtime.ParameterCodec
}

func newK8sClients(kubeconfig string) (k8sClients, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(kscheme.AddToScheme(scheme))
	utilruntime.Must(oobv1alpha1.AddToScheme(scheme))

	clients := k8sClients{
		parameterCodec: runtime.NewParameterCodec(scheme),
	}

	var err error
	var config *rest.Config
	if kubeconfig == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		return k8sClients{}, fmt.Errorf("cannot configure connection to Kubernetes: %w", err)
	}
	config.NegotiatedSerializer = serializer.NewCodecFactory(scheme)
	config.UserAgent = rest.DefaultKubernetesUserAgent()
	config.ContentType = runtime.ContentTypeProtobuf

	config.APIPath = "/api"
	config.GroupVersion = &corev1.SchemeGroupVersion
	clients.coreClient, err = rest.RESTClientFor(config)
	if err != nil {
		return k8sClients{}, fmt.Errorf("cannot create core REST client: %w", err)
	}

	config.APIPath = "/apis"
	config.GroupVersion = &oobv1alpha1.GroupVersion
	clients.oobClient, err = rest.RESTClientFor(config)
	if err != nil {
		return k8sClients{}, fmt.Errorf("cannot create OOB REST client: %w", err)
	}

	return clients, nil
}

func getConsoleSpec(ctx context.Context, clients k8sClients, namespace, name string) (consoleSpec, error) {
	log.Debug(ctx, "Getting OOB")
	var oob oobv1alpha1.OOB
	err := clients.oobClient.Get().NamespaceIfScoped(namespace, namespace != "").Resource("oobs").Name(name).Do(ctx).Into(&oob)
	if err != nil {
		return consoleSpec{}, fmt.Errorf("cannot get OOB: %w", err)
	}
	if !oob.DeletionTimestamp.IsZero() {
		return consoleSpec{}, fmt.Errorf("OOB is being deleted")
	}

	if oob.Status.IP == "" {
		return consoleSpec{}, fmt.Errorf("OOB has no IP address")
	}
	if oob.Status.Mac == "" {
		return consoleSpec{}, fmt.Errorf("OOB has no MAC address")
	}
	cons := false
	for _, c := range oob.Status.Capabilities {
		if c == "console" {
			cons = true
		}
	}
	if !cons {
		return consoleSpec{}, fmt.Errorf("OOB has no console capability")
	}
	if oob.Status.Console == "" {
		return consoleSpec{}, fmt.Errorf("OOB had no console type")
	}

	log.Debug(ctx, "Getting secret")
	var secret corev1.Secret
	err = clients.coreClient.Get().NamespaceIfScoped(namespace, namespace != "").Resource("secrets").Name(oob.Status.Mac).Do(ctx).Into(&secret)
	if err != nil {
		return consoleSpec{}, fmt.Errorf("cannot get secret: %w", err)
	}

	if secret.Type != "kubernetes.io/basic-auth" {
		return consoleSpec{}, fmt.Errorf("secret has incorrect type: %s", secret.Type)
	}

	mac, _ := secret.Data["mac"]
	if string(mac) != oob.Status.Mac {
		return consoleSpec{}, fmt.Errorf("secret has incorrect MAC address")
	}

	user, ok := secret.Data["username"]
	if !ok {
		return consoleSpec{}, fmt.Errorf("secret has no username")
	}

	var passwd []byte
	passwd, ok = secret.Data["password"]
	if !ok {
		return consoleSpec{}, fmt.Errorf("secret has no password")
	}

	return consoleSpec{
		typ:      oob.Status.Console,
		user:     string(user),
		password: string(passwd),
		host:     oob.Status.IP,
	}, nil
}
