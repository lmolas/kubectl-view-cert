[![Go Report Card](https://goreportcard.com/badge/github.com/lmolas/kubectl-view-cert)](https://goreportcard.com/report/github.com/lmolas/kubectl-view-cert)
[![github actions](https://github.com/lmolas/kubectl-view-cert/workflows/golangci-lint/badge.svg)](https://github.com/lmolas/kubectl-view-cert/actions?query=workflow%3Agolangci-lint)
[![GitHub release](https://img.shields.io/github/v/release/lmolas/kubectl-view-cert)](https://github.com/lmolas/kubectl-view-cert/releases/latest)
[![License](https://img.shields.io/github/license/lmolas/kubectl-view-cert)](LICENSE)

# kubectl-view-cert

A kubectl plugin to view certificate information stored in secrets.

## Installation

Use [krew](https://krew.sigs.k8s.io/) plugin manager to install:

    kubectl krew install view-cert
    kubectl view-cert --help

## Usage

Output of kubectl view-cert command is json.

kubectl view-cert plugin supports standard kubectl flags.

Some specific flags have been added:

  -A, --all-namespaces                 Query all objects in all API groups, both namespaced and non-namespaced
  
  -E, --expired                        Show only expired certificates

  -D, --expired-days-from-now int      Show expired certificates at date in future (now plus number of days)

  -S, --show-ca                        Show CA certificates

You can search for all certificates information stored in kubernetes.io/tls secrets.

If you use [kubectx](https://github.com/ahmetb/kubectx) and [kubens](https://github.com/ahmetb/kubectx), you do not have to specify the context and the namespace. If you do not use kubectx or kubens, you have to add kubectl namespace and context flags to the command examples described in this documentation.

The following command allows browsing all certificates found in kubernetes.io/tls secrets from current namespace:

    kubectl view-cert 

If you want to browse all namespaces, you can do:

    kubectl view-cert -A

If you want to see only expired certificates in all namespaces:

    kubectl view-cert -A -E

If you want to see all certificates that will expire in 90 days in all namespaces:

    kubectl view-cert -A -D 90

If you want to see all certificates with CA cert information in all namespaces:

    kubectl view-cert -A -S

You can also use view-cert plugin with some arguments to browse a specific secret (secret name is the first argument). The secret will be parsed only if its type is kubernetes.io/tls:

    kubectl view-cert mysecret

If you want to see information from a secret with a different type than kubernetes.io/tls it is possible by specifying a second argument: the secret key to read. The secret key must contain base64 pem encoded data.

    kubectl view-cert mysecret mykey

By using the two argument described above, you can for example browse istio secrets like this:

    kubectl view-cert istio.default cert-chain.pem

As all outputs are json, you can chain response with any [jq](https://github.com/stedolan/jq) command to narrow your search.

## License

Apache 2.0. See [LICENSE](./LICENSE).

---
