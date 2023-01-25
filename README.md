# oob-operator
[![Go Reference](https://pkg.go.dev/badge/github.com/onmetal/controller-utils.svg)](https://pkg.go.dev/github.com/onmetal/controller-utils)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) 
[![GitHub License](https://img.shields.io/static/v1?label=License&message=Apache-2.0&color=blue&style=flat-square)](LICENSE)



## Overview
The operator is doing a "light" lights out management of the hardware deployed in an onmetal installation.
It is handling the user management, power states, identification and service data collection via/of the 
baseboard management controllers by leveraging different industry standards and protocols (e.g. Redfish/IPMI).   

It is scanning the known IP Addresses/MAC Addresses from the out-of-band network and handling only specific
endpoints that are determined by a filtering mechanism that is preconfigured. The filtering mechanism is used 
to assign/find the preferred protocol and the proper manufacturer default credentials.

## Installation, using and developing 
To find out more, please refer to documentation folder [docs](/docs)

## Contributing

We'd love to get feedback from you. Please report bugs, suggestions or post questions by opening a GitHub issue.

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/) 
which provides a reconcile function responsible for synchronizing resources untile the desired state is reached on the cluster 

### Test It Out

Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
