# Copilot Instructions for Inspektor Gadget

This document provides comprehensive guidance for AI assistants working with the Inspektor Gadget project. It covers the project's architecture, development workflows, and best practices to help you contribute effectively.

## Project Overview

**Inspektor Gadget** is a collection of tools and framework for data collection and system inspection on Kubernetes clusters and Linux hosts using eBPF (Extended Berkeley Packet Filter). The project enables users to build, package, deploy, and execute eBPF programs encapsulated in OCI images called "Gadgets".

### Core Mission
- Provide easy-to-use eBPF-based observability tools for containers and Kubernetes
- Enable automatic enrichment of kernel data with high-level concepts (pods, containers, etc.)
- Offer multiple deployment modes: CLI tools, Kubernetes operators, and embeddable libraries
- Maintain a secure and extensible framework for custom gadget development

### Key Components

1. **`ig`** - Standalone CLI tool for Linux hosts
2. **`kubectl-gadget`** - Kubernetes plugin for cluster-wide gadget execution
3. **`gadgetctl`** - Remote control tool for managing `ig` daemon instances
4. **Gadgets** - eBPF programs packaged as OCI images with metadata and optional WASM post-processors
5. **Operators** - Framework components that handle fetching, loading, enrichment, filtering, and export

## Architecture and Core Concepts

### What is a Gadget?
A Gadget is an OCI image containing:
- One or more eBPF programs
- Metadata YAML file describing the gadget
- Optional WebAssembly modules for post-processing
- Optional documentation and examples

Gadgets are built using `ig image build` and can be stored in any OCI-compliant registry.

### What is Enrichment?
Enrichment is the process of augmenting raw eBPF data with high-level context:
- **Kernel → User-space**: Map PIDs, mount namespaces → Kubernetes pods, container names
- **User-space → Kernel**: Allow filtering by pod names, automatically translate to kernel primitives
- **Bidirectional**: Enable high-performance in-kernel filtering using high-level concepts

### What is an Operator?
Operators are framework components where actions are taken:
- **Under-the-hood operators**: Gadget fetching, loading, eBPF program management
- **User-exposed operators**: Enrichment, filtering, export, formatting
- **Configurable**: Can be reordered, overridden, and customized

### Target Environments
- **Kubernetes clusters**: Via `kubectl-gadget` plugin or operator deployment
- **Linux hosts**: Via `ig` CLI tool (standalone or containerized)
- **Remote systems**: Via `gadgetctl` connecting to `ig` daemon
- **Embedded**: As Go library in custom applications

## Project Structure

```
inspektor-gadget/
├── cmd/                          # CLI tools and main executables
│   ├── ig/                       # ig CLI tool source
│   ├── kubectl-gadget/           # kubectl plugin source
│   ├── gadgetctl/                # Remote control tool
│   └── common/                   # Shared CLI utilities
├── pkg/                          # Core Go packages and libraries
│   ├── gadgets/                  # Core gadget implementations
│   ├── operators/                # Framework operators
│   ├── runtime/                  # Runtime environments (local, k8s)
│   ├── netnsenter/               # Network namespace utilities
│   └── container-utils/          # Container runtime integration
├── gadgets/                      # Built-in gadget collection (30+ gadgets)
│   ├── trace_open/               # File open tracing
│   ├── trace_exec/               # Process execution tracing
│   ├── snapshot_process/         # Process snapshots
│   └── ...                      # Many more gadgets
├── docs/                         # Documentation
│   ├── reference/                # API and tool reference
│   ├── gadget-devel/             # Gadget development guides
│   ├── devel/                    # Project development docs
│   └── guides/                   # User guides and tutorials
├── examples/                     # Code examples for Go library usage
├── integration/                  # Integration tests
├── internal/                     # Internal packages
├── tools/                        # Development and build tools
├── wasmapi/                      # WebAssembly API definitions
├── include/                      # C headers for gadget development
└── charts/                       # Helm charts for Kubernetes deployment
```

## Development Environment Setup

### Prerequisites
- **Go 1.24+** - Primary development language
- **Docker** + **Docker Buildx** - For container builds and eBPF compilation
- **qemu-user-static** - For cross-platform container builds
- **Linux kernel 5.10+** with BTF enabled - For eBPF functionality
- **clang/llvm** - For eBPF compilation (via Docker)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/inspektor-gadget/inspektor-gadget.git
cd inspektor-gadget

# Install dependencies
go mod download

# Build core components
make ig                    # Build ig CLI
make kubectl-gadget        # Build kubectl plugin
make gadget-container      # Build container image

# Run tests
make test                  # Unit tests
make lint                  # Code linting
```

### Development with Minikube
```bash
# Start minikube with proper configuration
make minikube-start

# Build and deploy to minikube
make minikube-deploy

# Run integration tests
make integration-tests
```

## Build System and Common Tasks

### Make Targets Overview
```bash
# Building
make all                   # Build all marked targets
make ig                    # Build ig CLI
make kubectl-gadget        # Build kubectl plugin
make gadget-container      # Build container image
make build-gadgets         # Build all built-in gadgets

# Testing
make test                  # Unit tests
make integration-tests     # Integration tests (requires cluster)
make lint                  # Code linting and formatting

# Development
make minikube-deploy       # Deploy to minikube for testing
make clang-format          # Format eBPF C code
make generate-manifests    # Generate Kubernetes manifests

# Installation
make install/ig            # Install ig to /usr/local/bin
make install/kubectl-gadget # Install kubectl plugin to ~/.local/bin
```

### Cross-Platform Builds
```bash
# Build for all supported architectures
make ig-all
make kubectl-gadget-all
make cross-gadget-container

# Build for specific architecture
make ig-linux-amd64
make ig-darwin-arm64
```

## Code Organization and Patterns

### Package Hierarchy
- **`cmd/`** - CLI entry points, cobra command definitions
- **`pkg/gadgets/`** - Individual gadget implementations
- **`pkg/operators/`** - Framework operators (enrichment, filtering, export)
- **`pkg/runtime/`** - Runtime environments (local, Kubernetes)
- **`pkg/container-utils/`** - Container runtime abstractions
- **`internal/`** - Internal packages not for external use

### Key Interfaces
```go
// Gadget interface
type Gadget interface {
    Run(context.Context, *Runtime) error
    Stop() error
    GetDefinition() *GadgetDefinition
}

// Operator interface  
type Operator interface {
    Name() string
    Init(*OperatorConfig) error
    Process(*Event) error
}

// Runtime interface
type Runtime interface {
    RunGadget(context.Context, Gadget) error
    GetContainers() ([]*Container, error)
}
```

### Common Patterns

#### Gadget Implementation Structure
```go
// tracer.go - Main gadget logic
type Tracer struct {
    config     *Config
    enricher   *Enricher
    eventChan  chan Event
}

func (t *Tracer) Run(ctx context.Context) error {
    // Load eBPF program
    // Setup enrichment
    // Start event processing
    // Handle context cancellation
}

// types.go - Event definitions
type Event struct {
    Timestamp  time.Time
    Pid        uint32
    Comm       string
    // ... other fields
    
    // Enriched fields
    Container *Container `json:",omitempty"`
    Pod       *Pod       `json:",omitempty"`
}

// config.go - Configuration
type Config struct {
    Filter    string
    Output    string
    Follow    bool
    // ... other options
}
```

#### Error Handling
```go
// Use structured errors with context
return fmt.Errorf("loading eBPF program: %w", err)

// Use consistent error messages
if err := validateConfig(config); err != nil {
    return fmt.Errorf("invalid configuration: %w", err)
}
```

#### Logging
```go
// Use structured logging with logrus
log.WithFields(logrus.Fields{
    "gadget": "trace_open",
    "pid":    event.Pid,
}).Info("processing event")
```

## Development Workflows

### Adding a New Gadget

1. **Create gadget directory structure**:
```bash
mkdir -p gadgets/trace_newgadget
cd gadgets/trace_newgadget
```

2. **Implement core files**:
   - `program.bpf.c` - eBPF program
   - `tracer.go` - Go tracer implementation
   - `types.go` - Event structures
   - `gadget.yaml` - Metadata and configuration
   - `README.md` - Documentation

3. **Build and test**:
```bash
make build-gadgets
ig run trace_newgadget:latest --help
```

### Modifying Existing Gadgets

1. **Locate gadget directory**: `gadgets/trace_<name>/`
2. **Modify relevant files**:
   - eBPF program: `program.bpf.c`
   - Go logic: `tracer.go`
   - Event structure: `types.go`
3. **Rebuild**: `make build-gadgets`
4. **Test changes**: Run integration tests for the specific gadget

### Adding Framework Features

1. **Identify component type**:
   - Operator: `pkg/operators/`
   - Runtime feature: `pkg/runtime/`
   - Enrichment: `pkg/container-utils/`

2. **Implement interfaces**:
   - Follow existing patterns
   - Add comprehensive tests
   - Update documentation

3. **Integration testing**:
```bash
make test                    # Unit tests
make integration-tests       # Full integration
```

### Working with eBPF Code

#### eBPF Development Guidelines
- Use BPF CO-RE (Compile Once, Run Everywhere) patterns
- Include proper BTF type information
- Handle kernel version compatibility
- Use helper functions appropriately
- Follow kernel coding style for C code

#### Debugging eBPF Programs
```bash
# Enable eBPF debug output
ig run trace_open:latest --log-level=debug

# Use bpftool for program inspection
bpftool prog list
bpftool map list

# Check verifier logs
ig run trace_open:latest --log-level=trace
```

## Testing Strategy

### Unit Tests
```bash
# Run all unit tests
make test

# Run specific package tests
go test ./pkg/gadgets/trace_open/...

# Run with coverage
go test -cover ./...
```

### Integration Tests
```bash
# Kubernetes integration tests (requires cluster)
make integration-tests

# Non-Kubernetes integration tests
make -C integration/ig/non-k8s test-docker

# Gadget-specific tests
make integration-test-gadgets
```

### Benchmarking
```bash
# Run performance benchmarks
make gadgets-benchmarks

# Specific benchmark
go test -exec sudo -bench='BenchmarkAllGadgetsWithContainers' ./internal/benchmarks/...
```

## Security Considerations

### eBPF Security
- All eBPF programs are verified by the kernel
- Use minimal required capabilities
- Avoid reading sensitive data unnecessarily
- Implement proper bounds checking

### Container Security
- Use distroless base images where possible
- Run with minimal privileges
- Implement proper RBAC for Kubernetes deployments
- Validate all user inputs

### Gadget Verification
```bash
# Verify gadget signatures
ig run --verify trace_open:latest

# Check gadget metadata
ig image inspect trace_open:latest
```

### Supply Chain Security
- All releases are signed with Sigstore
- SBOMs (Software Bill of Materials) are generated
- Container images are scanned for vulnerabilities
- Dependencies are regularly updated

## Common Issues and Troubleshooting

### Build Issues

**Problem**: eBPF compilation fails
```bash
# Solution: Ensure proper Docker setup
docker run --rm -it --privileged ubuntu:22.04 uname -r
make ebpf-objects
```

**Problem**: Cross-compilation fails
```bash
# Solution: Install qemu-user-static
sudo apt-get install qemu-user-static
make cross-gadget-container
```

### Runtime Issues

**Problem**: eBPF program load fails
```bash
# Check kernel compatibility
uname -r
cat /proc/version

# Verify BTF availability
ls /sys/kernel/btf/vmlinux

# Check capabilities
ig run trace_open:latest --log-level=debug
```

**Problem**: Container enrichment not working
```bash
# Verify container runtime socket
ls -la /var/run/docker.sock
ls -la /var/run/containerd/containerd.sock

# Check permissions
groups $USER | grep docker
```

### Kubernetes Issues

**Problem**: kubectl-gadget not working
```bash
# Verify plugin installation
kubectl gadget version

# Check deployment status
kubectl get pods -n gadget

# View operator logs
kubectl logs -n gadget -l app=gadget
```

**Problem**: RBAC issues
```bash
# Check service account permissions
kubectl auth can-i create pods --as=system:serviceaccount:gadget:gadget

# Verify cluster role binding
kubectl get clusterrolebinding | grep gadget
```

## Performance Considerations

### eBPF Performance
- Use maps efficiently (avoid unnecessary lookups)
- Minimize per-event processing in eBPF
- Use ring buffers for high-frequency events
- Implement proper sampling for high-volume scenarios

### Go Performance
- Use object pooling for frequently allocated structures
- Implement backpressure for event processing
- Use efficient serialization (avoid reflection where possible)
- Profile memory usage with pprof

### Container Overhead
- Minimize container image size
- Use multi-stage builds
- Implement resource limits
- Monitor CPU and memory usage

## Integration Points

### Container Runtimes
- **Docker**: Socket communication via `/var/run/docker.sock`
- **containerd**: GRPC API via `/var/run/containerd/containerd.sock`
- **CRI-O**: Socket communication via `/var/run/crio/crio.sock`

### Kubernetes Integration
- **Custom Resource Definitions**: For gadget configuration
- **DaemonSet**: For cluster-wide gadget execution
- **Operator Pattern**: For lifecycle management
- **RBAC**: For security and access control

### Observability Integration
- **Prometheus**: Metrics export via prometheus operator
- **OpenTelemetry**: Tracing and metrics
- **JSON/CSV**: Structured data export
- **Custom exporters**: Via operator framework

## Contributing Guidelines

### Code Style
- Follow Go conventions and use `gofmt`
- Use meaningful variable and function names
- Add comprehensive documentation for public APIs
- Write tests for all new functionality

### Commit Guidelines
- Use conventional commit format
- Include area prefix (e.g., "gadgets/trace_open:", "operators/ebpf:")
- Sign off all commits (`git commit -s`)
- Keep commits atomic and focused

### Pull Request Process
1. Fork repository and create feature branch
2. Implement changes with tests
3. Run linting and tests locally
4. Update documentation if needed
5. Submit PR with clear description
6. Address review feedback
7. Ensure CI passes

### Documentation Updates
- Update relevant documentation for user-facing changes
- Add examples for new features
- Update godoc comments for API changes
- Consider adding blog posts for major features

## Advanced Topics

### WebAssembly Integration
- WASM modules for post-processing events
- Custom operators written in any WASM-supported language
- Performance considerations for WASM vs native Go

### Custom Runtime Development
- Implementing the Runtime interface
- Integration with other container platforms
- Supporting different eBPF loading mechanisms

### Gadget Packaging
- OCI image structure and conventions
- Metadata schema and validation
- Artifact publishing and distribution

### Operator Development
- Creating custom operators
- Operator configuration and lifecycle
- Integration with existing operator chain

---

This document should serve as a comprehensive guide for understanding and contributing to the Inspektor Gadget project. For the most up-to-date information, always refer to the official documentation at https://www.inspektor-gadget.io/docs/latest/