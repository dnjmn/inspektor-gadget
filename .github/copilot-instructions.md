# Copilot Instructions for Inspektor Gadget

## Overview

Inspektor Gadget is an eBPF-based observability framework that packages eBPF programs into OCI images called "Gadgets" and provides mechanisms to run them on Kubernetes clusters and Linux hosts. The project follows a sophisticated operator-based architecture where functionality is modularized into composable components.

## Architecture and Core Concepts

### The Three-Layer Gadget Architecture
1. **eBPF Layer**: Contains compiled eBPF programs (.o files) with BTF metadata
2. **WebAssembly Layer** (optional): Post-processing logic for data transformation
3. **Metadata Layer**: Gadget configuration, parameters, and annotations

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

## Essential Development Patterns

### Gadget Context Lifecycle
```go
// Standard gadget execution pattern
gadgetCtx := gadgetcontext.New(context.Background(), "trace_exec:latest",
    gadgetcontext.WithDataOperators(operators...))
runtime := local.New()
runtime.RunGadget(gadgetCtx, nil, paramValues)
```

**Operator Execution Order**: PreStart → Start → (running) → Stop → PostStop → Close
- Operations execute in priority order (lower numbers first)
- Close always runs in reverse order even if earlier operations fail

### eBPF Program Structure
All gadgets follow this pattern in their `.bpf.c` files:
```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>

struct event {
    gadget_timestamp timestamp_raw;
    struct gadget_process proc;
    // gadget-specific fields
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(name, events, event);

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct syscall_trace_enter *ctx) {
    struct event *event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) return 0;
    
    gadget_process_populate(&event->proc);
    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### Gadget Metadata (gadget.yaml)
Essential configuration file that defines gadget behavior:
```yaml
apiVersion: core.gadget.kinvolk.io/v1alpha1
kind: Gadget
metadata:
  name: my_gadget
  description: "Track system calls"
spec:
  datasources:
    events:
      fields:
        timestamp:
          annotations:
            columns.width: "30"
        comm:
          annotations:
            columns.width: "16"
        pid:
          annotations:
            columns.width: "8"
            columns.alignment: "right"
```

### Container Collection and Enrichment
Critical for understanding how gadgets track containers:
- **localmanager**: Tracks containers on local Linux systems
- **kubemanager**: Tracks containers in Kubernetes environments
- **MountNsFilterMap**: Key mechanism for filtering events by container
- **Container enrichment**: Automatically adds container metadata to events

## Gadget Development Process

### Creating a New Gadget
1. **Create gadget directory**: `mkdir gadgets/my_gadget && cd gadgets/my_gadget`
2. **Essential files needed**:
   - `program.bpf.c` - eBPF program
   - `gadget.yaml` - Metadata and configuration
   - `README.md` - Documentation
   - Optional: `test/` directory for tests

### Gadget Structure Template
```yaml
# gadget.yaml
apiVersion: core.gadget.kinvolk.io/v1alpha1
kind: Gadget
metadata:
  name: my_gadget
  description: "Description of what the gadget does"
spec:
  datasources:
    my_events:
      fields:
        timestamp:
          type: datetime
        pid:
          type: uint32
```

### Building and Testing Gadgets

#### Local Development Workflow
```bash
# Build gadget with local repository settings
ig image build . --tag ghcr.io/dnjmn/gadget/my_gadget:latest

# Test locally (requires sudo for eBPF)
sudo ig run ghcr.io/dnjmn/gadget/my_gadget:latest --timeout 10s

# Build and push to your fork's registry
ig image build . --tag ghcr.io/dnjmn/gadget/my_gadget:latest --push

# Sign the image (after pushing)
cosign sign ghcr.io/dnjmn/gadget/my_gadget:latest
```

#### Unit Testing Pattern
```go
// Standard gadget test in test/unit/my_gadget_test.go
func TestMyGadget(t *testing.T) {
    gadgettesting.InitUnitTest(t)
    
    runner := gadgetrunner.NewGadgetRunner[ExpectedEvent](t, 
        gadgetrunner.GadgetRunnerOpts[ExpectedEvent]{
            Image: "my_gadget",
            Timeout: 5 * time.Second,
            OnGadgetRun: func(gadgetCtx operators.GadgetContext) error {
                // Trigger events that the gadget should capture
                return nil
            },
        })
    runner.RunGadget()
    
    // Verify captured events
    require.Len(t, runner.CapturedEvents, expectedCount)
}
```

#### Integration Testing
```bash
# Run integration tests for specific gadget
make -C gadgets/my_gadget test-integration

# Run all gadget tests
make -C gadgets test-all
```

### Repository-Specific Settings

#### Registry Configuration
- **Base registry**: `ghcr.io/dnjmn/gadget/`
- **Image naming**: `ghcr.io/dnjmn/gadget/GADGET_NAME:TAG`
- **Default tag**: Use `latest` for development, semantic versions for releases

#### Image Signing
All gadget images must be signed with cosign:
```bash
# Sign after building and pushing
cosign sign ghcr.io/dnjmn/gadget/my_gadget:latest

# Verify signature
cosign verify ghcr.io/dnjmn/gadget/my_gadget:latest
```

### Build System and Common Tasks

#### Building Individual Gadgets
```bash
# Build with local toolchain (requires clang, headers)
ig image build . --local --tag ghcr.io/dnjmn/gadget/my_gadget:latest

# Build using container (recommended)
ig image build . --tag ghcr.io/dnjmn/gadget/my_gadget:latest

# Build and push to registry
ig image build . --tag ghcr.io/dnjmn/gadget/my_gadget:latest --push
```

#### Building Multiple Gadgets
```bash
# Build all gadgets
make -C gadgets build-all

# Build with custom repository
GADGET_REPOSITORY=ghcr.io/dnjmn/gadget make -C gadgets build-all
```

#### Cross-Platform Builds
```bash
# Build for all supported architectures
make ig-all
make kubectl-gadget-all

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

### DataSource and Event Flow
Events flow: eBPF → DataSource → Operators → Output
- **Tracers**: Single events (like syscalls)
- **Snapshotters**: Arrays of data (like process lists)
- **MapIterators**: Export eBPF map contents

## Important Conventions

### Parameter Naming
- Parameters use `kebab-case` in CLI: `--container-name`
- Internal Go code uses `camelCase`: `containerName`
- eBPF variables use `snake_case`: `container_name`

### Enriched Types Pattern
```c
// Use enriched types for automatic formatting
struct event {
    gadget_timestamp timestamp_raw;  // Automatically formatted as timestamp
    gadget_bytes bytes_raw;          // Automatically formatted with units
    gadget_uid uid_raw;              // Resolved to username
    gadget_mntns_id mntns_id;        // Used for container filtering
};
```

### Gadget Parameters
Define configurable parameters in your eBPF code:
```c
// In program.bpf.c
const volatile bool trace_failed_only = false;
GADGET_PARAM(trace_failed_only);

const volatile int min_duration_ms = 0;
GADGET_PARAM(min_duration_ms);
```

Then expose them in gadget.yaml:
```yaml
spec:
  params:
    - key: trace-failed-only
      description: "Only trace failed system calls"
      defaultValue: "false"
    - key: min-duration-ms
      description: "Minimum duration in milliseconds to trace"
      defaultValue: "0"
```

### Error Handling
- Always wrap errors with context: `fmt.Errorf("operation failed: %w", err)`
- Use structured logging: `logger.Debugf("message: %+v", data)`
- Operator errors should be recoverable where possible

## Testing and Debugging

### Environment Variables
- `IG_DEBUG_LOGS=true` - Enable debug logging
- `IG_VERIFY_IMAGE=false` - Skip image verification in tests
- `NODE_NAME` - Required for Kubernetes deployments

### Common Debug Commands
```bash
# Test gadget locally
sudo ig run trace_exec:latest --timeout 10s

# Test with fork's registry
sudo ig run ghcr.io/dnjmn/gadget/my_gadget:latest --timeout 10s

# Debug eBPF programs
sudo bpftool prog list
sudo bpftool map list

# Container collection debugging
sudo ig run trace_exec:latest --debug

# Verify image signature
cosign verify ghcr.io/dnjmn/gadget/my_gadget:latest
```

### Testing Best Practices
- Always test locally before pushing
- Use `gadgettesting.InitUnitTest(t)` for unit tests
- Include integration tests for complex gadgets
- Test with different container runtimes when applicable
- Verify image signatures after building

### Repository Testing Notes
This is a fork of the original inspektor-gadget repository:
- All testing should be done locally first
- Use `ghcr.io/dnjmn/gadget/` registry for all images
- Images must be signed with cosign after pushing
- Tests should not depend on external registries

### Integration Testing
Tests use `gadgetrunner.GadgetRunner` with standardized patterns:
- Mount namespace filtering via `MntnsFilterMap`
- Event normalization functions for cross-platform compatibility
- Timeout handling and proper cleanup

### Gadget Development Workflow Summary
1. **Create**: `mkdir gadgets/my_gadget && cd gadgets/my_gadget`
2. **Implement**: Write `program.bpf.c` and `gadget.yaml`
3. **Build**: `ig image build . --tag ghcr.io/dnjmn/gadget/my_gadget:latest`
4. **Test**: `sudo ig run ghcr.io/dnjmn/gadget/my_gadget:latest`
5. **Unit Test**: Create tests in `test/unit/` directory
6. **Push**: `ig image build . --tag ghcr.io/dnjmn/gadget/my_gadget:latest --push`
7. **Sign**: `cosign sign ghcr.io/dnjmn/gadget/my_gadget:latest`

## Critical Files for Understanding

- **`pkg/gadget-context/run.go`** - Core operator execution lifecycle
- **`pkg/operators/ebpf/ebpf.go`** - eBPF program loading and management
- **`pkg/container-collection/`** - Container tracking implementation
- **`examples/gadgets/trace_open/main.go`** - Simple gadget usage example
- **`gadgets/trace_exec/program.bpf.c`** - Comprehensive eBPF example

This framework emphasizes composition over inheritance - understand operators and their interactions to be productive with any gadget development or debugging task.
