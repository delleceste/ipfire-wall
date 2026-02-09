#!/bin/bash
# cleanup-test-env.sh

echo "Cleaning up netns test environment..."

# Delete namespaces (this also removes all interfaces inside them)
ip netns del hostA 2>/dev/null || true
ip netns del hostB 2>/dev/null || true
ip netns del hostC 2>/dev/null || true

echo "Cleanup complete!"

