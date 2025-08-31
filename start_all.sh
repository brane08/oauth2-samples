#!/bin/bash

# Exit on errors
set -e

# Start SSO server
echo "Starting SSO Server on port 5000..."
python3 server.py &
SSO_PID=$!
echo "SSO Server PID: $SSO_PID"

# Start Client app
echo "Starting Client App on port 6000..."
python3 client.py &
CLIENT_PID=$!
echo "Client App PID: $CLIENT_PID"

# Function to stop both processes
cleanup() {
    echo ""
    echo "Stopping apps..."
    kill $SSO_PID $CLIENT_PID 2>/dev/null
    wait $SSO_PID $CLIENT_PID 2>/dev/null
    echo "Stopped."
    exit 0
}

# Trap Ctrl+C
trap cleanup SIGINT

# Keep script alive until killed
wait
