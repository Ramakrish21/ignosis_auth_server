# ---------------------------------------------
# Configuration
# ---------------------------------------------

# Base URL of the FastAPI server
BASE_URL="http://127.0.0.1:8000"

# Username used in automated Newman tests
TEST_USERNAME="ignosisscripttest"


# ---------------------------------------------
# Start FastAPI Server
# ---------------------------------------------

echo " Starting FastAPI server in the background..."

# Start the server with uvicorn and run it in the background
# Save its PID so we can stop it later
uvicorn main:app --host 127.0.0.1 --port 8000 &
SERVER_PID=$!

echo " Waiting for server to start (PID: $SERVER_PID)..."
sleep 5


# ---------------------------------------------
# Run Newman Tests
# ---------------------------------------------

echo "🚀 Running Newman test collection..."

# Execute the Newman test collection with environment variables
newman run \
    --env-var baseUrl="$BASE_URL" \
    --env-var username="$TEST_USERNAME" \
    https://raw.githubusercontent.com/UXGorilla/hiring-backend/main/collection.json

# Store Newman exit code (0 = success, non-zero = failure)
NEWMAN_STATUS=$?


# ---------------------------------------------
# Stop FastAPI Server
# ---------------------------------------------

echo " Tests complete. Stopping FastAPI server..."

# Kill the server using the saved PID
kill $SERVER_PID

# Ensure the process is fully terminated
wait $SERVER_PID 2>/dev/null

echo " Server stopped successfully."


# ---------------------------------------------
# Exit with Newman status code
# ---------------------------------------------

# If Newman tests failed, this script will exit with a non-zero code.
# This is important for CI/CD pipelines.
exit $NEWMAN_STATUS
