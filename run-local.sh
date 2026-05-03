#!/bin/bash

echo "🚀 GITHUBRECON - Local Setup"
echo "======================================"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo ""
    echo "Please create .env with your GitHub token:"
    echo "cp .env.example .env"
    echo "Then edit .env and add your token"
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Error: Node.js is not installed"
    echo "Please install from https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js version: $(node --version)"
echo ""

# Install dependencies if needed
if [ ! -d "backend/node_modules" ] || [ ! -d "frontend/node_modules" ]; then
    echo "📦 Installing dependencies..."
    cd backend && npm install && cd ..
    cd frontend && npm install && cd ..
fi

# Setup database
echo "🗄️  Setting up SQLite database..."
cd backend
npx prisma generate > /dev/null 2>&1
DATABASE_URL="file:./dev.db" npx prisma db push --accept-data-loss > /dev/null 2>&1
cd ..

echo ""
echo "✅ Setup complete!"
echo ""
echo "Starting application..."
echo "  Backend:  http://localhost:3001/api/health"
echo "  Frontend: http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start both servers
npx concurrently -n "backend,frontend" -c "blue,green" \
  "cd backend && NODE_ENV=development PORT=3001 DATABASE_URL=file:./dev.db npm run dev --silent" \
  "cd frontend && npm run dev --silent"
