#!/bin/bash

# ALCUB3 MCP Server Test Script
# Tests all configured MCP servers for ALCUB3 development

echo "🔧 ALCUB3 MCP Server Configuration Test"
echo "========================================"

echo ""
echo "📋 Current MCP Configuration:"
claude mcp list

echo ""
echo "🧪 Testing Individual MCP Servers:"
echo ""

# Test Filesystem MCP Server
echo "1. Testing Filesystem MCP Server..."
claude mcp get filesystem && echo "✅ Filesystem server configured correctly" || echo "❌ Filesystem server configuration issue"

echo ""

# Test Brave Search MCP Server  
echo "2. Testing Brave Search MCP Server..."
claude mcp get brave-search && echo "✅ Brave Search server configured correctly" || echo "❌ Brave Search server configuration issue"

echo ""

# Test Context7 MCP Server
echo "3. Testing Context7 MCP Server..."
claude mcp get context7 && echo "✅ Context7 server configured correctly" || echo "❌ Context7 server configuration issue"

echo ""

# Test Notion MCP Server
echo "4. Testing Notion MCP Server..."
claude mcp get notion && echo "✅ Notion server configured correctly" || echo "❌ Notion server configuration issue"

echo ""

# Test Supermemory Integration
echo "5. Testing Supermemory Integration..."
claude mcp get supermemory && echo "✅ Supermemory integration configured correctly" || echo "❌ Supermemory integration configuration issue"

echo ""
echo "🔒 Security Configuration Check:"
echo ""

# Check filesystem permissions
echo "Checking filesystem access permissions..."
if [ -d "/Users/aaronkiyaani-mcclary/Dev IDE Projects/alcub3-cli/" ]; then
    echo "✅ ALCUB3 project directory accessible"
else
    echo "❌ ALCUB3 project directory not found"
fi

if [ -d "/Users/aaronkiyaani-mcclary/secure/data/" ]; then
    echo "✅ Secure data directory accessible"
else
    echo "⚠️  Secure data directory not found (will be created as needed)"
    mkdir -p "/Users/aaronkiyaani-mcclary/secure/data/"
fi

echo ""
echo "🎯 MCP Server Executables Check:"
echo ""

# Check if MCP server executables exist
echo "Checking MCP server files..."

if [ -f "/Users/aaronkiyaani-mcclary/Dev/alcub3-mcp-servers/mcp-official-servers/src/filesystem/dist/index.js" ]; then
    echo "✅ Filesystem MCP server executable found"
else
    echo "❌ Filesystem MCP server executable missing"
fi

if [ -f "/Users/aaronkiyaani-mcclary/Dev/alcub3-mcp-servers/brave-search-mcp/dist/index.js" ]; then
    echo "✅ Brave Search MCP server executable found"
else
    echo "❌ Brave Search MCP server executable missing"
fi

# Check global NPM installations
echo ""
echo "Checking global MCP installations..."

if command -v "@upstash/context7-mcp" &> /dev/null || npm list -g "@upstash/context7-mcp" &> /dev/null; then
    echo "✅ Context7 MCP server globally installed"
else
    echo "❌ Context7 MCP server not found globally"
fi

if command -v "@notionhq/notion-mcp-server" &> /dev/null || npm list -g "@notionhq/notion-mcp-server" &> /dev/null; then
    echo "✅ Notion MCP server globally installed"
else
    echo "❌ Notion MCP server not found globally"
fi

echo ""
echo "📊 Configuration Summary:"
echo "========================"

# Count configured servers
server_count=$(claude mcp list | wc -l)
echo "Total MCP servers configured: $server_count"

echo ""
echo "🚀 Ready for ALCUB3 Development with MCP Acceleration!"
echo ""
echo "Next steps:"
echo "1. Start a new Claude Code session to test MCP tools"
echo "2. Use MCP tools for daily development workflow"
echo "3. Monitor development acceleration metrics"
echo ""
echo "For usage examples, see: docs/ALCUB3_MCP_SETUP.md"