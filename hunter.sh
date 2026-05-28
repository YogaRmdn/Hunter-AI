#!/bin/bash
cd "$(dirname "$0")"

# Auto-setup venv kalo belum ada
if [ ! -f ".venv/bin/python3" ]; then
    echo "📦 Setup virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install -q openai anthropic google-generativeai requests dnspython colorama
    echo "✅ Selesai!"
fi

exec .venv/bin/python3 hunter.py "$@"
