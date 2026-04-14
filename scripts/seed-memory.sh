#!/bin/bash
# Seed memory from all existing Claude Code sessions.
# Parses sessions → extracts observations → saves to ~/.nexus

export PATH="/home/hawon/.local/share/fnm:$PATH"
eval "$(fnm env)" 2>/dev/null
fnm use lts-latest 2>/dev/null

node --import tsx -e "
import { discoverSessions } from '/home/hawon/claude-vault/src/parser/discover.js';
import { parseSession } from '/home/hawon/claude-vault/src/parser/parse.js';
import { createNexusMemory } from '/home/hawon/claude-vault/src/memory-engine/nexus-memory.js';
import { join } from 'path';

const dataDir = join(process.env.HOME, '.nexus');
const mem = createNexusMemory(dataDir);

const discovery = discoverSessions();
let totalSessions = 0;
let totalObs = 0;

for (const proj of discovery.projects) {
  for (const sp of proj.sessions) {
    totalSessions++;
    try {
      const session = parseSession(sp);
      // Extract user+assistant text
      const texts = [];
      for (const msg of session.messages) {
        if (msg.role === 'user' && typeof msg.content === 'string' && msg.content.length > 30) {
          texts.push(msg.content.slice(0, 500));
        }
        if (msg.role === 'assistant' && typeof msg.content === 'string' && msg.content.length > 50) {
          texts.push(msg.content.slice(0, 500));
        }
      }
      if (texts.length < 2) continue;

      // Ingest combined text per session
      const combined = texts.join('. ');
      const domain = (proj.projectId ?? 'general').replace(/[^a-z0-9-]/gi, '-').slice(0, 30);
      const added = mem.ingest(combined, domain, session.sessionId);
      totalObs += added;
      if (added > 0) process.stdout.write('.');
    } catch { /* skip */ }
  }
}

mem.save();
console.log();
console.log('Sessions processed:', totalSessions);
console.log('Observations created:', totalObs);
console.log('Saved to:', dataDir);
" 2>&1
