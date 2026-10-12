#!/usr/bin/env node
'use strict';

// Runs every test/*.test.js with node's built-in test runner. The explicit file list keeps
// this working on Node 18/20, whose --test flag doesn't expand globs.

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const dir = __dirname;
const files = fs
  .readdirSync(dir)
  .filter((f) => f.endsWith('.test.js'))
  .sort()
  .map((f) => path.join(dir, f));
const res = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' });
process.exit(res.status === null ? 1 : res.status);
