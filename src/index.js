import * as core from '@actions/core';
import { run } from './main.js';

run().catch(e => core.setFailed(`Cargo Check crashed: ${e && e.stack ? e.stack : e}`));
