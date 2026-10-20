import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";

/**
 * Run a program with an argv array. No shell is involved, so user-influenced
 * values are always passed as discrete arguments and can never be interpreted
 * as shell syntax (`;`, `$(...)`, backticks, pipes, redirects).
 */
export const execFileAsync = promisify(execFileCb);
