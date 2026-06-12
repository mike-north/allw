#!/usr/bin/env node
/**
 * `allw-approver` CLI — the v0 stand-in approver entrypoint.
 *
 * Commands:
 *   pair    Pair this approver with an account on the relay (mints a device cert).
 *   watch   Open the device presence socket and approve/deny incoming requests (alias: serve).
 *   keygen  Generate a fresh local keyfile without pairing.
 *
 * All cryptography is delegated to the WASM core (`docs/architecture.md` — WASM-local hard
 * constraint). ⚠ v0 stand-in: device keys are software-held (see README / issue #23).
 */

import { parseArgs } from "node:util";

import { runKeygen } from "./commands/keygen.js";
import { runPair } from "./commands/pair.js";
import { createReadlinePrompter, runWatch, type WebSocketLike } from "./commands/watch.js";
import { defaultKeyfilePath } from "./lib/paths.js";
import { loadWasm } from "./lib/wasm.js";

const USAGE = `allw-approver — minimal stand-in approver (v0; software-held keys)

USAGE:
  allw-approver <command> [options]

COMMANDS:
  pair      Pair this approver with an account via the relay (registers the device key, mints a
            device certificate, prints the account-root trust anchor).
  watch     Open the device presence WebSocket and approve/deny requests as they arrive.
            Alias: serve.
  keygen    Generate a fresh local keyfile (three software-held seeds) without pairing.
  help      Show this help.

COMMON OPTIONS:
  --keyfile <path>   Keyfile location (default: ~/.allw/approver-keyfile.json)
  -h, --help         Show help.

pair OPTIONS:
  --relay <url>      Relay base URL (required), e.g. https://relay.example.com
  --account <id>     Account id to pair with (required).
  --label <name>     Human label for this device (optional).
  --code <code>      Use an existing pairing code (account owner ran /pairing/start). If omitted,
                     the CLI drives /pairing/start itself.
  --pairing-token <token>
                     Bearer token returned with an existing pairing code.

watch OPTIONS:
  --relay <url>      Override the paired relay URL (defaults to the keyfile's relay_url).

keygen OPTIONS:
  --force            Overwrite an existing keyfile (orphans the current device's seeds).

⚠ v0 stand-in: device keys are held in software in the keyfile. Production custody is hardware-
  backed (Secure Enclave / StrongBox) — see issue #23. The wire protocol is unchanged either way.
`;

/** Print usage and exit with the given code. */
function printUsageAndExit(code: number): never {
  (code === 0 ? console.log : console.error)(USAGE);
  process.exit(code);
}

/** Require a string option, exiting with a clear message if it is missing. */
function requireOption(value: string | undefined, flag: string): string {
  if (value === undefined || value.length === 0) {
    console.error(`error: ${flag} is required\n`);
    printUsageAndExit(1);
  }
  return value;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    printUsageAndExit(command === undefined ? 1 : 0);
  }

  const { values } = parseArgs({
    args: argv.slice(1),
    options: {
      keyfile: { type: "string" },
      relay: { type: "string" },
      account: { type: "string" },
      label: { type: "string" },
      code: { type: "string" },
      "pairing-token": { type: "string" },
      force: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
    allowPositionals: false,
  });

  if (values.help) printUsageAndExit(0);

  const keyfilePath = values.keyfile ?? defaultKeyfilePath();
  const wasm = await loadWasm();

  switch (command) {
    case "keygen": {
      runKeygen(wasm, { keyfilePath, force: values.force });
      return;
    }
    case "pair": {
      const relayUrl = requireOption(values.relay, "--relay");
      const accountId = requireOption(values.account, "--account");
      await runPair(wasm, {
        relayUrl,
        accountId,
        keyfilePath,
        ...(values.label !== undefined ? { label: values.label } : {}),
        ...(values.code !== undefined ? { code: values.code } : {}),
        ...(values["pairing-token"] !== undefined
          ? { pairingAuthToken: values["pairing-token"] }
          : {}),
      });
      return;
    }
    case "watch":
    case "serve": {
      await runWatch(
        wasm,
        {
          keyfilePath,
          ...(values.relay !== undefined ? { relayUrl: values.relay } : {}),
        },
        {
          // Node 24 ships a global WebSocket; it satisfies our structural WebSocketLike surface.
          connect: (url: string): WebSocketLike => new WebSocket(url),
          prompter: createReadlinePrompter(),
        },
      );
      return;
    }
    default: {
      console.error(`error: unknown command '${command}'\n`);
      printUsageAndExit(1);
    }
  }
}

main().catch((err: unknown) => {
  console.error(`allw-approver: ${(err as Error).message}`);
  process.exit(1);
});
