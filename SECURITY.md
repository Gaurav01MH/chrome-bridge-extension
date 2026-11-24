# Security Policy

## Scope

This repository contains only the ChromeBridge Manifest V3 browser extension. The companion local Node.js service and desktop controller are maintained separately.

## Reporting a vulnerability

Please do not publish pairing secrets, private URLs, browser data, screenshots containing personal information, or working exploit details in a public issue. Use GitHub's private vulnerability reporting feature if it is enabled for this repository. Otherwise, contact the repository owner through a private channel before public disclosure.

## Security design

- The extension connects only to the fixed local WebSocket endpoint `ws://127.0.0.1:8765/bridge`.
- Pairing uses challenge-response HMAC-SHA-256. The shared secret is not sent over the WebSocket.
- The extension stores the pairing secret in Chrome extension local storage.
- Host permissions are optional and granted per origin.
- The extension accepts a fixed set of commands and does not execute arbitrary JavaScript supplied by the terminal.
- Click targets are inspected and revalidated immediately before supported actions.
- Generic form submission is not supported.
- Page text is treated as untrusted data.
- Logs and public reports must not contain pairing secrets or private page content.

## High-impact permission

The `debugger` permission is required for CDP mouse input and causes Chrome to display a prominent warning. It can grant broad access to a tab's debugging interface. Install this extension only when you trust the local companion service and have reviewed the source.

## Limitations

This is not a security boundary against malware or another process running as the same Windows user. A compromised local machine or companion service may be able to interfere with the browser session.

[executed on device: LAPTOP-G72PTQJ6 (2b3fcac6-b6bc-499c-b844-33cea8460bff)]