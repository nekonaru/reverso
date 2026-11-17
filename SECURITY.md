# Security policy

## Scope

Reverso is a local command line tool. It does not run a service, open a
listener or execute the files it analyzes. Analysis is static: nothing you
point it at is loaded or run.

## Supported versions

The latest release on the `main` branch. There is no backport policy yet.

## Reporting a vulnerability

Use GitHub private vulnerability reporting:

1. Open the repository on GitHub.
2. Go to the Security tab.
3. Click "Report a vulnerability".

Include what you found, how to reproduce it, and what you think the impact is.
You will get an acknowledgement within a few days. Please do not disclose the
issue publicly until a fix is released.

## Handling of analyzed files

Analyzed files are never written outside the output directory you choose, the
mirror refuses private network addresses by default, and all input sizes are
capped. If you believe one of these guarantees is broken, report it as above.
