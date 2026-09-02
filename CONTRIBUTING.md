# Contribution Guide

This is **Achilles**. File bugs and features on [this repo](https://github.com/kineticquant/achilles-harness/issues).

Reporting a problem, reproducing it, sharing domain knowledge, shaping the design, implementing the solution, and verifying the result are all valuable work.

> [!TIP]
> Beyond code, check out [other ways to contribute](#other-ways-to-contribute)

---

## Issue Workflow

Every open issue is tracked on [GitHub Issues](https://github.com/kineticquant/achilles-harness/issues):

- **Inbox**: The issue is waiting for triage.
- **Needs info**: More information is needed before the issue can progress.
- **Accepted / design**: We want to solve the problem and are working out the design, constraints, and verification plan.
- **Ready**: The intended solution is settled and implementation can begin.
- **In progress**: Implementation is underway.
- **Verification**: The implementation is ready for a human to confirm that it works.
- **Done**: The result has been verified and the issue is closed.

Issues we do not plan to pursue are closed with an explanation. We do not use rejection labels.

Feature requests should describe a broadly useful problem rather than only a preferred implementation. Adding features is easy; maintaining them is a long-term cost, so we may decline features that add complexity without enough general benefit.

GitHub Discussions remain useful for informal conversation, but decisions that affect an implementation should be captured in the issue.

## How to Contribute

If you find a bug or want a new feature, [open an issue](https://github.com/kineticquant/achilles-harness/issues/new/choose). A good issue explains the problem, who it affects, and why it matters. For bugs, include clear reproduction steps and a diagnostics report when possible.
Please write the issue yourself. Your agent can do the research and help you explore, but you should understand the issue. You can
suggest a solution direction, but refrain from a detailed solution especially code.

The best place to contribute is the discussion between **Accepted / design** and **Ready**. This is where the engineering happens: turning a worthwhile problem into a specific solution that an agent can implement. Take part in the issue discussion by bringing context and domain knowledge, challenging assumptions, comparing approaches, identifying constraints and trade-offs, and agreeing on how the result will be verified.

Substantial contributors at any stage may be recognized as co-authors. The unit of contribution is taking a problem to a verified solution, not writing the patch.

## From Issue to Pull Request

Do not begin implementation or open a pull request until the intended design is settled on the issue.

Every external pull request must:

- link the Ready issue it implements;
- stay within the design and scope agreed in the issue;
- explain how the issue's verification plan was carried out; and
- return material design changes to the issue for discussion.

Pull requests that do not implement a Ready issue will be closed. Automated dependency and release pull requests, urgent security fixes, and work explicitly directed by the core team are exempt.

Don't open many pull requests in quick succession. Submit them in order of preference and wait for them to land before opening more.

## Agent Loop Migration

We are replacing the legacy agent loop in `crates/goose/src/agents/agent.rs` with the state machine in `crates/goose/src/agents/state_machine/`. The state-machine path is enabled with `GOOSE_STATE_MACHINE=1`.

Until the migration is complete, changes to agent-loop behavior must be implemented and tested in both paths. Pull requests should explain how parity between the two paths was verified.

## AI Code Reviews

We use codex as an AI code reviewer. AI code reviewing has come a long way and more often than not points
out real issues. So we expect you to address all of them by either fixing the code or adding a one-line
answer as to why this is not an issue or not worth fixing.

If not, we might close the PR and/or reply with a link to this section. Once you address the comments, you
can always reopen.

## Quick Responsible AI Tips

There's no need to tell us you used AI in your work. You are contributing to an agent, it would be odd if 
you had not. Our general thinking is, use AI any way you want, but until the robot revolution comes, you
are responsible for the final code. Before submitting a PR for review, make sure you have reviewed it yourself.
We'll close any vibe coded submissions that obviously skip this step.

You can use whatever agent and whatever methodology you like as long as you stick to that principle. We hope
you like Achilles of course and use that. One thing to watch out for is LLM eagerness. They like to please and
are in a hurry. 

   * **Think first**. Agents tend to jump straight to code writing. Explain the architecture you want first to 
      avoid this behavior, based on your own understanding of the code, or have the agent explore the code first and
      suggest approaches. If the first implementation doesn't look quite right, just start over and use
      what you learned to do better next time.
   * **Spot the laziness**. LLMs will make their job easy. They'll write trivial tests, make types wide and
      optional so the compiler doesn't complain, catch exceptions and just log instead of handling errors
      and copy local patterns whether appropriate or not. Push back!
   * **Spot the uncertainty**. As much as the bots declare I see the issue now clearly, they often do not. Call
      them on it, if you see the agent flailing. Another telltale sign is if the agent starts listing the
      number of ways it fixed an issue or starts writing overly defensive code.
   * **Spot the bloat**. Agents like to insert redundant comments or worse, commenting on the change at hand,
     not the resulting code. They create loads of tests that don't really test anything and if they do,
     test the implementation, not the intention. They also like to log anything, just in case.
   
## Prerequisites

Achilles includes Rust binaries (CLI still named `goose`) alongside an Electron app for the GUI.

We use [Hermit][hermit] to manage development dependencies (Rust, Node, pnpm, just, etc.).
Activate Hermit when entering the project:

```bash
source bin/activate-hermit
```

Or add [shell hook auto-activation](https://cashapp.github.io/hermit/usage/shell/#shell-hooks) so Hermit activates automatically when you `cd` into the project (recommended).

We provide a shortcut to standard commands using [just][just] in our `justfile`.

### Windows Subsystem for Linux

For WSL users, you might need to install `build-essential` and `libxcb` otherwise you might run into `cc` linking errors (cc stands for C Compiler).
Install them by running these commands:

```
sudo apt update                   # Refreshes package list (no installs yet)
sudo apt install build-essential  # build-essential is a package that installs all core tools
sudo apt install libxcb1-dev      # libxcb1-dev is the development package for the X C Binding (XCB) library on Linux
```

## Development Setup

### Rust

First let's compile the CLI and try it out.
Hermit manages dependencies — activate it from the repo root:

```
source ./bin/activate-hermit
cargo build
```

When that completes, debug builds of the binaries are available, including the CLI:

```
./target/debug/goose --help
```

For first-time setup, run the configure command:

```
./target/debug/goose configure
```

Once a connection to an LLM provider is working, start a session:

```
./target/debug/goose session
```

These same commands can be recompiled and immediately run using `cargo run -p goose-cli` for iteration.
When making changes to the Rust code, test them on the CLI or run checks, tests, and the linter:

```
cargo check  # verify changes compile
cargo test  # run tests with changes
cargo fmt   # format code
cargo clippy --all-targets -- -D warnings # run the linter
```

### Node

To run the app:

```
just run-ui
```

This command builds a release build of Rust (equivalent to `cargo build -r`) and starts the Electron process.
The app opens a window and displays first-time setup. After completing setup, Achilles is ready for use.

Make GUI changes in `ui/desktop`.

#### Troubleshooting: blank screen on `just run-ui`

If the app opens to a blank window (logs show `Cannot read properties of null (reading 'useRef')`), your `node_modules` is out of date and is loading two copies of React. Delete it and reinstall:

```
rm -rf ui/desktop/node_modules
cd ui && pnpm install
```

See #8757.

### Debugging

To debug the external ACP backend, run it from an IDE. The configuration will depend on the IDE. The command to run is:

```
export GOOSE_SERVER__SECRET_KEY=test
cargo run --package goose-cli --bin goose -- serve --platform desktop --enable-scheduler --host 127.0.0.1 --port 3000
```

The `debug-ui` recipe connects to `http://127.0.0.1:3000` by default. If the
backend uses another port, set `GOOSE_PORT` when starting the UI, or set
`GOOSE_EXTERNAL_BACKEND_URL` to the backend's HTTP base URL.

Once the backend is running, start a UI and connect it to the backend by running:

```
just debug-ui
```

The UI connects to the backend started in the IDE, allowing breakpoints
and stepping through the backend code while interacting with the UI.

## Creating a fork

To fork the repository:

1. Go to https://github.com/kineticquant/achilles-harness and click “Fork” (top-right corner).
2. This creates https://github.com/<your-username>/achilles-harness under your GitHub account.
3. Clone your fork (not the main repo):

```
git clone https://github.com/<your-username>/achilles-harness.git
cd achilles-harness
```

4. Optionally add goose if you need to compare engine changes:

```
git remote add goose https://github.com/aaif-goose/goose.git
```

5. Create a branch in your fork for your changes:

```
git checkout -b my-feature-branch
```

6. Sync your fork with Achilles `main`:

```
git remote add upstream https://github.com/kineticquant/achilles-harness.git
git fetch upstream
git checkout main
git merge upstream/main
```

7. Push to your fork. Because you’re the owner of the fork, you have permission to push here.

```
git push origin my-feature-branch
```

8. Open a Pull Request from your branch on your fork to kineticquant/achilles-harness’s main branch.

## Keeping Your Fork Up-to-Date

To ensure a smooth integration of your contributions, it's important that your fork is kept up-to-date with the main 
repository. This helps avoid conflicts and allows us to merge your pull requests more quickly. Here’s how you can sync your fork:

### Syncing Your Fork with the Main Repository

1. **Add the Main Repository as a Remote** (Skip if you have already set this up):

   ```bash
   git remote add upstream https://github.com/kineticquant/achilles-harness.git
   ```

2. **Fetch the Latest Changes from the Main Repository**:

   ```bash
   git fetch upstream
   ```

3. **Checkout Your Development Branch**:

   ```bash
   git checkout your-branch-name
   ```

4. **Merge Changes from the Main Branch into Your Branch**:

   ```bash
   git merge upstream/main
   ```

   Resolve any conflicts that arise and commit the changes.

5. **Push the Merged Changes to Your Fork**:

   ```bash
   git push origin your-branch-name
   ```

This process will help you keep your branch aligned with the ongoing changes in the main repository, minimizing integration issues when it comes time to merge!

### Before Submitting a Pull Request

Before you submit a pull request, please ensure your fork is synchronized as described above. This check ensures your changes are compatible with the latest in the main repository and streamlines the review process.

If you encounter any issues during this process or have any questions, please reach out by [opening an issue][issues], and we'll be happy to help.

## Env Vars

You may want to make more frequent changes to your provider setup or similar to test things out
as a developer. You can use environment variables to change things on the fly without redoing
your configuration.

> [!TIP]
> At the moment, we are still updating some of the CLI configuration to make sure this is
> respected.

You can change the provider the CLI points to via the `GOOSE_PROVIDER` env var (inherited name). If you already
have a credential for that provider in your keychain from previously setting up, it should
reuse it. For things like automations or to test without doing official setup, you can also
set the relevant env vars for that provider. For example `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
or `DATABRICKS_HOST`. Refer to the provider details for more info on required keys.

### Isolating Test Environments

When testing changes or running multiple configurations, use `GOOSE_PATH_ROOT` to isolate your data:

```bash
# Test with a clean environment
export GOOSE_PATH_ROOT="/tmp/goose-test"
./target/debug/goose session

# Or for a single command
GOOSE_PATH_ROOT="/tmp/goose-dev" cargo run -p goose-cli -- session
```

This creates isolated `config/`, `data/`, and `state/` directories under the specified path, preventing your test sessions from affecting your main installation.

## Enable traces with [locally hosted Langfuse](https://langfuse.com/docs/deployment/self-host)

- [Start a local Langfuse using the docs](https://langfuse.com/self-hosting/docker-compose). Create an organization and project and create API credentials.
- Set the environment variables so that the agent can connect to the langfuse server:

```
export LANGFUSE_INIT_PROJECT_PUBLIC_KEY=publickey-local
export LANGFUSE_INIT_PROJECT_SECRET_KEY=secretkey-local
```

Then you can view your traces at http://localhost:3000

## Conventional Commits

This project follows the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification for PR titles. Conventional Commits make it easier to understand the history of a project and facilitate automation around versioning and changelog generation.

[issues]: https://github.com/kineticquant/achilles-harness/issues
[hermit]: https://cashapp.github.io/hermit/
[just]: https://github.com/casey/just?tab=readme-ov-file#installation

## Other Ways to Contribute

There are many ways to contribute besides code.

- **Stars on GitHub:** Star [kineticquant/achilles-harness](https://github.com/kineticquant/achilles-harness).
- **Ask Questions:** Open a [discussion](https://github.com/kineticquant/achilles-harness/discussions) or an issue.
- **Give Feedback:** [File a bug](https://github.com/kineticquant/achilles-harness/issues/new/choose) or a feature request.
- **Improve Documentation:** Product docs live in [`docs/`](docs/README.md).
- **Help Other Members:** Comment on issues and review pull requests.
