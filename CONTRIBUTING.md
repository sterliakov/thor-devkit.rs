# Contributing

You want to help contribute? Awesome! Thanks for taking the time to look at the
guidelines for this repo. Here's what you need to know!

## License

**thor-devkit.rs** is proudly licenced under the GNU General Public License v3, and so are all
contributions. Please see the [`LICENSE`] file in this directory for more details.

[`LICENSE`]: https://github.com/sterliakov/thor-devkit.rs/blob/main/LICENSE

## Pull Requests

To make changes to **thor-devkit.rs**, please send in pull requests on GitHub to
the `main` branch. I'll review them and either merge or request changes. GitHub Actions
tests everything as well, so you may get feedback from it too.

If you make additions or other changes to a pull request, feel free to either amend
previous commits or only add new ones, however you prefer.

## Issue Tracker

You can find the issue tracker [on
GitHub](https://github.com/sterliakov/thor-devkit.rs/issues). If you've found a
problem with **thor-devkit.rs**, please open an issue there.


## Development workflow

First, we use [`pre-commit`](https://pre-commit.com/) for linters aggregation. After cloning the repo
make sure to install `pre-commit` (if you have python installed, it's as simple as
`pip install pre-commit`) and execute the following command:

```bash
pre-commit install
```

This will make sure that linters are run against every commit you make.

To run tests, use standard

```bash
cargo test
```

To run tests with measuring coverage, install [`tarpaulin`](https://github.com/xd009642/tarpaulin) via `cargo install cargo-tarpaulin` and use

```bash
cargo tarpaulin --out Html
```

You will find coverage in `tarpaulin-report.html` (gitignored) file at the root
of repository. CI does this automatically, so you may not need to execute this locally.


## Types of Contributions

### Report Bugs

Report bugs at https://github.com/sterliakov/thor-devkit.rs/issues.

If you are reporting a bug, please include:

* Your operating system name and version.
* Any details about your local setup that might be helpful in troubleshooting.
* Detailed steps to reproduce the bug.

### Fix Bug

Look through the GitHub issues for bugs. Anything tagged with "bug"
is open to whoever wants to implement it.

### Implement Features

Look through the GitHub issues for features. Anything tagged with "feature"
is open to whoever wants to implement it.

### Write Documentation

thor-devkit.rs could always use more documentation, whether as part of the
official thor-devkit.rs docs, in docstrings, or even on the web in blog posts,
articles, and such.

### Submit Feedback

The best way to send feedback is to file an issue at https://github.com/sterliakov/thor-devkit.rs/issues.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome :)

## Get Started!

Ready to contribute? Here's how to set up `thor-devkit.rs` for local development.

1. Fork the `thor-devkit.rs` repo on GitHub.
2. Clone your fork locally:
    ```shell
    $ git clone git@github.com:your_name_here/thor-devkit.rs.git
    ```
3. Create a branch for local development:
    ```shell
    $ git checkout -b name-of-your-bugfix-or-feature
    ```
   Now you can make your changes locally.

4. When you're done making changes, check that your changes pass the tests:
    ```shell
    $ cargo test
    ```
5. If necessary, create a new Rust script under the `examples/` folder which
   demonstrates usage of the new feature.

   Then, run the new example script to confirm that it works as intended:
    ```shell
    $ cargo run --example my_awesome_example
    ```
6. Commit your changes and push your branch to GitHub:
    ```shell
    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature
    ```
7. Submit a pull request through the GitHub website.

## Pull Request Guidelines

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in README.md.

## Deploying

A reminder for the maintainers on how to deploy.

First, create a release branch from `master` and bump a version there, open a release PR:
```shell
$ git checkout master
$ git pull origin master
$ git switch -c release/x.y.z
$ cargo bump patch # possible: major / minor / patch
$ git push
$ gh pr create --title 'Release x.y.z'  # Or go via github GUI
```

When all checks are green, merge it into `master`. Wait for tests to pass and create a tag to trigger automated release:
```shell
$ git checkout master
$ git pull origin master
$ git tag vx.y.z
$ git push --tags
```
