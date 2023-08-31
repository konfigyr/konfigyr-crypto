# Contributing to Konfigyr Crypto library

Konfigyr Crypto library is released under the Apache 2.0 license.
If you would like to contribute something, or simply want to hack on the code this document should help you [get started](https://github.com/konfigyr/konfigyr-crypto#getting-started).

## Code of Conduct
This project adheres to the Contributor Covenant [code of conduct](CODE_OF_CONDUCT.md).  By participating, you are expected to uphold this code.

## Using GitHub Issues
We use GitHub issues to track bugs and enhancements.

If you are reporting a bug, please help to speed up problem diagnosis by providing as much information as possible.

Ideally, that would include a [complete & minimal sample project](https://stackoverflow.com/help/minimal-reproducible-example) that reproduces the problem.

## Submitting Pull Requests
This project uses [pull requests](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests) for the community to suggest changes to the project.

There are a few important things to keep in mind when submitting a pull request:

* Expect feedback and to make changes to your contributions.
* Unless it is a minor change:
  * It is best to discuss pull requests on an issue before doing work
  * We expect the pull request to start with a https://github.blog/2019-02-14-introducing-draft-pull-requests/[draft pull request].
    * The pull request should be as small as possible and focus on a single unit of change.
    This ensures that we are collaborating together as soon as possible.
    * Generally, this means do not introduce any new interfaces and as few classes as possible.
    That may mean using an external library directly in a `Filter`.
    * We will discuss with you how to iterate once you have submitted the initial draft pull request.

## Squash commits

Use `git rebase –interactive`, `git add –patch` and other tools to "squash" multiple commits into atomic changes.

## Format commit messages

. Keep the subject line to 50 characters or fewer if possible.
. Do not end the subject line with a period.
. In the body of the commit message, explain how things worked before this commit, what has changed, and how things work now.
. Include Fixes gh-<issue-number> at the end if this fixes a GitHub issue.
