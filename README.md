# yarn npm audit action

GitHub Action to run `yarn npm audit`

## Feature

### Create a Pull Request comment

If vulnerabilities are found by `yarn npm audit`, Action triggered by PR creates a comment.

### Create an Issue

If vulnerabilities are found by `yarn npm audit`, Action triggered by push, schedule creates the following GitHub Issue.

![image](https://github.com/basaldev/yarn-npm-audit-action/blob/main/issue.png)

## Usage

### Inputs

|Parameter|Required|Default Value|Description|
|:--:|:--:|:--:|:--|
|severity_level|false|low|The value of `--severity` flag|
|create_issues|false|true|Flag to create issues when vulnerabilities are found|
|create_pr_comments|false|true|Flag to create pr comments when vulnerabilities are found|
|dedupe_issues|false|false|Flag to de-dupe against open issues|
|github_context|false|`${{ toJson(github) }}`|The `github` context|
|github_token|true|N/A|GitHub Access Token.<br>${{ secrets.MY_GITHUB_ACCESS_TOKEN }} is recommended.|
|issue_assignees|false|N/A|Issue assignees (separated by commma)|
|issue_labels|false|N/A|Issue labels (separated by commma)|
|issue_title|false|npm audit found vulnerabilities|Issue title|
|json_flag|false|false|Run `yarn npm audit` with `--json`|
|production_flag|false|false|Run `yarn npm audit` with `--environment production`|
|recursive_flag|false|false|Run `yarn npm audit` with `--recursive`|
|working_directory|false|N/A|The directory which contains package.json|

### Outputs

|Parameter name|Description|
|:--:|:--|
|npm_audit|The output of the npm audit report in a text format|

## Example Workflow

```yaml
name: yarn npm audit

on:
  pull_request:
  push:
    branches:
      - main
      - 'releases/*'
# on:
#   schedule:
#     - cron: '0 10 * * *'

jobs:
  scan:
    name: npm audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: install dependencies
        run: yarn install
      - uses: basaldev/yarn-npm-audit-action@v2
        with:
          severity_level: moderate
          github_token: ${{ secrets.MY_GITHUB_ACCESS_TOKEN }}
          issue_assignees: basal-luke
          issue_labels: vulnerability,test
          dedupe_issues: true
          recursive_flag: true
```

- - -

This action is inspired by [homoluctus/gitrivy](https://github.com/homoluctus/gitrivy).
