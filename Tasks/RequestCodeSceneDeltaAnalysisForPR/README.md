# Request CodeScene Delta Analysis for pull requests

Adds pull request status policy for CodeScene Delta Analysis.
See CodeScene documentation for pre-requisites.

The task requires the setting "Allow scripts to access the OAuth token" to be enabled, see [here](https://docs.microsoft.com/en-us/azure/devops/pipelines/process/phases?view=azure-devops&tabs=yaml#access-to-oauth-token) for more details.
After the first time this task is run, a status will be available to add as a branch policy, see [here](https://docs.microsoft.com/en-us/azure/devops/repos/git/pr-status-policy?view=azure-devops#configure-the-branch-policy) for more details.
