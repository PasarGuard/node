# Contribute to Gozargah-Node-Go
Thanks for considering contributing to Gozargah!

## Questions

Please don't ask your questions in issues. Instead, use one of the following ways to ask:
- Ask on our telegram group: [@Gozargah_Marzban](https://t.me/gozargah_marzban)
- Ask on our [Node GitHub Discussions](https://github.com/m03ed/gozargah_node_go/discussions) for long term discussion or larger questions.
- Ask on our [Marzban GitHub Discussions](https://github.com/gozargah/marzban/discussions) for long term discussion or larger questions.

## Reporting issues

Include the following information in your post:
- Describe what you expected to happen.
- Describe what actually happened. Include server logs or any error that browser shows.
- If possible, post your core config file and what you have set in env (by censoring critical information).
- Also tell the version of Marzban, Core and docker (if you use docker) you are using.

# Submitting a Pull Request
If there is not an open issue for what you want to submit, prefer opening one for discussion before working on a PR. You can work on any issue that doesn't have an open PR linked to it or a maintainer assigned to it. These show up in the sidebar. No need to ask if you can work on an issue that interests you.
<br/>
Before you create a PR, make sure to run tests using the `make test` command to prevent any bugs.

## Branches
When starting development on this project, please make sure to create a new branch off the `dev` branch. This helps to keep the `main` branch stable and free of any development work that may not be complete or fully tested.

## Project Structure
```
├───backend             # Backend handler and interfaces
│   └───xray            # Xray methods and jobs
│       └───api         # Xray API handler
├───common              # Proto files and common object structures
├───config              # Reads .env configuration
├───controller          # Service controllers for managing API interactions  
│   ├───rest            # REST API protocol methods
│   └───rpc             # gRPC protocol methods
├───logger              # primary logger for backend logs
└───tools               # Standalone utilities with no project dependencies
```
