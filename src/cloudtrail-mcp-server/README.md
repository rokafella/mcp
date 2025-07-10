# AWS Labs cloudtrail MCP Server

An AWS Labs Model Context Protocol (MCP) server for cloudtrail

## Instructions

A server for querying AWS account activity using AWS CloudTrail.

## TODO (REMOVE AFTER COMPLETING)

* [ ] Optionally add an ["RFC issue"](https://github.com/awslabs/mcp/issues) for the community to review
* [ ] Generate a `uv.lock` file with `uv sync` -> See [Getting Started](https://docs.astral.sh/uv/getting-started/)
* [ ] Remove the example tools in `./awslabs/cloudtrail_mcp_server/server.py`
* [ ] Add your own tool(s) following the [DESIGN_GUIDELINES.md](https://github.com/awslabs/mcp/blob/main/DESIGN_GUIDELINES.md)
* [ ] Keep test coverage at or above the `main` branch - NOTE: GitHub Actions run this command for CodeCov metrics `uv run --frozen pytest --cov --cov-branch --cov-report=term-missing`
* [ ] Document the MCP Server in this "README.md"
* [ ] Add a section for this cloudtrail MCP Server at the top level of this repository "../../README.md"
* [ ] Create the "../../doc/servers/cloudtrail-mcp-server.md" file with these contents:

    ```markdown
    ---
    title: cloudtrail MCP Server
    ---

    {% include "../../src/cloudtrail-mcp-server/README.md" %}
    ```

* [ ] Reference within the "../../doc/index.md" like this:

    ```markdown
    ### cloudtrail MCP Server

    An AWS Labs Model Context Protocol (MCP) server for cloudtrail

    **Features:**

    - Feature one
    - Feature two
    - ...

    A server for querying AWS account activity using AWS CloudTrail.

    [Learn more about the cloudtrail MCP Server](servers/cloudtrail-mcp-server.md)
    ```

* [ ] Submit a PR and pass all the checks
