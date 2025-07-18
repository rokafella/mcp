# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""CloudTrail tools for MCP server."""

import boto3
import os
import time
from awslabs.cloudtrail_mcp_server import MCP_SERVER_VERSION
from awslabs.cloudtrail_mcp_server.common import (
    parse_time_input,
    remove_null_values,
    validate_max_results,
)
from awslabs.cloudtrail_mcp_server.models import (
    EventDataStore,
    QueryResult,
    QueryStatus,
)
from botocore.config import Config
from datetime import datetime
from loguru import logger
from mcp.server.fastmcp import Context
from pydantic import Field
from typing import Annotated, Any, Dict, List, Literal, Optional


class CloudTrailTools:
    """CloudTrail tools for MCP server."""

    def __init__(self):
        """Initialize the CloudTrail tools."""
        self._cloudtrail_client = None
        self._cloudtrail_client_region = None

    @property
    def cloudtrail_client(self):
        """Get the CloudTrail client for the default region (us-east-1)."""
        if self._cloudtrail_client is None or self._cloudtrail_client_region != 'us-east-1':
            self._cloudtrail_client = self._get_cloudtrail_client('us-east-1')
            self._cloudtrail_client_region = 'us-east-1'
        return self._cloudtrail_client

    def _get_cloudtrail_client(self, region: str):
        """Create a CloudTrail client for the specified region."""
        config = Config(user_agent_extra=f'awslabs/mcp/cloudtrail-mcp-server/{MCP_SERVER_VERSION}')

        try:
            if aws_profile := os.environ.get('AWS_PROFILE'):
                return boto3.Session(profile_name=aws_profile, region_name=region).client(
                    'cloudtrail', config=config
                )
            else:
                return boto3.Session(region_name=region).client('cloudtrail', config=config)
        except Exception as e:
            logger.error(f'Error creating CloudTrail client for region {region}: {str(e)}')
            raise

    def register(self, mcp):
        """Register all CloudTrail tools with the MCP server."""
        # Register simplified lookup_events tool that handles all filtering
        mcp.tool(name='lookup_events')(self.lookup_events)

        # Register lake_query tool
        mcp.tool(name='lake_query')(self.lake_query)

        # Register get_query_status tool
        mcp.tool(name='get_query_status')(self.get_query_status)

        # Register list_event_data_stores tool
        mcp.tool(name='list_event_data_stores')(self.list_event_data_stores)

    async def lookup_events(
        self,
        ctx: Context,
        start_time: Annotated[
            Optional[str],
            Field(
                description='Start time for event lookup (ISO format or relative like "1 day ago")'
            ),
        ] = None,
        end_time: Annotated[
            Optional[str],
            Field(
                description='End time for event lookup (ISO format or relative like "1 hour ago")'
            ),
        ] = None,
        attribute_key: Annotated[
            Optional[
                Literal[
                    'EventId',
                    'EventName',
                    'ReadOnly',
                    'Username',
                    'ResourceType',
                    'ResourceName',
                    'EventSource',
                    'AccessKeyId',
                ]
            ],
            Field(description='Attribute to search by'),
        ] = None,
        attribute_value: Annotated[
            Optional[str], Field(description='Value to search for in the specified attribute')
        ] = None,
        max_results: Annotated[
            Optional[int],
            Field(description='Maximum number of events to return (1-50, default: 10)'),
        ] = None,
        region: Annotated[
            str,
            Field(description='AWS region to query. Defaults to us-east-1.'),
        ] = 'us-east-1',
    ) -> Dict[str, Any]:
        """Look up CloudTrail events based on various criteria.

        This tool searches CloudTrail events using the LookupEvents API, which provides access to the
        last 90 days of management events. You can filter by time range and search for specific
        attribute values.

        Usage: Use this tool to find CloudTrail events by various attributes like username, event name,
        resource name, etc. This is useful for security investigations, troubleshooting, and audit trails.

        Returns:
        --------
        Dictionary containing:
            - events: List of CloudTrail events matching the criteria with exact CloudTrail schema
            - next_token: Token for pagination if more results available
            - query_params: Parameters used for the query
        """
        try:
            # Create CloudTrail client for the specified region
            cloudtrail_client = self._get_cloudtrail_client(region)

            # Set default time range if not provided (last 24 hours)
            if not start_time:
                start_time = '1 day ago'
            if not end_time:
                end_time = 'now'

            # Parse time inputs
            start_dt = parse_time_input(start_time)
            end_dt = parse_time_input(end_time)

            # Validate max_results
            max_results = validate_max_results(max_results, default=10, max_allowed=50)

            # Build lookup parameters
            lookup_params = {
                'StartTime': start_dt,
                'EndTime': end_dt,
                'MaxResults': max_results,
            }

            # Add attribute filter if provided
            if attribute_key and attribute_value:
                lookup_params['LookupAttributes'] = [
                    {'AttributeKey': attribute_key, 'AttributeValue': attribute_value}
                ]

            logger.info(f'Looking up CloudTrail events with params: {lookup_params}')

            # Call CloudTrail API
            response = cloudtrail_client.lookup_events(**remove_null_values(lookup_params))

            # Return events exactly as they come from CloudTrail API
            events = response.get('Events', [])

            result = {
                'events': events,
                'next_token': response.get('NextToken'),
                'query_params': {
                    'start_time': start_dt.isoformat(),
                    'end_time': end_dt.isoformat(),
                    'attribute_key': attribute_key,
                    'attribute_value': attribute_value,
                    'max_results': max_results,
                    'region': region,
                },
            }

            logger.info(
                f'Successfully retrieved {len(events)} CloudTrail events from region {region}'
            )
            return result

        except Exception as e:
            logger.error(f'Error in lookup_events: {str(e)}')
            await ctx.error(f'Error looking up CloudTrail events: {str(e)}')
            raise

    async def lake_query(
        self,
        ctx: Context,
        sql: Annotated[
            str,
            Field(
                description="SQL query to execute against CloudTrail Lake. IMPORTANT: You must include a valid Event Data Store (EDS) ID in the FROM clause of your SQL query. Use list_event_data_stores tool to get available EDS IDs first. CloudTrail Lake only supports SELECT statements using Trino-compatible SQL syntax. Example: SELECT * FROM 0233062b-51c6-4d18-8dec-a8c90da840d9 WHERE eventname = 'ConsoleLogin'"
            ),
        ],
        region: Annotated[
            str,
            Field(description='AWS region to query. Defaults to us-east-1.'),
        ] = 'us-east-1',
    ) -> QueryResult:
        """Execute a SQL query against CloudTrail Lake for complex analytics and filtering.

        CloudTrail Lake allows you to run SQL queries against your CloudTrail events for advanced
        analysis. This is more powerful than the basic lookup functions and allows for complex
        filtering, aggregation, and analysis.

        IMPORTANT LIMITATIONS:
        - CloudTrail Lake only supports SELECT statements using Trino-compatible SQL syntax
        - INSERT, UPDATE, DELETE, CREATE, DROP, and other DDL/DML operations are not supported
        - Your SQL query MUST include a valid Event Data Store (EDS) ID in the FROM clause
        - Use the list_event_data_stores tool first to get available EDS IDs, then reference the EDS ID
          directly in your FROM clause

        Valid SQL query examples:
        - SELECT eventname, count(*) FROM 0233062b-51c6-4d18-8dec-a8c90da840d9 WHERE eventtime > '2023-01-01' GROUP BY eventname
        - SELECT useridentity.username, eventname, eventtime FROM your-eds-id WHERE errorcode IS NOT NULL
        - SELECT DISTINCT awsregion FROM your-eds-id WHERE eventname = 'CreateUser'

        Returns:
        --------
        QueryResult containing:
            - query_id: Unique identifier for the query
            - query_status: Current status of the query
            - query_result_rows: Results if query completed successfully
            - query_statistics: Performance statistics for the query
        """
        try:
            # Create CloudTrail client for the specified region
            cloudtrail_client = self._get_cloudtrail_client(region)

            logger.info(f'Starting CloudTrail Lake query in region {region}')
            logger.info(f'SQL: {sql}')

            # Start the query directly with the provided SQL
            start_response = cloudtrail_client.start_query(
                QueryStatement=sql,
            )

            query_id = start_response['QueryId']
            logger.info(f'Started query with ID: {query_id}')

            # Poll for completion (with a reasonable timeout)
            max_wait_time = 300  # 5 minutes
            poll_interval = 2  # 2 seconds
            elapsed_time = 0

            # Initialize variables to avoid "possibly unbound" errors
            query_status = 'RUNNING'
            status_response = {}

            while elapsed_time < max_wait_time:
                status_response = cloudtrail_client.describe_query(QueryId=query_id)
                query_status = status_response['QueryStatus']

                if query_status in ['FINISHED', 'FAILED', 'CANCELLED', 'TIMED_OUT']:
                    break

                time.sleep(poll_interval)
                elapsed_time += poll_interval

            # Get final results
            if query_status == 'FINISHED':
                results_response = cloudtrail_client.get_query_results(
                    QueryId=query_id, MaxQueryResults=1000
                )

                raw_results = results_response.get('QueryResultRows', [])

                return QueryResult(
                    query_id=query_id,
                    query_status=query_status,
                    query_statistics=status_response.get('QueryStatistics'),
                    query_result_rows=raw_results,  # Keep original format for compatibility
                    next_token=results_response.get('NextToken'),
                )
            else:
                return QueryResult(
                    query_id=query_id,
                    query_status=query_status,
                    query_statistics=status_response.get('QueryStatistics'),
                    error_message=status_response.get('ErrorMessage'),
                )

        except Exception as e:
            logger.error(f'Error in lake_query: {str(e)}')
            await ctx.error(f'Error executing CloudTrail Lake query: {str(e)}')
            raise

    async def get_query_status(
        self,
        ctx: Context,
        query_id: Annotated[str, Field(description='The ID of the query to check status for')],
        region: Annotated[
            str,
            Field(description='AWS region to query. Defaults to us-east-1.'),
        ] = 'us-east-1',
    ) -> QueryStatus:
        """Get the status of a CloudTrail Lake query.

        This tool checks the status of a previously started CloudTrail Lake query. Use this
        when you need to check if a long-running query has completed or if you want to get
        details about query execution.

        Usage: Use this tool to monitor the progress of CloudTrail Lake queries, especially
        long-running ones that may take time to complete.

        Returns:
        --------
        QueryStatus containing:
            - query_id: The query identifier
            - query_status: Current status (QUEUED, RUNNING, FINISHED, FAILED, CANCELLED, TIMED_OUT)
            - query_statistics: Performance and execution statistics
            - error_message: Error details if the query failed
        """
        try:
            # Create CloudTrail client for the specified region
            cloudtrail_client = self._get_cloudtrail_client(region)

            logger.info(f'Checking status for query {query_id} in region {region}')

            # Get query status
            response = cloudtrail_client.describe_query(QueryId=query_id)

            return QueryStatus(
                query_id=query_id,
                query_status=response['QueryStatus'],
                query_statistics=response.get('QueryStatistics'),
                error_message=response.get('ErrorMessage'),
                delivery_s3_uri=response.get('DeliveryS3Uri'),
                delivery_status=response.get('DeliveryStatus'),
            )

        except Exception as e:
            logger.error(f'Error in get_query_status: {str(e)}')
            await ctx.error(f'Error getting query status: {str(e)}')
            raise

    async def list_event_data_stores(
        self,
        ctx: Context,
        include_details: Annotated[
            bool,
            Field(
                description='Whether to include detailed event selector information (default: true)'
            ),
        ] = True,
        region: Annotated[
            str,
            Field(description='AWS region to query. Defaults to us-east-1.'),
        ] = 'us-east-1',
    ) -> Dict[str, Any]:
        """List available CloudTrail Lake Event Data Stores with their capabilities and event selectors.

        Event Data Stores are the storage and query engines for CloudTrail Lake. This tool helps you
        understand which Event Data Stores are available and their configurations.

        Usage: Use this tool to understand which Event Data Stores are available and their
        configurations. This information is needed when executing CloudTrail Lake queries.

        Returns:
        --------
        Dictionary containing:
            - event_data_stores: List of available Event Data Stores with their configurations
            - summary: Summary of the Event Data Stores capabilities
        """
        try:
            # Create CloudTrail client for the specified region
            cloudtrail_client = self._get_cloudtrail_client(region)

            logger.info(f'Listing CloudTrail Lake Event Data Stores in region {region}')

            # List event data stores
            response = cloudtrail_client.list_event_data_stores()
            event_data_stores = response.get('EventDataStores', [])

            # Process and format the data stores
            formatted_stores = []
            for store in event_data_stores:
                formatted_store = EventDataStore.model_validate(store).model_dump()

                # Add detailed information if requested
                if include_details and formatted_store.get('event_data_store_arn'):
                    try:
                        details_response = cloudtrail_client.get_event_data_store(
                            EventDataStore=formatted_store['event_data_store_arn']
                        )
                        # Merge additional details
                        formatted_store.update(
                            {
                                'advanced_event_selectors': details_response.get(
                                    'AdvancedEventSelectors', []
                                ),
                                'multi_region_enabled': details_response.get('MultiRegionEnabled'),
                                'organization_enabled': details_response.get(
                                    'OrganizationEnabled'
                                ),
                            }
                        )
                    except Exception as detail_error:
                        logger.warning(
                            f'Could not get detailed info for store {formatted_store.get("name")}: {detail_error}'
                        )

                # Remove null values from the formatted store
                formatted_stores.append(remove_null_values(formatted_store))

            # Create summary
            summary = {
                'total_stores': len(formatted_stores),
                'active_stores': len(
                    [s for s in formatted_stores if s.get('status') == 'ENABLED']
                ),
                'multi_region_stores': len(
                    [s for s in formatted_stores if s.get('multi_region_enabled')]
                ),
                'organization_stores': len(
                    [s for s in formatted_stores if s.get('organization_enabled')]
                ),
            }

            result = {
                'event_data_stores': formatted_stores,
                'summary': summary,
                'region': region,
            }

            logger.info(
                f'Successfully retrieved {len(formatted_stores)} Event Data Stores from region {region}'
            )
            return result

        except Exception as e:
            logger.error(f'Error in list_event_data_stores: {str(e)}')
            await ctx.error(f'Error listing Event Data Stores: {str(e)}')
            raise

    def _process_query_results(
        self, raw_results: List[List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Process CloudTrail Lake query results into a user-friendly format.

        Converts the nested field/value format into simple dictionaries.

        Args:
            raw_results: Raw CloudTrail Lake results in nested format

        Returns:
            List of processed result dictionaries
        """
        if not raw_results:
            return []

        processed_results = []

        # Process each row
        for row in raw_results:
            if not row or not isinstance(row, list):
                continue

            # Convert field/value pairs to dictionary
            processed_row = {}
            for field_info in row:
                if (
                    isinstance(field_info, dict)
                    and 'field' in field_info
                    and 'value' in field_info
                ):
                    field_name = field_info['field']
                    field_value = field_info['value']

                    # Handle different data types
                    processed_row[field_name] = self._format_field_value(field_value)

            if processed_row:  # Only add non-empty rows
                processed_results.append(processed_row)

        return processed_results

    def _format_field_value(self, value: Any) -> Any:
        """Format field values with appropriate data types."""
        if value is None:
            return None

        # If it's already a string, check if it looks like a date, number, or boolean
        if isinstance(value, str):
            # Try to detect and convert common data types
            value_lower = value.lower().strip()

            # Boolean detection
            if value_lower in ('true', 'false'):
                return value_lower == 'true'

            # Null detection
            if value_lower in ('null', 'none', ''):
                return None

            # Date detection (ISO format)
            if len(value) >= 19 and ('T' in value or '-' in value[:10]):
                try:
                    # Try parsing as datetime
                    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    return dt.isoformat()
                except (ValueError, TypeError):
                    pass

            # Number detection
            try:
                # Try integer first
                if '.' not in value and 'e' not in value_lower:
                    return int(value)
                else:
                    return float(value)
            except (ValueError, TypeError):
                pass

        # Return as-is if no conversion applies
        return value
