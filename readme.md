# Intelligent Harvester

## Tool that make threat intelligence collection easy

## Architechture

Intelligent harvester has microservice arcitechture. Microservises are python apps wrapped in Docker containers. Containers communicate with each other via message queue (NATS).

`intelligent_harverster`

Just asynchronously downloads the feeds splits them to chunks from configuration file `feeds.yml` and send it to MQ.

`intelligent_parser`

Listen to MQ, receive chunks of the feeds from `intelligent_harvester` and parse indicator of compromise from it, then send to `intelligent_normalizer`.

`intelligent_normalizer`

- Insert new iocs, upsert if exists with updated attributes
- Normalize values into a common formats

`intelligent_storage`

Listen to MQ, receive indicators of compromise and save them to database.

`intelligent_analyzer`

Provide analytics features over the indicators datasets.
