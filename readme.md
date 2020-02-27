# Intelligent Harvester

## Tool that make threat intelligence collection easy

## Architechture

Intelligent harvester has microservice arcitechture. Microservises are python apps wrapped in Docker containers. Containers communicate with each other via message queue (NATS).

`intelligent_harverster`

Just asynchronously downloads the feeds splits them to chunks from configuration file `feeds.yml` and send it to MQ.

`intelligent_parser`

Listen to MQ, receive chunks of the feeds from `intelligent_harvester` and parse indicator of compromise from it, then send to `intelligent_normalizer`.

`intelligent_normalizer`

TBD

`intelligent_aggregator`

TBD

`intelligent_storage`

Listen to MQ, receive indicators of compromise and save them to database.

`intelligent_analyzer`

Provide analytics features over the indicators datasets.

## Installation

`git clone <repository>`

`pip install -r requirements.txt`

## Usage

### Windows

So simple:

`python collect.py`

Or if you want to specify path to configuration file and export IoCs in plain text newline as delimiter:

`python collect.py --config "X:\path-to-harvester\config\settings.yaml" --output txt`

Or if you want to specify number of parallel proccesses for download and parsing and export IoCs to SQLite database:

`python collect.py --config "X:\path-to-harvester\config\settings.yaml" --processes 4 --output sqlite`