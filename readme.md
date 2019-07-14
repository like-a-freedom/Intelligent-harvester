# Intelligent Harvester

## Tool that make threat intelligence collection easy

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