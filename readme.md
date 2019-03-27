# Intelligent Harvester

## Tool that make threat intelligence collection easy

## Installation

`git clone <repository>`

`pip install -r requirements.txt`

## Usage

### Windows

So simple:

`python collect.py`

Or if you want to specify path to configuration file:

`python collect.py -c "X:\path-to-harvester\settings.conf"`

Or if you want to specify number of parallel proccesses for download and parsing:

`python collect.py -c "X:\path-to-harvester\settings.conf" --processes 4`