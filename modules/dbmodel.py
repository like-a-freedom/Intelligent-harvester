from infi.clickhouse_orm import models, fields, engines
from infi.clickhouse_orm.database import Database
from infi.clickhouse_orm.models import Model
from infi.clickhouse_orm.fields import *

class ThreatIntel(Model):
    
    iocValue = StringField()
    iocType = StringField()
    providerName = StringField()
    createdDate = DateTimeField()

