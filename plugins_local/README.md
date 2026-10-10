# Drop-in plugins

Any `*.py` file here (not starting with `_`) is imported at startup. Every concrete
`Plugin` subclass with a `name` is registered. Run `osint plugins` to check that yours
was found.

```python
from pydantic import BaseModel
from osint.core.plugins import Enricher

class Params(BaseModel):
    api_key_env: str = "MY_API_KEY"

class MyEnricher(Enricher):
    name = "my_enricher"
    entity_types = {"domain"}
    params_schema = Params

    async def enrich(self, entity, ctx):
        return []
```

To package a plugin for reuse, put it in its own package instead and register it under
the `osint.plugins` entry-point group.
