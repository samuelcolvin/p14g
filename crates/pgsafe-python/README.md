# pgsafe

Check untrusted SQL against an allowlist and rewrite it so it is safe to run on Postgres.

See the [project README](https://github.com/samuelcolvin/pgsafe) for what pgsafe does and does not protect against.

```python
from pgsafe import Policy, Select

policy = Policy(Select('orders', columns=['id', 'product', 'qty']))

safe = policy.rewrite('select id from orders where qty < 3')
print(safe.sql)
#> SELECT "orders"."id" FROM "orders" WHERE ("orders"."qty" < 3)

policy.rewrite('select * from pg_shadow')
#> pgsafe.PgSafeError: reading from table "pg_shadow" is not allowed
```
