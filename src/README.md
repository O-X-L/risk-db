# Risk-DB Sources

These Python3 scripts are used for building and managing the Risk-DB.

You can also run your own dedicated instances of these services.

We want to be transparent. All code that is not security-related will be Open-Source.

----

## Contribute

Contributions like [reporting issues](https://github.com/O-X-L/risk-db/issues/new), [engaging in discussions](https://github.com/O-X-L/risk-db/discussions) or [PRs](https://github.com/O-X-L/risk-db/pulls) are welcome!

Feel free to share your opinion about possible optimizations/extensions.

----

## Docker

Dockerized services will be added later on.

----

## Config

### PTR Queries

As querying the PTRs is one of the most time-consuming tasks when building the databases, we added an env-var to switch that step on or off:

`RISKDB_QUERY_PTR=0` => only the PTRs inside the cache-file are loaded

You could use this to offload the querying of PTRs to another service/server.

----

## Performance

The build-process is not yet very performant.

* It utilizes ony one CPU-core (threading is only used for PTR-queries)
* For ~8 million reports:
  * it used ~5GB RAM
  * querying the PTRs can take up to 1h (*without pre-existing cache*)
  * querying the PTRs with cache that is a few minutes old still takes ~15m (*retries of query failures*)
  * building the objects takes ~`265s`
  * dumping the objects and writing the databases takes ~`40s`

If you have found any way of improving the performance - feel free to open an issue or contact us per email! We are happy for every contribution (:

----

## Troubleshooting

### Open-Files Limit

If you see this error: `OSError: [Errno 24] Too many open files`

You can try to increase the limit of the current user like this: `ulimit -n 2048`

You can check your systems hard and soft limits like this: `ulimit -Hn` & `ulimit -Sn`

Or in a systemd-service you can set it like this:

```
# .service file
[Service]
LimitNOFILE=10000
```

After that - you'll need to reload it: `systemctl daemon-reload`
