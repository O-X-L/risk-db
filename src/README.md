# Risk-DB Sources

These Python3 scripts are used for building and managing the Risk-DB.

You can also run your own dedicated instances of these services.

We want to be transparent. All code that is not security-related will be Open-Source.

## Contribute

Contributions like [reporting issues](https://github.com/O-X-L/risk-db/issues/new), [engaging in discussions](https://github.com/O-X-L/risk-db/discussions) or [PRs](https://github.com/O-X-L/risk-db/pulls) are welcome!

Feel free to share your opinion about possible optimizations/extensions.

## Docker

Dockerized services will be added later on.

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
