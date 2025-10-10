# phantun (docker)

## Build

```sh
docker build -t phantun -f docker/Dockerfile .
```

## Usage

[docker-compose.yml](docker-compose.yml) contains an example single-host configuration. To try it, run compose in the first terminal:
```sh
docker compose up
```

and in the second terminal run `netcat`:
```sh
nc -u 127.0.0.1 1234
```

Now everything you type in the second terminal must be echoed.
