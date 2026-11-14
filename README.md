# SubA

[简体中文](README.zh-CN.md)

SubA is a self-hosted service for collecting, converting, and distributing proxy subscriptions, with optional sing-box management.

SubA is in beta and was developed primarily with AI.

## Deployment

After startup, open `http://localhost:8090` on the host and select **Install Web**. The first account you create becomes the administrator.

### CLI

Download the Linux amd64 or arm64 archive from [GitHub Releases](https://github.com/zlpharepo/suba/releases). Replace `amd64` with `arm64` on ARM64.

```sh
tar -xzf suba-linux-amd64.tar.gz
./suba --config ./config --data ./data
```

#### systemd

On Linux with systemd, stop any foreground SubA instance before starting the service. On first install, create the service user and group.

```sh
sudo useradd --system --user-group --shell /bin/false suba
```

Run the following from the directory containing the extracted binary.

```sh
sudo install -m 0755 ./suba /usr/local/bin/suba
sudo install -d -m 0700 -o suba -g suba /etc/suba /var/lib/suba
```

Save the unit as `/etc/systemd/system/suba.service`.

```ini
[Unit]
Description=SubA
After=network.target

[Service]
User=suba
Group=suba
ExecStart=/usr/local/bin/suba --host 127.0.0.1 --port 8090 --config /etc/suba --data /var/lib/suba
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start the service.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now suba.service
```

### Docker CLI

The Docker examples use host networking on Linux so sing-box can listen directly on the host's ports. The web UI listens on loopback. TUN requires additional device access and permissions.

```sh
docker run -d --name suba --restart unless-stopped --network host \
  -e HOST=127.0.0.1 \
  -v suba-config:/app/config \
  -v suba-data:/app/data \
  ghcr.io/zlpharepo/suba:latest
```

### Docker Compose

Save as `compose.yaml` and run `docker compose up -d`.

```yaml
services:
  suba:
    image: ghcr.io/zlpharepo/suba:latest
    network_mode: host
    restart: unless-stopped
    environment:
      HOST: 127.0.0.1
    volumes:
      - suba-config:/app/config
      - suba-data:/app/data

volumes:
  suba-config:
  suba-data:
```

## License

[GNU General Public License v3.0](LICENSE)
