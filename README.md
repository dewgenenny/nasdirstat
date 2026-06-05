# nasdirstat

WinDirStat-style disk usage treemap for your NAS. Scans a mapped `/data` directory using native Python and displays an interactive D3 treemap.

## Features

- **Interactive treemap** — D3 v7 zoomable treemap with drill-down navigation
- **File-type colouring** — video, audio, images, documents, archives, disk images each get a distinct colour (WinDirStat style)
- **Hover tooltips** — name, size, % of parent, % of total
- **Breadcrumb navigation** — click any level to jump back up
- **Scheduled + on-demand scans** — configurable interval (hourly → weekly) or manual
- **Persistent cache** — gzip JSON survives container restarts
- **Optional authentication** — session-based login with rate limiting and CSRF protection
- **Unraid Community Apps** ready

## Quick start

```yaml
services:
  nasdirstat:
    image: ghcr.io/dewgenenny/nasdirstat:latest
    ports:
      - "8000:8000"
    volumes:
      - /mnt/user:/data:ro
      - ./index:/index
    environment:
      - PRUNE_PATHS=/data/appdata /data/system /data/domains /data/isos
      - AUTH_USER=admin
      - AUTH_PASS=your-strong-password
```

Then open `http://<host>:8000` and click **Rescan** to populate the treemap.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DATA_PATH` | `/data` | Root directory to scan |
| `PRUNE_PATHS` | `/data/appdata /data/system /data/domains /data/isos` | Space-separated paths to skip |
| `MAX_FILES_PER_DIR` | `200` | Largest N files tracked per directory; the rest are aggregated |
| `AUTH_USER` / `AUTH_PASS` | `""` | Set both to enable login |
| `NOAUTH` | `false` | Disable authentication (LAN-only deployments) |
| `SESSION_HOURS` | `24` | Login session lifetime |

## Unraid

Install via **Community Apps** by searching for **nasdirstat**, or add the template URL manually:

```
https://raw.githubusercontent.com/dewgenenny/nasdirstat/main/templates/nasdirstat.xml
```

## Development

```bash
# Start dev stack with NOAUTH=true and test data
DEV_DATA_PATH=/path/to/some/data docker compose -f docker-compose.dev.yml up --build

# Run tests
DEV_DATA_PATH=/path/to/some/data docker compose -f docker-compose.dev.yml up --abort-on-container-exit --exit-code-from tests
```

## License

MIT © 2026 dewgenenny
