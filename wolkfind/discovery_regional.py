# /// script
# dependencies = ["boto3", "rich"]
# ///
from __future__ import annotations

from typing import Callable

import boto3
from rich.console import Console

from discovery_config import BOTO_CONFIG, DISCOVERY_MAP, LOOKUP_DAYS
from deeptrail import get_trail_config, download_trail_samples, parse_trail_events


def discover_region(
    session: boto3.Session,
    account_id: str,
    account_dir: str,
    region: str,
    write_json: Callable,
    paginate: Callable,
    safe_api_call: Callable,
    verbose: bool,
    console: Console,
    deeptrail: bool = False,
    trail_days: int = 30,
) -> str:
    for svc, files in DISCOVERY_MAP.items():
        if verbose: console.print(f"    [dim]({region})[/] [blue]Scanning {svc}...[/]")
        try:
            client = session.client(svc, region_name=region, config=BOTO_CONFIG)
            for filename, (op, key, base_kwargs) in files.items():
                # Merge base kwargs with any operation-specific overrides
                kwargs = dict(base_kwargs)
                
                data = paginate(client, op, key, **kwargs)
                if data:
                    write_json(account_dir, region, svc, filename, {key: data})
        except Exception as e:
            if verbose:
                console.print(f"  [dim red]! {svc} connection failed in {region}: {e}[/]")

    if deeptrail:
        config = get_trail_config(session, console, verbose)
        if config:
            bucket, prefix = config
            files = download_trail_samples(
                session, account_id, account_dir, region, bucket, prefix, trail_days, verbose, console, safe_api_call
            )
            if files:
                events = parse_trail_events(files)
                write_json(account_dir, region, "cloudtrail", "discovery_events.json", {"Records": events})
                if verbose: console.print(f"    [dim blue]({region}) Parsed {len(events)} events for discovery.[/]")

    return region
