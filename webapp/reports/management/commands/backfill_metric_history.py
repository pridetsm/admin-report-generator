from django.core.management.base import BaseCommand

from reports import metric_history


class Command(BaseCommand):
    help = ("ONE-TIME catch-up pull of every metric_registry.REGISTRY entry's full history "
           "Prometheus still has, into MetricSample (prometheus_snapshot_db) -- run this once "
           "by hand after capture_metric_history is wired up (or after a new registry entry "
           "ships), so hourly captures don't have to build up history one point at a time. "
           "Safe to re-run.")

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=15,
                            help="How far back to pull (default 15 -- matches this "
                                 "Prometheus's own default retention, before it's shrunk to "
                                 "live_window_days).")

    def handle(self, *args, **options):
        result = metric_history.backfill(days=options["days"])
        if result["error"]:
            self.stderr.write(self.style.ERROR(f"Prometheus unreachable: {result['error']}"))
            return
        counts = " ".join(f"{k}={v}" for k, v in result.items() if k != "error")
        self.stdout.write(self.style.SUCCESS(counts))
