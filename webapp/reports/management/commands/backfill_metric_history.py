from django.core.management.base import BaseCommand

from reports import metric_history


class Command(BaseCommand):
    help = ("ONE-TIME catch-up pull of every RAM/CPU/Disk/SWIFT/COB series' full history "
           "Prometheus still has, into MetricSample -- run this once by hand right after "
           "capture_metric_history is wired up, so its own hourly captures don't have to "
           "build up two weeks of history one point at a time. Safe to re-run.")

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=15,
                            help="How far back to pull (default 15 -- matches this "
                                 "Prometheus's own default retention).")

    def handle(self, *args, **options):
        result = metric_history.backfill(days=options["days"])
        if result["error"]:
            self.stderr.write(self.style.ERROR(f"Prometheus unreachable: {result['error']}"))
            return
        self.stdout.write(self.style.SUCCESS(
            f"ram={result['ram']} cpu={result['cpu']} disk={result['disk']} "
            f"swift={result['swift']} cob={result['cob']}"))
