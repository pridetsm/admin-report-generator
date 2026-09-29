from django.core.management.base import BaseCommand

from reports import metric_history


class Command(BaseCommand):
    help = ("One fresh RAM/CPU/Disk/SWIFT/COB reading per series, across the whole business "
           "topology, written to MetricSample -- scheduled hourly, see deploy/gms/"
           "folder_exporter.yml (job metric_history_capture).")

    def handle(self, *args, **options):
        result = metric_history.capture_now()
        if result["error"]:
            self.stderr.write(self.style.ERROR(f"Prometheus unreachable: {result['error']}"))
            return
        self.stdout.write(self.style.SUCCESS(
            f"ram={result['ram']} cpu={result['cpu']} disk={result['disk']} "
            f"swift={result['swift']} cob={result['cob']}"))
