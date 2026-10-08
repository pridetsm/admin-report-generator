from django.core.management.base import BaseCommand

from reports import metric_history


class Command(BaseCommand):
    help = ("One fresh reading per metric_registry.REGISTRY entry, across the whole estate, "
           "written to MetricSample (prometheus_snapshot_db) -- scheduled hourly, see "
           "deploy/gms/folder_exporter.yml (job metric_history_capture).")

    def handle(self, *args, **options):
        result = metric_history.capture_now()
        if result["error"]:
            self.stderr.write(self.style.ERROR(f"Prometheus unreachable: {result['error']}"))
            return
        counts = " ".join(f"{k}={v}" for k, v in result.items() if k != "error")
        self.stdout.write(self.style.SUCCESS(counts))
