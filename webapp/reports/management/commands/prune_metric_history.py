from django.core.management.base import BaseCommand
from django.utils import timezone

from reports.models import MetricSample, MetricSampleRetentionRevision


class Command(BaseCommand):
    help = ("Delete MetricSample rows older than the admin-configured retention "
           "(MetricSampleRetentionRevision.current_days(), default 400d) -- scheduled daily, "
           "see deploy/gms/folder_exporter.yml (job metric_history_prune). Never grows "
           "prometheus_snapshot_db unbounded, unlike the Prometheus TSDB problem this whole "
           "archive exists to get away from.")

    def handle(self, *args, **options):
        days = MetricSampleRetentionRevision.current_days()
        cutoff = timezone.now() - timezone.timedelta(days=days)
        deleted, _ = MetricSample.objects.filter(taken_at__lt=cutoff).delete()
        self.stdout.write(self.style.SUCCESS(
            f"deleted={deleted} cutoff={cutoff.isoformat()} retention_days={days}"))
