from django.core.management.base import BaseCommand, CommandError

from reports.automated_reports import REPORT_TYPES, generate_automated_report, report_to_dict
from reports.automated_reports_mail import send_automated_report
from reports.models import AutomatedReportInstance, SystemConfig


class Command(BaseCommand):
    help = ("Generate one Automated Report type, store it (Phase 5 item 13 -- append-only "
           "history), and e-mail it IF SystemConfig.automated_reports_distribution_enabled "
           "is on (Phase 7: shadow mode by default).")

    def add_arguments(self, parser):
        parser.add_argument("report_type", choices=sorted(REPORT_TYPES))
        parser.add_argument("--force-distribute", action="store_true",
                            help="E-mail this instance even if distribution is off "
                                 "(manual one-off send, e.g. for the Phase 7 admin review).")

    def handle(self, *args, **options):
        report_type = options["report_type"]
        report = generate_automated_report(report_type)
        instance = AutomatedReportInstance.objects.create(
            report_type=report_type, generated_at=report.generated_at,
            window_start=report.window_start, window_end=report.window_end,
            ai_provider=report.ai_provider, ai_requested_provider=report.ai_requested_provider,
            ai_error=report.ai_error, content=report_to_dict(report),
        )
        self.stdout.write(self.style.SUCCESS(
            f"Generated {report.label} (id={instance.pk}) ai_provider={report.ai_provider} "
            f"total_issues={report.total_issues}"))

        sc = SystemConfig.get()
        should_distribute = sc.automated_reports_distribution_enabled or options["force_distribute"]
        if not should_distribute:
            self.stdout.write("Distribution is off (shadow mode) -- stored only, not e-mailed.")
            return

        try:
            subject = send_automated_report(instance)
        except Exception as exc:   # noqa: BLE001 -- a failed send must not look like a failed run
            self.stderr.write(self.style.WARNING(f"Generated but NOT e-mailed: {exc}"))
            return
        instance.distributed = True
        from django.utils import timezone
        instance.distributed_at = timezone.now()
        instance.save(update_fields=["distributed", "distributed_at"])
        self.stdout.write(self.style.SUCCESS(f"E-mailed: {subject}"))
