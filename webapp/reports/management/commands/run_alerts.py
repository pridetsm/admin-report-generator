from django.core.management.base import BaseCommand

from reports import alerting


class Command(BaseCommand):
    help = "Poll Prometheus, evaluate active alert groups, and e-mail new/overdue findings."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Compute and print what would be sent; no DB writes, no e-mail.")

    def handle(self, *args, **options):
        result = alerting.run_alert_cycle(dry_run=options["dry_run"])
        self.stdout.write(self.style.SUCCESS(
            f"groups={result.groups_evaluated} systems={result.systems_captured} "
            f"new={result.new_count} reminders={result.reminder_count} "
            f"resolved={result.resolved_count} emails_sent={result.emails_sent}"))
        for e in result.emails_preview:
            self.stdout.write(f"--- would send to {e['to']} ---\nSubject: {e['subject']}\n{e['text_body']}\n")
