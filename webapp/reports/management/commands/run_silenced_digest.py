from django.core.management.base import BaseCommand

from reports import alerting


class Command(BaseCommand):
    help = ("Roll up everything that happened under an active AlertSilence over the last "
           "24 hours into one digest e-mail per AlertGroup.")

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Compute and print what would be sent; no e-mail.")

    def handle(self, *args, **options):
        result = alerting.build_silenced_digest(dry_run=options["dry_run"])
        self.stdout.write(self.style.SUCCESS(
            f"silences_evaluated={result.silences_evaluated} "
            f"groups_notified={result.groups_notified} emails_sent={result.emails_sent}"))
        for e in result.emails_preview:
            self.stdout.write(f"--- would send to {e['to']} ---\nSubject: {e['subject']}\n{e['text_body']}\n")
