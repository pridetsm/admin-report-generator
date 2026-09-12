from django.core.management.base import BaseCommand

from reports import events


class Command(BaseCommand):
    help = "Poll Prometheus, evaluate active event groups, and e-mail newly-occurred events."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Compute and print what would be sent; no DB writes, no e-mail.")

    def handle(self, *args, **options):
        result = events.run_event_cycle(dry_run=options["dry_run"])
        self.stdout.write(self.style.SUCCESS(
            f"groups={result.groups_evaluated} new={result.new_count} "
            f"emails_sent={result.emails_sent}"))
        for e in result.emails_preview:
            self.stdout.write(f"--- would send to {e['to']} ---\nSubject: {e['subject']}\n{e['text_body']}\n")
