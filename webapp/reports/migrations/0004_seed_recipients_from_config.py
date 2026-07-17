"""Seed the curated recipient list from config.ini [recipients] so the in-app list starts
populated with whatever was already configured (idempotent; never fails the migration)."""
from django.db import migrations


def seed(apps, schema_editor):
    Recipient = apps.get_model("reports", "EmailRecipient")
    try:
        import configparser
        import generate_report as gr   # send_report/ is on sys.path (settings)
        cp = configparser.ConfigParser(interpolation=None)
        cp.read(str(gr.DEFAULT_CONFIG))
        if not cp.has_section("recipients"):
            return
        to = [e.strip() for e in cp["recipients"].get("to", "").split(",") if e.strip()]
        choices = [e.strip() for e in cp["recipients"].get("choices", "").split(",") if e.strip()]
        for e in to:
            Recipient.objects.get_or_create(email=e, defaults={"default_selected": True})
        for e in choices:
            Recipient.objects.get_or_create(email=e, defaults={"default_selected": False})
    except Exception:   # noqa: BLE001 — seeding is best-effort; config may be absent
        pass


def unseed(apps, schema_editor):
    # keep any curation the admin has done; nothing to reverse safely
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0003_emailrecipient"),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
