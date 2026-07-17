"""Seed the role catalogue (System Admin, Network Admin, Gov Systems Admin, Administrator)
as Django groups. Idempotent."""
from django.db import migrations

ROLE_NAMES = ["System Admin", "Network Admin", "Gov Systems Admin", "Administrator"]


def seed(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    for name in ROLE_NAMES:
        Group.objects.get_or_create(name=name)


def unseed(apps, schema_editor):
    # leave groups in place (users may be assigned to them); nothing to reverse safely
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0005_rolerequest"),
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
