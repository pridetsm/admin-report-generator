"""Seed the Management role group.

Roles are Django Groups, created by migration so a fresh deployment has them without anyone
running a command. 0006 seeded the original four, 0012 added Security Admin; this adds
Management -- a single-screen role (the Executive Dashboard) rather than an estate.

The name is written out literally rather than imported from reports.roles: a migration has to
keep describing the database as it was when written, and importing the live list would make
this file's meaning change every time that list does.
"""
from django.db import migrations

ROLE_NAME = "Management"


def add_role(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    Group.objects.get_or_create(name=ROLE_NAME)


def remove_role(apps, schema_editor):
    # Only removes the empty group; any user still holding it keeps their other roles.
    Group = apps.get_model("auth", "Group")
    Group.objects.filter(name=ROLE_NAME).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0047_automatedfindingaction"),
    ]

    operations = [
        migrations.RunPython(add_role, remove_role),
    ]
