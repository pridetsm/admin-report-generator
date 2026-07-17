"""Create a UserProfile for every existing user (new users get one via a post_save signal)."""
from django.conf import settings
from django.db import migrations


def create_profiles(apps, schema_editor):
    User = apps.get_model(settings.AUTH_USER_MODEL.split(".")[0], settings.AUTH_USER_MODEL.split(".")[1])
    UserProfile = apps.get_model("reports", "UserProfile")
    existing = set(UserProfile.objects.values_list("user_id", flat=True))
    UserProfile.objects.bulk_create(
        [UserProfile(user_id=uid) for uid in User.objects.values_list("id", flat=True)
         if uid not in existing]
    )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0007_userprofile"),
    ]

    operations = [
        migrations.RunPython(create_profiles, noop),
    ]
