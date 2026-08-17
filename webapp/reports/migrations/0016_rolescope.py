from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('reports', '0015_remove_grafanaconfigrevision_allow_embedding_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='RoleScope',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name='ID')),
                ('role', models.CharField(help_text="Role (Django group) name, e.g. 'Network Admin'",
                                          max_length=64, unique=True)),
                ('systems', models.JSONField(
                    blank=True, default=list,
                    help_text='System names from prometheus.yml. Empty = this role sees every system.')),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('updated_by', models.ForeignKey(blank=True, null=True,
                                                 on_delete=django.db.models.deletion.SET_NULL,
                                                 related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'role scope',
                'ordering': ['role'],
            },
        ),
    ]
