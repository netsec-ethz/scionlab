# Generated by Django 3.1.6 on 2022-01-27 14:35

from django.db import migrations

from scionlab.models.core import Host, Service


def bump_version(apps, schema_editor):
    """
    Data migration: bump the version of those hosts that run
    the Control Service of Core ASes.
    They need to get new configuration from the Coordinator, due to a change in how the
    CA type is specified.
    """
    Host.objects.bump_config(services__type=Service.CS, AS__is_core=True)


class Migration(migrations.Migration):

    dependencies = [
        ('scionlab', '0005_trc_pem'),
    ]

    operations = [
        migrations.RunPython(bump_version,        # forward
                             lambda a, b: None),  # backward
    ]
