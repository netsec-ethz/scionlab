# Generated by Django 3.0.7 on 2020-12-10 09:16

from django.db import migrations


def bump_config(apps, schema_editor):
    # Host = apps.get_model('scionlab', 'Host')
    from scionlab.models.core import Host
    Host.objects.bump_config()


class Migration(migrations.Migration):

    dependencies = [
        ('scionlab', '0009_remove_interface_bind_port'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='borderrouter',
            name='control_port',
        ),
        migrations.RemoveField(
            model_name='borderrouter',
            name='internal_port',
        ),
        migrations.RunPython(bump_config),
    ]
