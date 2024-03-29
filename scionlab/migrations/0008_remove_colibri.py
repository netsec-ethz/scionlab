# Generated by Django 3.2.18 on 2024-01-26 08:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scionlab', '0007_remove_ssh_host'),
    ]

    operations = [
        migrations.AlterField(
            model_name='service',
            name='type',
            field=models.CharField(choices=[
                ('CS', 'Control Service'),
                ('SIG', 'SCION IP Gateway'),
                ('BW', 'Bandwidth tester server'),
                ('PP', 'Pingpong server'),
            ], max_length=16),
        ),
    ]
