# Generated by Django 4.0.4 on 2022-04-20 17:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tesseract', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='balance',
            field=models.DecimalField(decimal_places=8, default=0, max_digits=8),
        ),
        migrations.AddField(
            model_name='user',
            name='online',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='rights',
            field=models.TextField(blank=True),
        ),
    ]
