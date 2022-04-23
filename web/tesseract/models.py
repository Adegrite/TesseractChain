from asyncio.windows_events import NULL
from django.db import models


# Create your models here.
class User(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField()
    password = models.CharField(max_length=255)
    public_key = models.CharField(max_length=34)
    secret = models.CharField(max_length=255)
    balance = models.DecimalField(max_digits=8, decimal_places=8, default=NULL)
    online = models.BooleanField(default=False)
    rights = models.TextField(blank=True)
    time_create = models.DateTimeField(auto_now_add=True)
    time_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.username

    def get_absolute_url(self):
        # return reverse("model_detail", kwargs={"pk": self.pk})
        pass

    # class Meta:
    #     verbose_name = 'Users'
    #     verbose_name_plural = 'Users'