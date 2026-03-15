from django.db import models
from django.contrib.auth.models import User

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    upload_date = models.DateTimeField(auto_now_add=True)
    asset_count = models.IntegerField()
    scan_data_json = models.JSONField() # This stores the whole scan result
    status = models.CharField(max_length=50)
