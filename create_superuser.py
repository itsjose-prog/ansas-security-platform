import os
import django
from django.contrib.auth import get_user_model

# 1. Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.settings") # Check if your folder is 'backend' or 'ansas_project'
django.setup()

User = get_user_model()

# 2. Create Superuser if it doesn't exist
username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@example.com')
password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'admin123')

try:
    if not User.objects.filter(username=username).exists():
        print(f"Creating superuser: {username}")
        User.objects.create_superuser(username, email, password)
        print("✅ Superuser created successfully!")
    else:
        print("ℹ️ Superuser already exists. Skipping.")
except Exception as e:
    print(f"❌ Error creating superuser: {e}")