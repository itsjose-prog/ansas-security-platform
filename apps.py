# apps.py (in your root folder)
from django.contrib.admin.apps import AdminConfig
from django.contrib.auth.apps import AuthConfig
from django.contrib.contenttypes.apps import ContentTypesConfig

class MongoAdminConfig(AdminConfig):
    name = 'django.contrib.admin' # <--- ADD THIS
    default_auto_field = 'django_mongodb_backend.fields.ObjectIdAutoField'

class MongoAuthConfig(AuthConfig):
    name = 'django.contrib.auth' # <--- ADD THIS
    default_auto_field = 'django_mongodb_backend.fields.ObjectIdAutoField'

class MongoContentTypesConfig(ContentTypesConfig):
    name = 'django.contrib.contenttypes' # <--- ADD THIS
    default_auto_field = 'django_mongodb_backend.fields.ObjectIdAutoField'