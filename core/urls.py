from django.urls import path
from .views import NmapUploadView, GenerateReportView, RegisterView, LoginView

urlpatterns = [
    path('upload-scan/', NmapUploadView.as_view(), name='upload-scan'),
    # path for generating report based on scan_id
    path('report/<str:scan_id>/', GenerateReportView.as_view(), name='generate-report'),
    # Auth URLs
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
]