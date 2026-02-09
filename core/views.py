from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId

# PDF Imports
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Import your custom tools
from .nmap_parser import parse_nmap_xml
from .cve_fetcher import NVDFetcher

# --- INITIALIZE ENVIRONMENT ---
load_dotenv() # Load the .env file

# --- MONGODB CLOUD CONNECTION ---
mongo_uri = os.getenv('MONGO_URI')

# 1. Connect to the Cluster
try:
    client = MongoClient(mongo_uri)
    # 2. Select the Database
    db = client['ansas_db']
    # 3. Select the Collection
    scans_collection = db['scans']
    print(f"✅ Successfully connected to MongoDB Atlas")
except Exception as e:
    print(f"❌ MongoDB Connection Error: {e}")


# --- 1. AUTHENTICATION VIEWS (Open to Everyone) ---

class RegisterView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response({"error": "Please provide both username and password"}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create_user(username=username, password=password)
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({"token": token.key, "message": "User created successfully"}, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = authenticate(username=username, password=password)
        
        if user:
            token, created = Token.objects.get_or_create(user=user)
            return Response({"token": token.key, "username": user.username})
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


# --- 2. REPORT GENERATION VIEW (Authenticated & Isolated) ---

class GenerateReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            # SECURITY CHECK: Ensure user can only download THEIR OWN report
            scan = scans_collection.find_one({"_id": ObjectId(scan_id), "user": request.user.username})
            
            if not scan:
                return Response({"error": "Report not found or Access Denied"}, status=status.HTTP_404_NOT_FOUND)
        except:
             return Response({"error": "Invalid ID"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate PDF
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="report_{scan_id}.pdf"'
        p = canvas.Canvas(response, pagesize=letter)
        width, height = letter

        # A. Header
        p.setFont("Helvetica-Bold", 18)
        p.drawString(50, height - 50, "ANSAS Security Audit Report")
        p.setFont("Helvetica", 12)
        p.drawString(50, height - 80, f"Target File: {scan.get('filename', 'Unknown')}")
        p.drawString(50, height - 100, f"Scan Date: {scan.get('upload_date', 'Unknown')}")
        p.line(50, height - 110, 550, height - 110)

        # B. Executive Summary
        y = height - 150
        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, y, "Executive Summary")
        y -= 20
        p.setFont("Helvetica", 12)
        p.drawString(50, y, f"Total Assets Scanned: {scan.get('asset_count', 0)}")
        y -= 30

        # C. Detailed Findings
        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, y, "Detailed Findings")
        y -= 25
        p.setFont("Helvetica", 10)

        for host in scan.get('scan_data', []):
            if y < 100: # New page if we run out of space
                p.showPage()
                y = height - 50
            
            ip = host.get('ip_address', 'Unknown')
            p.setFont("Helvetica-Bold", 11)
            p.drawString(50, y, f"Host: {ip}")
            y -= 15
            
            p.setFont("Helvetica", 10)
            for svc in host.get('services', []):
                port = svc.get('port')
                prod = svc.get('product')
                vulns = svc.get('vuln_count', 0)
                
                # Highlight risks in red
                if vulns > 0:
                    text = f"  - Port {port}: {prod} [Risk: {vulns} Vulnerabilities Found]"
                    p.setFillColorRGB(0.8, 0, 0) # Red
                else:
                    text = f"  - Port {port}: {prod} [Safe]"
                    p.setFillColorRGB(0, 0, 0) # Black
                
                p.drawString(50, y, text)
                y -= 15
            
            y -= 10 # Spacing between hosts
            p.setFillColorRGB(0, 0, 0) # Reset to black

        # Finalize
        p.showPage()
        p.save()
        return response


# --- 3. UPLOAD & HISTORY VIEW (Authenticated & Isolated) ---

class NmapUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Retrieves scans ONLY for the logged-in user.
        """
        try:
            current_user = request.user.username
            print(f"DEBUG: Fetching history for user -> {current_user}") 

            # THE PRIVACY FILTER: Only find scans belonging to this user
            cursor = scans_collection.find({"user": current_user}).sort("upload_date", -1)
            
            scans_list = list(cursor)
            
            # Formatting for JSON
            for scan in scans_list:
                if '_id' in scan:
                    scan['_id'] = str(scan['_id'])
                if 'upload_date' in scan:
                    scan['upload_date'] = scan['upload_date'].strftime("%Y-%m-%d %H:%M:%S")
            
            return Response(scans_list, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, *args, **kwargs):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Save File
        upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        file_path = os.path.join(upload_dir, file_obj.name)
        with open(file_path, 'wb+') as destination:
            for chunk in file_obj.chunks():
                destination.write(chunk)

        # Parse File
        parsed_data = parse_nmap_xml(file_path)
        if "error" in parsed_data:
             return Response(parsed_data, status=status.HTTP_400_BAD_REQUEST)

        # Intelligence (NVD Fetch)
        # Securely load the key from .env
        api_key = os.getenv('NVD_API_KEY')
        fetcher = NVDFetcher(api_key=api_key)
        
        for host in parsed_data:
            for service in host['services']:
                product = service.get('product', 'unknown')
                version = service.get('version', 'unknown')
                if product != 'unknown' and version != 'unknown':
                    vulns = fetcher.search_cves(product, version)
                    service['vulnerabilities'] = vulns
                    service['vuln_count'] = len(vulns)
                else:
                    service['vulnerabilities'] = []
                    service['vuln_count'] = 0

        # SAVE WITH USER TAG (Essential for Privacy)
        scan_record = {
            "user": request.user.username, 
            "filename": file_obj.name,
            "upload_date": datetime.now(),
            "asset_count": len(parsed_data),
            "scan_data": parsed_data,
            "status": "analyzed"
        }

        try:
            result = scans_collection.insert_one(scan_record)
            scan_id = str(result.inserted_id)
        except Exception as e:
            return Response({"error": f"Database Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "message": "File analyzed and saved successfully",
            "db_id": scan_id,
            "filename": file_obj.name,
            "scan_data": parsed_data
        }, status=status.HTTP_201_CREATED)