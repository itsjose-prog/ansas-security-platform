from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token

# --- ANSAS Custom Engines ---
from .compliance_engine import evaluate_compliance  # Feature: DPA Logic
from .remediation_engine import get_remediation    # Feature: Fix Logic
from .nmap_parser import parse_nmap_xml            # Feature: XML Parsing
from .cve_fetcher import NVDFetcher                # Feature: NVD Intelligence

import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId

# --- PDF Generation Tools ---
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas

# --- DATABASE SETUP ---
load_dotenv() 
client = MongoClient(os.getenv('MONGO_URI'))
db = client['ansas_db']
scans_collection = db['scans']

# --- 1. AUTHENTICATION VIEWS ---
# Handles User Signup and Token Generation
class RegisterView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username, password = request.data.get('username'), request.data.get('password')
        if User.objects.filter(username=username).exists():
            return Response({"error": "User exists"}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(username=username, password=password)
        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key}, status=status.HTTP_201_CREATED)

# Handles User Login
class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        user = authenticate(username=request.data.get('username'), password=request.data.get('password'))
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({"token": token.key, "username": user.username})
        return Response({"error": "Invalid"}, status=status.HTTP_401_UNAUTHORIZED)

# --- 2. REPORT GENERATION (Consolidated Feature Set) ---
class GenerateReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        # Retrieve Scan from MongoDB
        scan = scans_collection.find_one({"_id": ObjectId(scan_id), "user": request.user.username})
        if not scan: return Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)

        # Feature: White-Labeling (Capturing Client/Auditor details from URL params)
        client_name = request.GET.get('client_name', 'Internal Audit')
        auditor_name = request.GET.get('auditor_name', 'Ombati Josephat')
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Initialize PDF Canvas
        response = HttpResponse(content_type='application/pdf')
        p = canvas.Canvas(response, pagesize=letter)
        width, height = letter

        # --- PAGE 1: TECHNICAL FINDINGS ---
        # Feature: Professional Branding & Header
        p.setFillColor(colors.darkblue); p.rect(0, height - 100, width, 100, fill=1)
        p.setFillColor(colors.white); p.setFont("Helvetica-Bold", 24)
        p.drawString(50, height - 50, "Security Audit Report")
        p.setFont("Helvetica-Bold", 10)
        p.drawRightString(width - 50, height - 50, f"Client: {client_name}")
        p.drawRightString(width - 50, height - 65, f"Auditor: {auditor_name}")

        # Feature: Asset Inventory Listing
        y = height - 140
        p.setFillColor(colors.black); p.setFont("Helvetica-Bold", 16)
        p.drawString(50, y, "Vulnerability Summary"); y -= 30
        for host in scan.get('scan_data', []):
            if y < 150: p.showPage(); y = height - 50
            p.setFont("Helvetica-Bold", 12); p.drawString(50, y, f"Host: {host['ip_address']}")
            y -= 20
            for svc in host.get('services', []):
                p.setFont("Helvetica", 10); p.drawString(70, y, f"• Port {svc['port']}: {svc['product']}")
                y -= 15

        # --- PAGE 2: KENYA DPA AUDIT ---
        # Feature: Compliance Mapping Logic (Chained to same PDF)
        p.showPage(); y = height - 50
        p.setFillColor(colors.darkred); p.setFont("Helvetica-Bold", 18)
        p.drawString(50, y, "Kenya Data Protection Act (DPA) Audit")
        y -= 40; p.setFillColor(colors.black)
        violations = scan.get('compliance_findings', {}).get('violations', [])
        if not violations: p.drawString(50, y, "✅ No violations detected.")
        else:
            for v in violations:
                if y < 100: p.showPage(); y = height - 50
                p.setFont("Helvetica-Bold", 11); p.drawString(50, y, f"Section {v['section']}: {v['provision']}")
                y -= 15; p.setFont("Helvetica", 10); p.drawString(70, y, f"Issue: {v['finding']}"); y -= 25

        # --- PAGE 3: REMEDIATION ROADMAP ---
        # Feature: Remediation Intelligence (Chained to same PDF)
        p.showPage(); y = height - 50
        p.setFillColor(colors.darkgreen); p.setFont("Helvetica-Bold", 18)
        p.drawString(50, y, "Technical Remediation Roadmap")
        y -= 40; p.setFillColor(colors.black)
        for host in scan.get('scan_data', []):
            for svc in host.get('services', []):
                rem = svc.get('remediation')
                if rem:
                    if y < 120: p.showPage(); y = height - 50
                    p.setFont("Helvetica-Bold", 10); p.drawString(50, y, f"Asset: {host['ip_address']} Port: {svc['port']}")
                    y -= 15; p.setFont("Helvetica", 9); p.drawString(70, y, f"Action: {rem['action']}")
                    y -= 12; p.setFont("Helvetica-Oblique", 8); p.drawString(70, y, f"Steps: {rem['steps']}"); y -= 25

        p.save()
        return response

# --- 3. UPLOAD & ANALYSIS VIEW ---
class NmapUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file_obj = request.FILES.get('file')
        # ... (File Saving Logic) ...
        upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        if not os.path.exists(upload_dir): os.makedirs(upload_dir)
        file_path = os.path.join(upload_dir, file_obj.name)
        with open(file_path, 'wb+') as dest: [dest.write(chunk) for chunk in file_obj.chunks()]

        # Feature: Core Analysis Engine
        parsed_data = parse_nmap_xml(file_path)
        fetcher = NVDFetcher(api_key=os.getenv('NVD_API_KEY'))
        
        for host in parsed_data:
            for svc in host['services']:
                prod, ver = svc.get('product', 'unknown'), svc.get('version', 'unknown')
                # Feature: NVD CVE Intelligence
                vulns = fetcher.search_cves(prod, ver) if prod != 'unknown' else []
                svc['vulnerabilities'], svc['vuln_count'] = vulns, len(vulns)
                # Feature: Dynamic Remediation Attachment
                svc['remediation'] = get_remediation(prod)

        # Feature: Compliance Engine Trigger
        comp_summary = evaluate_compliance(parsed_data)
        
        # Feature: MongoDB Record Persistence
        res = scans_collection.insert_one({
            "user": request.user.username, "filename": file_obj.name,
            "upload_date": datetime.now(), "scan_data": parsed_data,
            "compliance_findings": comp_summary
        })
        return Response({"db_id": str(res.inserted_id), "scan_data": parsed_data}, status=status.HTTP_201_CREATED)

    def get(self, request):
        # Feature: Scan History Retrieval
        cursor = scans_collection.find({"user": request.user.username}).sort("upload_date", -1)
        scans = list(cursor)
        for s in scans: s['_id'], s['upload_date'] = str(s['_id']), s['upload_date'].strftime("%Y-%m-%d %H:%M")
        return Response(scans)