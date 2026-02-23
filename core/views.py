from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from .compliance_engine import evaluate_compliance
from .remediation_engine import get_remediation
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId

# PDF Imports
from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas

# Import your custom tools
from .nmap_parser import parse_nmap_xml
from .cve_fetcher import NVDFetcher

# --- INITIALIZE ENVIRONMENT ---
load_dotenv() 

# --- MONGODB CLOUD CONNECTION ---
mongo_uri = os.getenv('MONGO_URI')

try:
    client = MongoClient(mongo_uri)
    db = client['ansas_db']
    scans_collection = db['scans']
    print(f"✅ Successfully connected to MongoDB Atlas")
except Exception as e:
    print(f"❌ MongoDB Connection Error: {e}")


# --- 1. AUTHENTICATION VIEWS ---

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


# --- 2. REPORT GENERATION VIEW (WHITE LABEL + COMPLIANCE) ---

class GenerateReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            # SECURITY CHECK
            scan = scans_collection.find_one({"_id": ObjectId(scan_id), "user": request.user.username})
            if not scan:
                return Response({"error": "Report not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception:
             return Response({"error": "Invalid ID format"}, status=status.HTTP_400_BAD_REQUEST)

        # 1. Capture White Label Params
        client_name = request.GET.get('client_name', '')
        client_phone = request.GET.get('client_phone', '')
        client_email = request.GET.get('client_email', '')
        auditor_name = request.GET.get('auditor_name', '')
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M")

        # 2. Setup PDF Response
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="report_{scan_id}.pdf"'
        p = canvas.Canvas(response, pagesize=letter)
        width, height = letter

        # 3. Header Design
        p.setFillColor(colors.darkblue)
        p.rect(0, height - 100, width, 100, fill=1)
        p.setFillColor(colors.white)
        p.setFont("Helvetica-Bold", 24)
        p.drawString(50, height - 50, "Security Audit Report")
        p.setFont("Helvetica", 10)
        p.drawString(50, height - 70, "Automated Network Security Assessment System (ANSAS)")

        # 4. White Label Details (Right Aligned)
        p.setFont("Helvetica-Bold", 10)
        p.drawRightString(width - 50, height - 40, f"Client: {client_name}" if client_name else "Client: Internal Audit")
        
        p.setFont("Helvetica", 9)
        offset = 55
        if client_email:
            p.drawRightString(width - 50, height - offset, f"Email: {client_email}")
            offset += 12
        if client_phone:
            p.drawRightString(width - 50, height - offset, f"Phone: {client_phone}")
            offset += 12

        p.setFont("Helvetica-Oblique", 9)
        if auditor_name:
            p.drawRightString(width - 50, height - 85, f"Auditor: {auditor_name}")
        
        p.setFont("Helvetica", 9)
        p.drawRightString(width - 50, height - 95, f"Date: {report_date}")

        # 5. Executive Summary
        y = height - 140
        p.setFillColor(colors.black)
        p.setFont("Helvetica-Bold", 16)
        p.drawString(50, y, "Executive Summary")
        y -= 25
        p.setFont("Helvetica", 11)
        p.drawString(50, y, f"Target File: {scan.get('filename', 'Unknown')}")
        y -= 20
        p.drawString(50, y, f"Total Assets Scanned: {scan.get('asset_count', 0)}")
        y -= 35

        # 6. Detailed Technical Findings
        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, y, "Detailed Technical Findings")
        y -= 25

        for host in scan.get('scan_data', []):
            if y < 120: 
                p.showPage()
                y = height - 50
            
            ip = host.get('ip_address', 'Unknown IP')
            os_name = host.get('os_name', 'Unknown OS')
            p.setFont("Helvetica-Bold", 12)
            p.setFillColor(colors.darkblue)
            p.drawString(50, y, f"Host: {ip} ({os_name})")
            p.setFillColor(colors.black)
            y -= 20
            
            services = host.get('services', [])
            p.setFont("Helvetica", 10)
            if not services:
                p.setFont("Helvetica-Oblique", 10)
                p.drawString(70, y, "No open services detected.")
                y -= 20
            else:
                for svc in services:
                    if y < 80:
                        p.showPage()
                        y = height - 50

                    port = svc.get('port', '?')
                    prod = svc.get('product', 'Unknown')
                    vulns = svc.get('vulnerabilities', [])
                    
                    p.setFont("Helvetica-Bold", 10)
                    p.drawString(70, y, f"• Port {port}: {prod}")
                    y -= 15

                    if vulns:
                        for v in vulns:
                            cve = v.get('id', 'No CVE')
                            score = v.get('cvss_score', 0)
                            try:
                                s = float(score)
                                if s >= 9.0: p.setFillColor(colors.red)
                                elif s >= 7.0: p.setFillColor(colors.orange)
                                else: p.setFillColor(colors.black)
                            except: p.setFillColor(colors.black)

                            p.setFont("Helvetica", 9)
                            p.drawString(90, y, f"- [{cve}] CVSS Score: {score}")
                            y -= 15
                            p.setFillColor(colors.black)
                    else:
                        p.setFont("Helvetica-Oblique", 9)
                        p.setFillColor(colors.green)
                        p.drawString(90, y, "- Status: Secure")
                        p.setFillColor(colors.black)
                        y -= 15
            y -= 10

        # --- 7. NEW: COMPLIANCE AUDIT PAGE ---
        p.showPage()
        y = height - 50
        p.setFillColor(colors.darkred)
        p.setFont("Helvetica-Bold", 18)
        p.drawString(50, y, "Kenya Data Protection Act (DPA) Audit")
        y -= 30
        
        # Access the structured results from the compliance engine
        comp_summary = scan.get('compliance_findings', {})
        findings_list = comp_summary.get('violations', [])
        
        if not findings_list:
            p.setFillColor(colors.green)
            p.setFont("Helvetica", 12)
            p.drawString(50, y, "✅ No major DPA compliance violations detected based on current scan.")
        else:
            p.setFont("Helvetica-Oblique", 10)
            p.setFillColor(colors.black)
            p.drawString(50, y, "The following findings indicate potential non-compliance with the DPA 2019:")
            y -= 30
            
            for finding in findings_list:
                if y < 120:
                    p.showPage()
                    y = height - 50
                
                p.setFont("Helvetica-Bold", 11)
                p.drawString(50, y, f"Violation: {finding['section']} - {finding['provision']}")
                y -= 15
                p.setFont("Helvetica", 10)
                p.drawString(70, y, f"• Asset IP: {finding['ip']}")
                y -= 12
                p.drawString(70, y, f"• Issue: {finding['finding']}")
                y -= 12
                p.setFont("Helvetica-Oblique", 9)
                p.drawString(70, y, f"• Legal Mandate: {finding['law']}")
                y -= 25

                # --- REMEDIATION ROADMAP PAGE ---
        p.showPage()
        y = height - 50
        p.setFillColor(colors.darkgreen)
        p.setFont("Helvetica-Bold", 18)
        p.drawString(50, y, "Technical Remediation Roadmap")
        
        y -= 40
        p.setFont("Helvetica", 10)
        p.setFillColor(colors.black)

        for host in scan.get('scan_data', []):
            for svc in host.get('services', []):
                # Only show remediation for services with issues or specific products
                if svc.get('vuln_count', 0) > 0:
                    if y < 100: p.showPage(); y = height - 50
                    
                    rem = svc.get('remediation', {})
                    p.setFont("Helvetica-Bold", 11)
                    p.drawString(50, y, f"Target: {host['ip_address']} - Port {svc['port']}")
                    y -= 15
                    p.setFont("Helvetica", 10)
                    p.drawString(70, y, f"• Action: {rem.get('action')}")
                    y -= 12
                    p.setFont("Helvetica-Oblique", 9)
                    p.drawString(70, y, f"• Steps: {rem.get('steps')}")
                    y -= 25

        p.save()
        return response


# --- 3. UPLOAD & HISTORY VIEW ---
# ... (Keep all imports and connection strings exactly as they are) ...

# --- 2. REPORT GENERATION VIEW (WHITE LABEL + COMPLIANCE + REMEDIATION) ---

class GenerateReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            scan = scans_collection.find_one({"_id": ObjectId(scan_id), "user": request.user.username})
            if not scan:
                return Response({"error": "Report not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception:
             return Response({"error": "Invalid ID format"}, status=status.HTTP_400_BAD_REQUEST)

        client_name = request.GET.get('client_name', '')
        client_phone = request.GET.get('client_phone', '')
        client_email = request.GET.get('client_email', '')
        auditor_name = request.GET.get('auditor_name', '')
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M")

        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="report_{scan_id}.pdf"'
        p = canvas.Canvas(response, pagesize=letter)
        width, height = letter

        # --- PAGE 1: TECHNICAL FINDINGS ---
        p.setFillColor(colors.darkblue)
        p.rect(0, height - 100, width, 100, fill=1)
        p.setFillColor(colors.white)
        p.setFont("Helvetica-Bold", 24)
        p.drawString(50, height - 50, "Security Audit Report")
        p.setFont("Helvetica", 10)
        p.drawString(50, height - 70, "Automated Network Security Assessment System (ANSAS)")

        p.setFont("Helvetica-Bold", 10)
        p.drawRightString(width - 50, height - 40, f"Client: {client_name}" if client_name else "Client: Internal Audit")
        p.setFont("Helvetica", 9)
        p.drawRightString(width - 50, height - 55, f"Date: {report_date}")

        y = height - 140
        p.setFillColor(colors.black)
        p.setFont("Helvetica-Bold", 16)
        p.drawString(50, y, "Executive Summary")
        y -= 40

        for host in scan.get('scan_data', []):
            if y < 150: p.showPage(); y = height - 50
            p.setFont("Helvetica-Bold", 12)
            p.drawString(50, y, f"Host: {host.get('ip_address')} ({host.get('os_name', 'Unknown')})")
            y -= 20
            for svc in host.get('services', []):
                p.setFont("Helvetica", 10)
                p.drawString(70, y, f"• Port {svc.get('port')}: {svc.get('product')}")
                y -= 15
            y -= 10

        # --- PAGE 2: KENYA DPA COMPLIANCE ---
        p.showPage()
        y = height - 50
        p.setFillColor(colors.darkred)
        p.setFont("Helvetica-Bold", 18)
        p.drawString(50, y, "Kenya Data Protection Act (DPA) Audit")
        y -= 40
        
        comp_summary = scan.get('compliance_findings', {})
        findings_list = comp_summary.get('violations', [])
        
        if not findings_list:
            p.setFillColor(colors.green)
            p.setFont("Helvetica", 12)
            p.drawString(50, y, "✅ No major DPA compliance violations detected.")
        else:
            p.setFillColor(colors.black)
            for finding in findings_list:
                if y < 100: p.showPage(); y = height - 50
                p.setFont("Helvetica-Bold", 11)
                p.drawString(50, y, f"Violation: {finding['section']} - {finding['provision']}")
                y -= 15
                p.setFont("Helvetica", 10)
                p.drawString(70, y, f"• Issue: {finding['finding']}")
                y -= 25

        # --- PAGE 3: REMEDIATION ROADMAP ---
        p.showPage()
        y = height - 50
        p.setFillColor(colors.darkgreen)
        p.setFont("Helvetica-Bold", 18)
        p.drawString(50, y, "Technical Remediation Roadmap")
        y -= 40
        p.setFillColor(colors.black)

        for host in scan.get('scan_data', []):
            for svc in host.get('services', []):
                # We show remediation for vulnerable services OR unencrypted ones
                if svc.get('vuln_count', 0) > 0 or svc.get('remediation'):
                    if y < 100: p.showPage(); y = height - 50
                    rem = svc.get('remediation', {})
                    p.setFont("Helvetica-Bold", 11)
                    p.drawString(50, y, f"Target: {host['ip_address']} - Port {svc['port']}")
                    y -= 15
                    p.setFont("Helvetica", 10)
                    p.drawString(70, y, f"• Action: {rem.get('action', 'Patching')}")
                    y -= 12
                    p.setFont("Helvetica-Oblique", 9)
                    p.drawString(70, y, f"• Steps: {rem.get('steps', 'Update software')}")
                    y -= 30

        p.save()
        return response


# --- 3. UPLOAD & HISTORY VIEW ---

class NmapUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

        upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        if not os.path.exists(upload_dir): os.makedirs(upload_dir)
        file_path = os.path.join(upload_dir, file_obj.name)
        
        with open(file_path, 'wb+') as destination:
            for chunk in file_obj.chunks(): destination.write(chunk)

        parsed_data = parse_nmap_xml(file_path)
        
        api_key = os.getenv('NVD_API_KEY')
        fetcher = NVDFetcher(api_key=api_key)
        
        # FIXED LOOP: Processing remediation INSIDE the service loop
        for host in parsed_data:
            for service in host['services']:
                product = service.get('product', 'unknown')
                version = service.get('version', 'unknown')
                
                # 1. Fetch CVEs
                if product != 'unknown' and version != 'unknown':
                    vulns = fetcher.search_cves(product, version)
                    service['vulnerabilities'] = vulns
                    service['vuln_count'] = len(vulns)
                else:
                    service['vulnerabilities'] = []
                    service['vuln_count'] = 0

                # 2. Attach Remediation (CRITICAL FIX: MOVED INSIDE LOOP)
                service['remediation'] = get_remediation(product)

        compliance_summary = evaluate_compliance(parsed_data)

        scan_record = {
            "user": request.user.username, 
            "filename": file_obj.name,
            "upload_date": datetime.now(),
            "asset_count": len(parsed_data),
            "scan_data": parsed_data,
            "compliance_findings": compliance_summary,
            "status": "analyzed"
        }

        result = scans_collection.insert_one(scan_record)
        return Response({
            "message": "File analyzed successfully",
            "db_id": str(result.inserted_id),
            "scan_data": parsed_data,
            "compliance_summary": compliance_summary
        }, status=status.HTTP_201_CREATED)

    def get(self, request, *args, **kwargs):
        cursor = scans_collection.find({"user": request.user.username}).sort("upload_date", -1)
        scans_list = list(cursor)
        for scan in scans_list:
            scan['_id'] = str(scan['_id'])
            scan['upload_date'] = scan['upload_date'].strftime("%Y-%m-%d %H:%M:%S")
        return Response(scans_list, status=status.HTTP_200_OK)