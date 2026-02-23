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

# Import custom tools
from .nmap_parser import parse_nmap_xml
from .cve_fetcher import NVDFetcher

# --- INITIALIZE ENVIRONMENT ---
load_dotenv() 
mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['ansas_db']
scans_collection = db['scans']

# --- 1. AUTHENTICATION VIEWS (PRESERVED) ---
class RegisterView(APIView):
    permission_classes = [AllowAny] 
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if not username or not password:
            return Response({"error": "Missing credentials"}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(username=username, password=password)
        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "message": "User created successfully"}, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [AllowAny] 
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({"token": token.key, "username": user.username})
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

# --- 2. REPORT GENERATION VIEW (ALL FEATURES INTACT) ---
class GenerateReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            scan = scans_collection.find_one({"_id": ObjectId(scan_id), "user": request.user.username})
            if not scan:
                return Response({"error": "Report not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception:
             return Response({"error": "Invalid ID format"}, status=status.HTTP_400_BAD_REQUEST)

        # White Label Feature (Intact)
        client_name = request.GET.get('client_name', '')
        client_phone = request.GET.get('client_phone', '')
        client_email = request.GET.get('client_email', '')
        auditor_name = request.GET.get('auditor_name', '')
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M")

        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="report_{scan_id}.pdf"'
        p = canvas.Canvas(response, pagesize=letter)
        width, height = letter

        # Header Design (Intact)
        p.setFillColor(colors.darkblue); p.rect(0, height - 100, width, 100, fill=1)
        p.setFillColor(colors.white); p.setFont("Helvetica-Bold", 24)
        p.drawString(50, height - 50, "Security Audit Report")
        
        # White Label Right-Align Logic (Intact)
        p.setFont("Helvetica-Bold", 10)
        p.drawRightString(width - 50, height - 40, f"Client: {client_name}" if client_name else "Client: Internal Audit")
        p.setFont("Helvetica", 9)
        if client_email: p.drawRightString(width - 50, height - 55, f"Email: {client_email}")
        if auditor_name: p.drawRightString(width - 50, height - 85, f"Auditor: {auditor_name}")
        p.drawRightString(width - 50, height - 95, f"Date: {report_date}")

        # Page 1: Technical Findings & CVE Coloring (Intact)
        y = height - 140
        p.setFillColor(colors.black); p.setFont("Helvetica-Bold", 16)
        p.drawString(50, y, "Detailed Technical Findings"); y -= 35

        for host in scan.get('scan_data', []):
            if y < 120: p.showPage(); y = height - 50
            p.setFont("Helvetica-Bold", 12); p.setFillColor(colors.darkblue)
            p.drawString(50, y, f"Host: {host.get('ip_address')} ({host.get('os_name', 'Unknown')})")
            p.setFillColor(colors.black); y -= 20
            
            for svc in host.get('services', []):
                if y < 80: p.showPage(); y = height - 50
                p.setFont("Helvetica-Bold", 10); p.drawString(70, y, f"• Port {svc['port']}: {svc['product']}")
                y -= 15
                for v in svc.get('vulnerabilities', []):
                    score = float(v.get('cvss_score', 0))
                    if score >= 9.0: p.setFillColor(colors.red)
                    elif score >= 7.0: p.setFillColor(colors.orange)
                    else: p.setFillColor(colors.black)
                    p.setFont("Helvetica", 9)
                    p.drawString(90, y, f"- [{v.get('id')}] CVSS: {score}"); y -= 15
                p.setFillColor(colors.black)

        # PAGE 2: KENYA DPA AUDIT (RESTORED & VERIFIED)
        p.showPage(); y = height - 50
        p.setFillColor(colors.darkred); p.setFont("Helvetica-Bold", 18)
        p.drawString(50, y, "Kenya Data Protection Act (DPA) Audit")
        y -= 40; p.setFillColor(colors.black)
        
        violations = scan.get('compliance_findings', {}).get('violations', [])
        if not violations:
            p.setFont("Helvetica", 12); p.drawString(50, y, "✅ No violations detected.")
        else:
            for v in violations:
                if y < 100: p.showPage(); y = height - 50
                p.setFont("Helvetica-Bold", 11); p.drawString(50, y, f"Section {v['section']}: {v['provision']}")
                y -= 15; p.setFont("Helvetica", 10); p.drawString(70, y, f"IP: {v['ip']} | Issue: {v['finding']}")
                y -= 25

        # PAGE 3: TECHNICAL REMEDIATION (VERIFIED)
        p.showPage(); y = height - 50
        p.setFillColor(colors.darkgreen); p.setFont("Helvetica-Bold", 18)
        p.drawString(50, y, "Technical Remediation Roadmap")
        y -= 40; p.setFillColor(colors.black)

        for host in scan.get('scan_data', []):
            for svc in host.get('services', []):
                rem = svc.get('remediation')
                if rem:
                    if y < 120: p.showPage(); y = height - 50
                    p.setFont("Helvetica-Bold", 11); p.drawString(50, y, f"Target: {host['ip_address']} Port: {svc['port']}")
                    y -= 15; p.setFont("Helvetica", 10); p.drawString(70, y, f"Action: {rem.get('action')}")
                    y -= 12; p.setFont("Helvetica-Oblique", 9); p.drawString(70, y, f"Steps: {rem.get('steps')}")
                    y -= 30

        p.save()
        return response

# --- 3. UPLOAD & ANALYSIS VIEW (ALL FEATURES INTACT) ---
class NmapUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file_obj = request.FILES.get('file')
        if not file_obj: return Response({"error": "No file"}, status=status.HTTP_400_BAD_REQUEST)

        upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        if not os.path.exists(upload_dir): os.makedirs(upload_dir)
        file_path = os.path.join(upload_dir, file_obj.name)
        with open(file_path, 'wb+') as dest:
            for chunk in file_obj.chunks(): dest.write(chunk)

        parsed_data = parse_nmap_xml(file_path)
        fetcher = NVDFetcher(api_key=os.getenv('NVD_API_KEY'))
        
        # --- NEW FEATURE: TOPOLOGY DATA GENERATION ---
        nodes = [{"id": "Scanner", "group": 1, "label": "ANSAS Node"}]
        links = []

        for host in parsed_data:
            ip = host.get('ip_address')
            host_vuln_count = 0
            
            for service in host['services']:
                prod, ver = service.get('product', 'unknown'), service.get('version', 'unknown')
                # CVE Fetching Feature (Intact)
                vulns = fetcher.search_cves(prod, ver) if prod != 'unknown' and ver != 'unknown' else []
                service['vulnerabilities'] = vulns
                service['vuln_count'] = len(vulns)
                host_vuln_count += len(vulns)
                # Remediation Engine Attachment (Intact)
                service['remediation'] = get_remediation(prod)
            
            # Add to Topology
            nodes.append({
                "id": ip, 
                "group": 2, 
                "label": host.get('os_name', 'Host'),
                "vulns": host_vuln_count
            })
            links.append({"source": "Scanner", "target": ip})

        # Compliance Engine Feature (Intact)
        compliance_summary = evaluate_compliance(parsed_data)

        scan_record = {
            "user": request.user.username, 
            "filename": file_obj.name,
            "upload_date": datetime.now(),
            "asset_count": len(parsed_data),
            "scan_data": parsed_data,
            "compliance_findings": compliance_summary,
            "topology": {"nodes": nodes, "links": links}, # Saved for visual graph
            "status": "analyzed"
        }
        result = scans_collection.insert_one(scan_record)
        return Response({
            "db_id": str(result.inserted_id), 
            "scan_data": parsed_data, 
            "compliance_summary": compliance_summary,
            "topology": {"nodes": nodes, "links": links}
        }, status=status.HTTP_201_CREATED)

    def get(self, request):
        cursor = scans_collection.find({"user": request.user.username}).sort("upload_date", -1)
        scans_list = list(cursor)
        for s in scans_list:
            s['_id'] = str(s['_id'])
            s['upload_date'] = s['upload_date'].strftime("%Y-%m-%d %H:%M:%S")
        return Response(scans_list)