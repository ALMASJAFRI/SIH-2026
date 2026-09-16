# -*- coding: utf-8 -*-
"""Refactored Email Forensics with Autonomous LLM Agent, SQLite Persistence, and Single-Line Plotly Timeline"""

import os
import time
import requests
import base64
import email
import email.utils
import mimetypes
from email import policy
import hashlib
import ipaddress
import re
import folium
import sqlite3
import networkx as nx
import plotly.graph_objects as go
from datetime import datetime
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from langgraph.prebuilt import create_react_agent

from langchain_openai import ChatOpenAI



class AttachmentMeta(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str

class EmailAuthHeaders(BaseModel):
    spf_header: Optional[str] = None
    dkim_signature: Optional[str] = None
    auth_results: Optional[str] = None
    dmarc_result: Optional[str] = None

class EmailExtractedData(BaseModel):
    message_id: Optional[str] = None
    sender: Optional[str] = None
    return_path: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    auth_headers: EmailAuthHeaders
    ip_hops: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    attachments: List[AttachmentMeta] = Field(default_factory=list)
    body_text_sample: str = ""



class EmailForensicsExtractor:
    def __init__(self, raw_eml_bytes: bytes):
        self.msg = email.message_from_bytes(raw_eml_bytes, policy=policy.default)
        self.ipv4_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_regex = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

    def is_public_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
        except ValueError:
            return False

    def extract_ip_hops(self) -> List[str]:
        received_headers = self.msg.get_all('Received', [])
        extracted_ips = []
        for header in received_headers:
            for match in self.ipv4_regex.findall(str(header)):
                if self.is_public_ip(match) and match not in extracted_ips:
                    extracted_ips.append(match)
        return extracted_ips

    def extract_auth_headers(self) -> EmailAuthHeaders:
        auth_results = self.msg.get('Authentication-Results', '')
        dmarc_status = None
        if 'dmarc=' in auth_results.lower():
            match = re.search(r'dmarc=([a-zA-Z]+)', auth_results, re.IGNORECASE)
            if match: dmarc_status = match.group(1).lower()
        return EmailAuthHeaders(
            spf_header=self.msg.get('Received-SPF') or None,
            dkim_signature=self.msg.get('DKIM-Signature') or None,
            auth_results=auth_results or None,
            dmarc_result=dmarc_status
        )

    def extract_body_and_urls(self):
        urls = set()
        text_samples = []
        for part in self.msg.walk():
            content_type = part.get_content_type()
            if 'attachment' in str(part.get('Content-Disposition', '')): continue

            if content_type == 'text/plain':
                try:
                    payload = part.get_content()
                    text_samples.append(payload[:1000])
                    urls.update(url.rstrip('.,;)') for url in self.url_regex.findall(payload))
                except Exception: pass
            elif content_type == 'text/html':
                try:
                    soup = BeautifulSoup(part.get_content(), 'html.parser')
                    urls.update(a['href'].strip() for a in soup.find_all('a', href=True) if a['href'].strip().startswith(('http://', 'https://')))
                except Exception: pass
        return list(urls), " ".join(text_samples)[:1500]

    def extract_attachments(self) -> List[AttachmentMeta]:
        attachments = []
        for i, part in enumerate(self.msg.walk()):
            if part.get_content_maintype() == 'multipart': continue

            content_type = part.get_content_type()
            filename = part.get_filename()
            if 'attachment' in str(part.get('Content-Disposition', '')).lower() or filename or part.get_content_maintype() != 'text':
                if not filename:
                    ext = mimetypes.guess_extension(content_type) or '.bin'
                    filename = f"hidden_inline_file_{i}{ext}"

                payload = part.get_payload(decode=True)
                if payload:
                    attachments.append(AttachmentMeta(filename=filename, content_type=content_type, size_bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
        return attachments

    def process(self) -> EmailExtractedData:
        urls, body_sample = self.extract_body_and_urls()
        return EmailExtractedData(
            message_id=self.msg.get('Message-ID'), sender=self.msg.get('From'), return_path=self.msg.get('Return-Path'),
            recipient=self.msg.get('To'), subject=self.msg.get('Subject'), date=self.msg.get('Date'),
            auth_headers=self.extract_auth_headers(), ip_hops=self.extract_ip_hops(), urls=urls,
            attachments=self.extract_attachments(), body_text_sample=body_sample
        )


def init_db(db_path="inbox_threats.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            message_id TEXT PRIMARY KEY,
            subject TEXT,
            verdict TEXT,
            date_received TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT,
            entity_value TEXT,
            entity_type TEXT,
            FOREIGN KEY(email_id) REFERENCES emails(message_id)
        )
    """)
    conn.commit()
    return conn


def save_to_db(conn, extracted_data: EmailExtractedData, verdict: str):
    cursor = conn.cursor()
    msg_id = extracted_data.message_id or f"local_id_{int(time.time())}"
    subject = extracted_data.subject or "No Subject"

    
    try:
        if extracted_data.date:
            parsed_date = email.utils.parsedate_to_datetime(extracted_data.date)
            date_str = parsed_date.strftime("%Y-%m-%d %H:%M:%S")
        else:
            date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("INSERT OR IGNORE INTO emails (message_id, subject, verdict, date_received) VALUES (?, ?, ?, ?)", 
                   (msg_id, subject, verdict, date_str))

    for ip in extracted_data.ip_hops:
        cursor.execute("INSERT INTO entities (email_id, entity_value, entity_type) VALUES (?, ?, 'IP')", 
                       (msg_id, ip))
    conn.commit()



ANALYSIS_CACHE = {}



class IPGeoLookupTool:
    def __init__(self, api_token: str = None):
        self.api_token = api_token
    def lookup(self, ip_address: str) -> dict:
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = {"Authorization": f"Bearer {self.api_token}"} if self.api_token else {}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            data = response.json()
            lat, lon = None, None
            if "loc" in data:
                lat_str, lon_str = data["loc"].split(",")
                lat, lon = float(lat_str), float(lon_str)
            return {"ip": data.get("ip"), "city": data.get("city"), "country": data.get("country"), "org": data.get("org"), "lat": lat, "lon": lon}
        except Exception as e:
            return {"error": str(e), "ip": ip_address}

class VirusTotalURLTool:
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/urls/"
    def check_url(self, url: str) -> Dict[str, Any]:
        if not self.api_key or self.api_key == "YOUR_VT_API_KEY_HERE":
            return {"url": url, "error": "Provide a VirusTotal API key to check URLs."}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.api_key}
        try:
            time.sleep(15) 
            response = requests.get(self.base_url + url_id, headers=headers, timeout=10)
            if response.status_code == 404: return {"url": url, "verdict": "SAFE_OR_UNKNOWN", "details": "Not found in database"}
            response.raise_for_status()
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0: verdict = "MALICIOUS"
            elif stats.get("suspicious", 0) > 0: verdict = "SUSPICIOUS"
            else: verdict = "SAFE"
            return {"url": url, "verdict": verdict, "malicious_engines": stats.get("malicious", 0)}
        except Exception as e:
            return {"error": str(e), "url": url}

class VirusTotalHashTool:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3/files/"
    def check_hash(self, sha256_hash: str) -> Dict[str, Any]:
        if not self.api_key: return {"error": "Missing VirusTotal API Key."}
        headers = {"accept": "application/json", "x-apikey": self.api_key}
        try:
            time.sleep(15)
            response = requests.get(self.base_url + sha256_hash, headers=headers, timeout=10)
            if response.status_code == 404: return {"hash": sha256_hash, "verdict": "UNKNOWN", "details": "File never seen"}
            response.raise_for_status()
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0: verdict = "MALICIOUS"
            elif stats.get("suspicious", 0) > 0: verdict = "SUSPICIOUS"
            else: verdict = "SAFE"
            return {"hash": sha256_hash, "verdict": verdict, "malicious_engines": stats.get("malicious", 0), "names": data.get("attributes", {}).get("names", [])[:3]}
        except Exception as e:
            return {"error": str(e), "hash": sha256_hash}


ip_lookup_tool_instance = IPGeoLookupTool()
url_checker_tool_instance = VirusTotalURLTool(api_key="80a98b1877060fd020eac36fb723706103439806f49cb042143fb1d92d7eb314")
hash_checker_tool_instance = VirusTotalHashTool(api_key="80a98b1877060fd020eac36fb723706103439806f49cb042143fb1d92d7eb314")

@tool
def ip_geolocation_lookup(ip_address: str) -> Dict[str, Any]: 
    """get ip locations from ips"""
    return ip_lookup_tool_instance.lookup(ip_address)

@tool
def url_threat_check(url: str) -> Dict[str, Any]: 
    """Get Urls Threat checks"""
    return url_checker_tool_instance.check_url(url)

@tool
def hash_threat_check(sha256_hash: str) -> Dict[str, Any]: 
    """Get Hash Threat checks"""
    return hash_checker_tool_instance.check_hash(sha256_hash)

@tool
def submit_final_verdict(verdict: str, reasoning: str) -> str:
    """submit the final verdict as 'THREAT','SPAM','SAFE' """
    valid_verdicts = ["SAFE", "SPAM", "THREAT"]
    upper_verdict = verdict.upper()
    if upper_verdict not in valid_verdicts:
        return f"Error: Invalid verdict '{verdict}'. Must be SAFE, SPAM, or THREAT."
    ANALYSIS_CACHE["verdict"] = upper_verdict
    ANALYSIS_CACHE["reasoning"] = reasoning
    return "Verdict successfully recorded to global cache. You can now finish."



agent_tools = [ip_geolocation_lookup, url_threat_check, hash_threat_check, submit_final_verdict]

llm = ChatOpenAI(
    model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"), 
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url="https://openrouter.ai/api/v1" 
)

system_prompt = """You are an elite cybersecurity forensic analyst agent.
You are provided with extracted metadata from a potentially suspicious email.

Your directives:
1. Autonomously invoke the provided tools to investigate the origin IPs, linked URLs, and extracted attachment hashes.
2. Analyze the aggregate results to identify phishing attempts, malicious infrastructure, or known malware.
3. CRITICAL: When you have made a decision, you MUST call the `submit_final_verdict` tool to officially record your verdict ('SAFE', 'SPAM', or 'THREAT'). Do not just type it in the chat. Call the tool to end the process.
"""

agent_app = create_react_agent(llm, tools=agent_tools, prompt=system_prompt)




def generate_journey_map(extracted_ips, ip_tool_instance):
    chronological_ips = list(reversed(extracted_ips))
    journey_data = [ip_tool_instance.lookup(ip) for ip in chronological_ips if ip_tool_instance.lookup(ip).get('lat')]
    if not journey_data: return None

    origin = journey_data[0]
    email_map = folium.Map(location=[origin['lat'], origin['lon']], zoom_start=2, tiles='https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}', attr='Esri')
    coordinates_path = []

    for index, hop in enumerate(journey_data):
        coord = (hop['lat'], hop['lon'])
        coordinates_path.append(coord)
        step_name = "True Origin" if index == 0 else "Final Destination" if index == len(journey_data) - 1 else f"Transit Hop {index}"
        icon_color = "red" if index == 0 else "green" if index == len(journey_data) - 1 else "blue"
        folium.Marker(location=coord, popup=f"<b>{step_name}</b><br>IP: {hop['ip']}", tooltip=step_name, icon=folium.Icon(color=icon_color, icon="info-sign")).add_to(email_map)

    if len(coordinates_path) > 1:
        folium.PolyLine(coordinates_path, color="red", weight=2.5, opacity=0.8, dash_array='5, 5').add_to(email_map)
    return email_map


def generate_timeline_graph(conn, output_html="threat_timeline.html"):
    """Generates a single continuous line graph showing threat progression over time."""
    cursor = conn.cursor()
    cursor.execute("SELECT date_received, verdict, subject FROM emails ORDER BY date_received ASC")
    records = cursor.fetchall()

    if not records:
        print("[-] Not enough historical data to generate timeline graph.")
        return None

    dates = []
    cumulative_threats = []
    hover_texts = []
    colors = []
    current_threat_count = 0

    for date_recv, verdict, subject in records:
        
        if verdict in ["THREAT", "SPAM"]:
            current_threat_count += 1
        
        dates.append(date_recv)
        cumulative_threats.append(current_threat_count)
        
        
        if verdict == "THREAT":
            colors.append("red")
        elif verdict == "SPAM":
            colors.append("orange")
        else:
            colors.append("green")
            
        hover_texts.append(f"<b>Time:</b> {date_recv}<br><b>Verdict:</b> {verdict}<br><b>Subject:</b> {subject}")

    fig = go.Figure()
    
    
    fig.add_trace(go.Scatter(
        x=dates, 
        y=cumulative_threats, 
        mode='lines+markers',
        name='Inbox Events',
        line=dict(color='darkgray', width=2, shape='hv'), # 'hv' makes it a clean step-chart
        marker=dict(size=12, color=colors, line=dict(width=1, color='black')),
        text=hover_texts,
        hoverinfo='text'
    ))

    fig.update_layout(
        title='Inbox Threat Progression Timeline',
        xaxis_title='Timeline (from 1st Inbox Event)',
        yaxis_title='Cumulative Threats Detected',
        template='plotly_white',
        xaxis=dict(tickangle=-45, showgrid=False),
        yaxis=dict(showgrid=True, rangemode='tozero')
    )

    fig.write_html(output_html)
    print(f"[+] Saved continuous timeline graph to '{output_html}'")
    return fig


if __name__ == "__main__":
    sample_eml_path = "/content/email_1_invoice.eml"
    db_path = "inbox_threats.db"

    
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"[*] Found old database at '{db_path}'. Wiping to ensure clean schema update.")

    
    db_conn = init_db(db_path)

    try:
        with open(sample_eml_path, "rb") as f:
            raw_bytes = f.read()

        extractor = EmailForensicsExtractor(raw_bytes)
        extracted_data = extractor.process()

        print("====== 1. EXTRACTION SUMMARY ======")
        print(f"Subject: {extracted_data.subject}")
        print(f"Found IPs: {len(extracted_data.ip_hops)}")

        print("\n====== 2. AUTONOMOUS AGENT ANALYSIS ======")
        email_payload = extracted_data.model_dump_json(indent=2)
        user_message = HumanMessage(content=f"Analyze this email data:\n{email_payload}")

        for event in agent_app.stream({"messages": [user_message]}):
            if "agent" in event:
                content = event["agent"]["messages"][0].content
                if content:
                    print(f"\n[Agent Thought Process]\n{content}")
            elif "tools" in event:
                for tool_msg in event["tools"]["messages"]:
                    print(f"[Tool Executed] {tool_msg.name}")

        print("\n====== 3. DB COMMIT & POST-PROCESSING ======")
        final_verdict = ANALYSIS_CACHE.get("verdict")

        if not final_verdict:
            print("[-] Error: Agent failed to call the submit_final_verdict tool.")
        else:
            save_to_db(db_conn, extracted_data, final_verdict)
            print("[+] Saved email data and agent verdict to local database.")

            if final_verdict in ["THREAT", "SPAM"]:
                journey_map = generate_journey_map(extracted_data.ip_hops, ip_lookup_tool_instance)
                if journey_map:
                    journey_map.save("journey_map.html")
                    print("[+] Saved route map to 'journey_map.html'.")

            
            generate_timeline_graph(db_conn)

    except FileNotFoundError:
        print(f"Error: Could not find the file at '{sample_eml_path}'.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        db_conn.close()