import axios from 'axios';
import { jsPDF } from 'jspdf';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export const exportJSON = async (caseItem: any) => {
  try {
    let fullData = caseItem;
    if (caseItem.id && (!caseItem.body_content || !caseItem.raw_headers)) {
      try {
        const res = await axios.get(`${API_URL}/cases/${caseItem.id}`);
        fullData = res.data || caseItem;
      } catch {
        fullData = caseItem;
      }
    }

    let suspiciousDomains = fullData.suspicious_domains;
    if (typeof suspiciousDomains === 'string') {
      try { suspiciousDomains = JSON.parse(suspiciousDomains); } catch { suspiciousDomains = []; }
    }
    let extractedUrls = fullData.extracted_urls;
    if (typeof extractedUrls === 'string') {
      try { extractedUrls = JSON.parse(extractedUrls); } catch { extractedUrls = []; }
    }
    let rawHeaders = fullData.raw_headers;
    if (typeof rawHeaders === 'string') {
      try { rawHeaders = JSON.parse(rawHeaders); } catch { rawHeaders = fullData.raw_headers; }
    }

    const payload = {
      report_title: "Forensic Email Threat Investigation Report",
      report_generated_at: new Date().toISOString(),
      case_id: fullData.id,
      subject: fullData.subject,
      sender: fullData.sender_email,
      recipient: fullData.recipient_email,
      status: fullData.status,
      date_logged: fullData.created_at,
      classification: {
        verdict: fullData.ai_classification,
        confidence_score: fullData.confidence_score,
        indicators: fullData.phishing_indicators
      },
      infrastructure: {
        originating_ip: fullData.source_ip,
        geolocation: fullData.geo_location,
        asn: fullData.asn_info,
        latitude: fullData.latitude,
        longitude: fullData.longitude
      },
      authentication: {
        spf_record: fullData.spf_record,
        dkim_valid: fullData.dkim_valid,
        dmarc_policy: fullData.dmarc_policy
      },
      threat_intelligence: {
        suspicious_domains: suspiciousDomains || [],
        extracted_urls: extractedUrls || []
      },
      body_content: fullData.body_content,
      raw_headers: rawHeaders
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Case_${fullData.id}_Forensic_Report.json`;
    a.click();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('Error generating JSON report:', error);
  }
};

export const exportCSV = async (caseItem: any) => {
  try {
    let data = caseItem;
    if (caseItem.id && (!caseItem.body_content || !caseItem.raw_headers)) {
      try {
        const res = await axios.get(`${API_URL}/cases/${caseItem.id}`);
        data = res.data || caseItem;
      } catch {
        data = caseItem;
      }
    }

    const escapeCsv = (str: any) => {
      if (str === null || str === undefined) return '""';
      const s = String(str).replace(/"/g, '""');
      return `"${s}"`;
    };

    let csv = "=== FORENSIC EMAIL INVESTIGATION REPORT ===\n";
    csv += "Field,Value\n";
    csv += `Case ID,${escapeCsv(data.id)}\n`;
    csv += `Subject,${escapeCsv(data.subject)}\n`;
    csv += `Sender,${escapeCsv(data.sender_email)}\n`;
    csv += `Recipient,${escapeCsv(data.recipient_email)}\n`;
    csv += `Classification Verdict,${escapeCsv((data.ai_classification || '').toUpperCase())}\n`;
    csv += `Confidence Score,${escapeCsv(((data.confidence_score || 0) * 100).toFixed(1) + '%')}\n`;
    csv += `Status,${escapeCsv(data.status)}\n`;
    csv += `Originating IP,${escapeCsv(data.source_ip || 'N/A')}\n`;
    csv += `Location,${escapeCsv(data.geo_location || 'Unknown')}\n`;
    csv += `Network / ASN,${escapeCsv(data.asn_info || 'Unknown')}\n`;
    csv += `SPF Record,${escapeCsv(data.spf_record ? 'Pass' : 'Fail / None')}\n`;
    csv += `DKIM Signature,${escapeCsv(data.dkim_valid ? 'Valid Signature' : 'Invalid / Missing')}\n`;
    csv += `DMARC Policy,${escapeCsv(data.dmarc_policy || 'None')}\n`;
    csv += `Date Logged,${escapeCsv(new Date(data.created_at).toLocaleString())}\n`;
    csv += `Report Generated,${escapeCsv(new Date().toLocaleString())}\n\n`;

    let domains = data.suspicious_domains;
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains); } catch { domains = []; }
    }
    domains = Array.isArray(domains) ? domains : [];

    csv += "=== THREAT INTELLIGENCE & IOCS ===\n";
    csv += "Index,Domain,Malicious Detections,Suspicious Detections,Reputation Score,Threat Flags\n";
    if (domains.length > 0) {
      domains.forEach((d: any, idx: number) => {
        const vt = d.virustotal || {};
        const flags = (d.reasons || []).join('; ');
        csv += `${idx + 1},${escapeCsv(d.domain)},${escapeCsv(vt.malicious ?? 0)},${escapeCsv(vt.suspicious ?? 0)},${escapeCsv(vt.reputation ?? 'N/A')},${escapeCsv(flags)}\n`;
      });
    } else {
      csv += "None,No malicious domains identified,0,0,Clean,None\n";
    }

    let urls = data.extracted_urls;
    if (typeof urls === 'string') {
      try { urls = JSON.parse(urls); } catch { urls = []; }
    }
    urls = Array.isArray(urls) ? urls : [];
    if (urls.length > 0) {
      csv += "\n=== EXTRACTED URLS ===\n";
      csv += "Index,URL\n";
      urls.forEach((u: string, idx: number) => {
        csv += `${idx + 1},${escapeCsv(u)}\n`;
      });
    }

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Case_${data.id}_Forensic_Report.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('Error generating CSV report:', error);
  }
};

export const exportPDF = async (caseItem: any) => {
  try {
    let data = caseItem;
    if (caseItem.id && (!caseItem.body_content || !caseItem.raw_headers)) {
      try {
        const res = await axios.get(`${API_URL}/cases/${caseItem.id}`);
        data = res.data || caseItem;
      } catch {
        data = caseItem;
      }
    }

    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 16;
    let y = 18;

    // Header Banner
    doc.setFillColor(30, 41, 59);
    doc.rect(margin, y, pageWidth - (margin * 2), 22, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('FORENSIC EMAIL THREAT INVESTIGATION REPORT', margin + 6, y + 9);

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(203, 213, 225);
    doc.text(`Case #${data.id}   |   Status: ${data.status}   |   Generated: ${new Date().toLocaleString()}`, margin + 6, y + 16);

    y += 30;

    const printHeader = (title: string) => {
      doc.setFillColor(241, 245, 249);
      doc.rect(margin, y - 4, pageWidth - (margin * 2), 8, 'F');
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(title, margin + 4, y + 1.5);
      y += 8;
    };

    // 1. Executive Summary
    printHeader('1. EXECUTIVE SUMMARY');
    doc.setFontSize(9);
    doc.setTextColor(51, 65, 85);

    const summary = [
      ['Subject:', data.subject || 'N/A'],
      ['Sender:', data.sender_email || 'N/A'],
      ['Recipient:', data.recipient_email || 'N/A'],
      ['Verdict:', `${(data.ai_classification || 'UNKNOWN').toUpperCase()} (${((data.confidence_score || 0) * 100).toFixed(1)}% confidence)`],
      ['Date Logged:', new Date(data.created_at).toLocaleString()],
    ];

    summary.forEach(([lbl, val]) => {
      doc.setFont('helvetica', 'bold');
      doc.text(lbl, margin + 4, y);
      doc.setFont('helvetica', 'normal');
      const splitVal = doc.splitTextToSize(String(val), pageWidth - margin * 2 - 40);
      doc.text(splitVal, margin + 40, y);
      y += (splitVal.length * 4.5) + 1;
    });

    y += 4;

    // 2. Network Telemetry
    printHeader('2. NETWORK & GEOLOCATION INFRASTRUCTURE');
    const infra = [
      ['Originating IP:', data.source_ip || 'N/A'],
      ['Physical Location:', data.geo_location || 'Unknown Location'],
      ['Network / ASN:', data.asn_info || 'Unknown ASN'],
    ];
    if (data.latitude && data.longitude) {
      infra.push(['Coordinates:', `${data.latitude.toFixed(4)}, ${data.longitude.toFixed(4)}`]);
    }
    infra.forEach(([lbl, val]) => {
      doc.setFont('helvetica', 'bold');
      doc.text(lbl, margin + 4, y);
      doc.setFont('helvetica', 'normal');
      const splitVal = doc.splitTextToSize(String(val), pageWidth - margin * 2 - 40);
      doc.text(splitVal, margin + 40, y);
      y += (splitVal.length * 4.5) + 1;
    });

    y += 4;

    // 3. Sender Identity
    printHeader('3. SENDER IDENTITY & AUTHENTICATION');
    const auth = [
      ['SPF Record:', data.spf_record ? 'PASS (Found & verified)' : 'FAIL / MISSING'],
      ['DKIM Signature:', data.dkim_valid ? 'VALID (Signature verified)' : 'INVALID / MISSING'],
      ['DMARC Policy:', data.dmarc_policy ? `Configured (${data.dmarc_policy})` : 'NONE'],
    ];
    auth.forEach(([lbl, val]) => {
      doc.setFont('helvetica', 'bold');
      doc.text(lbl, margin + 4, y);
      doc.setFont('helvetica', 'normal');
      doc.text(String(val), margin + 40, y);
      y += 5.5;
    });

    y += 4;

    // 4. Threat Intel & Domains
    printHeader('4. THREAT INTELLIGENCE & SUSPICIOUS DOMAINS');
    
    if (data.source_ip) {
      doc.setFont('helvetica', 'bold');
      doc.text(`[IP Threat Intel] Source IP: ${data.source_ip}`, margin + 4, y);
      y += 4.5;
      doc.setFont('helvetica', 'normal');
      doc.text(`AbuseIPDB Database: Verified against global multi-reporter incident registry`, margin + 8, y);
      y += 5.5;
    }

    let domains = data.suspicious_domains;
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains); } catch { domains = []; }
    }
    domains = Array.isArray(domains) ? domains : [];

    if (domains.length > 0) {
      domains.forEach((d: any, idx: number) => {
        if (y > 270) {
          doc.addPage();
          y = 18;
        }
        const vt = d.virustotal || {};
        doc.setFont('helvetica', 'bold');
        doc.text(`[IOC ${idx + 1}] Domain: ${d.domain}`, margin + 4, y);
        y += 4.5;
        doc.setFont('helvetica', 'normal');
        const statusLine = `Detections: ${vt.malicious || 0} Malicious, ${vt.suspicious || 0} Suspicious | Reputation: ${vt.reputation ?? 'N/A'}`;
        doc.text(statusLine, margin + 8, y);
        y += 4.5;
        if (d.reasons && d.reasons.length > 0) {
          d.reasons.forEach((r: string) => {
            const cleanR = r.replace(/virustotal/gi, 'Threat Intel');
            const lines = doc.splitTextToSize(`- Flag: ${cleanR}`, pageWidth - margin * 2 - 12);
            doc.text(lines, margin + 8, y);
            y += (lines.length * 4);
          });
        }
        y += 2;
      });
    } else {
      doc.setFont('helvetica', 'normal');
      doc.text('No malicious indicators flagged across security engines.', margin + 4, y);
      y += 6;
    }

    // Page Footers
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(148, 163, 184);
      doc.text(
        `Email Threat Forensic Platform • Case #${data.id} • Page ${i} of ${pageCount}`,
        pageWidth / 2,
        290,
        { align: 'center' }
      );
    }

    doc.save(`Case_${data.id}_Forensic_Report.pdf`);
  } catch (error) {
    console.error('Error generating PDF report:', error);
  }
};

export const downloadReportTxt = async (id: number, existingText?: string) => {
  try {
    let content = existingText;
    if (!content) {
      const reportRes = await axios.get(`${API_URL}/reports/${id}/forensic`);
      content = reportRes.data;
    }
    const blob = new Blob([content || ''], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Case_${id}_Forensic_Report.txt`;
    a.click();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('Error downloading text report:', error);
  }
};
