import requests
from django.http import JsonResponse
from django.shortcuts import render

def check_website(request, url):
    # Basic URL checks
    try:
        response = requests.get(f"http://{url}", timeout=10)
        if response.status_code != 200:
            return JsonResponse({'status': 'error', 'message': 'Website not reachable'}, status=400)
    except requests.exceptions.RequestException as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    
    # Further analysis logic here
    analysis = analyze_website(url)
    
    return JsonResponse({'status': 'success', 'data': analysis})

def analyze_website(url):
    data = {}
    
    # Check domain age and registrar
    try:
        whois_info = requests.get(f"https://api.domainsdb.info/v1/domains/search?domain={url}", timeout=10)
        whois_data = whois_info.json()
        if whois_data['total'] == 0:
            data['domain_info'] = 'Domain not found'
        else:
            data['domain_info'] = whois_data['domains'][0]
    except requests.exceptions.RequestException as e:
        data['domain_info'] = f"Error retrieving domain info: {str(e)}"
    
    # Check for HTTPS
    data['https'] = 'Yes' if url.startswith("https") else 'No'
    
    # Check reputation on VirusTotal
    try:
        vt_api_key = '0bbdb939d20c0d4d804995e21a25b785d4880d6caeaa850c0c52685a2d805b68'
        headers = {
            "x-apikey": vt_api_key
        }
        vt_info = requests.get(f"https://www.virustotal.com/api/v3/domains/{url}", headers=headers, timeout=10)
        vt_data = vt_info.json()
        data['virustotal_reputation'] = vt_data.get('data', {}).get('attributes', {}).get('reputation', 'N/A')
    except requests.exceptions.RequestException as e:
        data['virustotal_reputation'] = f"Error retrieving VirusTotal info: {str(e)}"
    
    return data
