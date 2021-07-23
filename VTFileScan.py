#Virus Total File scanner
import requests
import os, sys, time
import logging
import json
logging.basicConfig(encoding='utf-8', level=logging.DEBUG)
VTSCANURL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VTUPLOADURL = 'https://www.virustotal.com/vtapi/v2/file/scan/upload_url'
VTREPORTURL = 'https://www.virustotal.com/vtapi/v2/file/report'

def MakeparamsCtx():
    return {'apikey': os.getenv('VTAPIKEY')}

def ScanFile(file_path, params):
    URL = VTSCANURL
    abs_path = os.path.abspath(file_path)
    file_name = os.path.basename(abs_path)
    files = {'file': (file_name, open(abs_path, 'rb'))}
    logging.info("Scanning: %s"%(abs_path))
    #Shift file size to meet VT size demands
    size = os.path.getsize(abs_path) >> 20
    if size >= 32:
        if size <= 200:
            logging.error('File size too big for Virus Total Analysis')
            return
        elif size > 650:
            logging.error('File size too big for Virus Total Analysis')
            return
    
    logging.info("Sending Post Request to %s"%(URL))
    scan_response = requests.post(URL, files = files, params=params)
    logging.debug("scan_response:%s" % scan_response)
    return scan_response.json()

def GetUploadUrl(params):
    logging.info("Sending Post Request to Upload url")
    res = requests.get(VTUPLOADURL,params=params)
    logging.debug(params)
    logging.debug(res)
    return res.json()['upload_url']

def ScanAndGetReport(file_path, params, timeout):
    logging.info('Getting resource Id from VirusTotal for file path:', file_path)
    resource_id = ScanFile(file_path, params)
    if resource_id is not None:
        params['resource'] = resource_id['resource']
        #set timeout in fork to allow for scan to happen
        logging.info('Sleeping to allow VT to process')
        time.sleep(timeout)
        return requests.get(VTREPORTURL, params=params)
    else:
        return 

def ScanDir(list_of_files, params):
    out = []
    for f in list_of_files:
        r = ScanAndGetReport(f, params, 5)
        if r is not None:
            out.append(r.json())
    return out

def FmtVTResponse(vtresponse):
    logging.debug(vtresponse)
    out = []
    detections = "Detections: " + str(vtresponse['positives']) + "/" + str(vtresponse['total'])
    fields = ["sha1","permalink","sha256", "md5"]
    for f in fields:
        out.append(f + ":" + vtresponse[f])
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Invalid use, please provide a file_path")
        sys.exit()
    params = MakeparamsCtx()
    response = ScanAndGetReport(sys.argv[1], params, 5)
    with open('response.json','w') as f:
        json.dump(response.json(),f)