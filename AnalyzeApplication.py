import MemAnalysis as MA
import VTFileScan as VT
import argparse
import os, glob, logging
import json
logging.basicConfig(encoding='utf-8', level=logging.DEBUG)
parser = argparse.ArgumentParser(description='Application Analyzer v0.0.')

parser.add_argument('-memd','--memory_dir', type=str, nargs=1,
                    help='Directory containing .raw file for volatility analysis')

parser.add_argument('-appd','--aplication_dir', type=str, nargs=1,
                    help='Directory containing virus total files for analysis')

parser.add_argument('-rootd', '--root_dir', type=str, default=None, nargs=1,
                    help="Base directory to search for /mem and /app, if this is specified the memd and appd do not need to be")

args = parser.parse_args()

if __name__ == "__main__":
    mem_dir = ''
    app_dir = ''
    if args.root_dir:
        logging.debug("root dir: " + args.root_dir[0])
        root = os.path.abspath(args.root_dir[0])
        mem_dir = root + '/mem/'
        app_dir = root + '/apps/'
    
    elif args.root_dir == '':
        mem_dir = os.path.abspath(args.memory_dir[0])
        app_dir = os.path.abspath(args.application_dir[0])
    
    #Make a volatility analyzer
    logging.debug("Running volatility aggregation on ", mem_dir)
    ma = MA.VolatilityAggregator(mem_dir, MA.defualt_mem_diff_profile)
    ma.IteratePlugins()
    ma.Diff()
    memory_report = "\n".join(ma.ReportDiffs()).encode('utf-8')

    #Send files to Virus Total
    application_files = glob.glob(app_dir+'/*')
    #make a params ctx for VT
    
    ctx = VT.MakeparamsCtx()
    scans = VT.ScanDir(application_files, ctx)

    '''
    j = []
    with open('C:\\Users\\qbullock\\OneDrive - Munson Healthcare\\Desktop\\AppVetUtil\\FileScan\\response.json') as r:
        j = json.load(r)
    vt_report = VT.FmtVTResponse(j)
    '''
    
    
    vt_report = "\n".join(map(VT.FmtVTResponse, scans))

    with open(root + "/Report.html",'w') as f:
        f.write(vt_report)
        f.write('\n')
        f.write(memory_report)






    


