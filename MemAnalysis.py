import glob
import sys
import os
import subprocess
import imp
import json
import ntpath
import datetime
from tabulate import tabulate
vol = imp.load_source('vol', 'C:/Python27/volatility-master/vol.py')

# ----------Helpers--------------
def RowsToObjects(VolPluginResult):
    keys = VolPluginResult['columns']
    r = []
    for row in VolPluginResult['rows']:
        a = {}
        for i in range(len(row)):
            a[keys][i] = row[i]
        r.append(a)
    return r

def RowToTuple(row, indice_list):
    acc = []
    for i in indice_list:
        acc.append(row[i])
    return tuple(acc)

#--------------Volatility Aggregator Class-----------------------
class VolatilityAggregator:
    def __init__(self, root_dir, config):
        self.root_dir = os.path.abspath(root_dir)
        self.output_dir = self.root_dir+'\\..\\analysis_output\\'
        os.mkdir(self.output_dir)
        self.files = map(lambda x: os.path.abspath(x),
                         glob.glob(root_dir+"/*.raw"))
        self.config = config
        self.plugins = self.config['plugins']
        self.pluginlist = self.plugins.keys()
        self.results = {}
        self.formatted_tuples = {}
        self.diffs = {}

    def IteratePlugins(self):
        config = vol.config
        for plugin in self.plugins:
            self.results[plugin] = {}
            for f in self.files:
                print 'Running: {plugin} on {f}'.format(plugin=plugin, f=f)

                # create config object for volatility
                config.Cmd = plugin
                config.LOCATION = 'file:///' + f
                config.PROFILE = 'Win10x64_19041'  # todo: this should be detected via KDBgscan or specified in config
                config.OUTPUT = 'json'

                # call volatility, with file for output
                f_name = ntpath.basename(f).replace('.raw', '')
                output = self.output_dir + f_name + "." + plugin
                vol.run_config_with_output(config, output)

                # save results in mem
                with open(output) as j:
                    self.results[plugin][f_name] = json.load(j)

        self.InitTuples()
        return self.results
    
    def InitTuples(self):
        for plugin in self.results:
            self.formatted_tuples[plugin] = {}
            for state in self.results[plugin]:
                    comparison_list = map(lambda x: self.results[plugin][state]['columns'].index(x), self.config['plugins'][plugin]['comparison_fields'])
                    self.formatted_tuples[plugin][state] = set(map(lambda x: RowToTuple(x,comparison_list),  self.results[plugin][state]['rows']))

    def Diff(self):
        for plugin in self.formatted_tuples.keys():
            base_set = self.formatted_tuples[plugin]['base']
            self.diffs[plugin] = {}
            ordered_state_keys = self.config['order']
            
            for i,state in enumerate(ordered_state_keys):
                self.diffs[plugin][state] = {}
                state_set =  self.formatted_tuples[plugin][state]

                comparison_states = []
                if i > 0:
                    comparison_states.append(ordered_state_keys[i-1])
                if i == 0:
                    comparison_states.append('base')
                for comparison_key in comparison_states:
                    comparison_state = self.formatted_tuples[plugin][comparison_key]
                    diffs = state_set - base_set - comparison_state
                    
                    if 'output_filter' in self.config['plugins'][plugin]:
                        diffs = filter(self.config['plugins'][plugin]['output_filter']['fn'], diffs)
                     
                    self.diffs[plugin][state][comparison_key] = list(diffs)
                
        return self.diffs            
    
    def ReportDiffs(self):
        output = []
        for plugin in self.diffs:
            output.append("Diffs for %s" % (plugin))
            for state in self.diffs[plugin]:
                for compare_state in self.diffs[plugin][state]:
                    output.append("Diffs between %s and %s" % (state,compare_state))
                    rows_from_tuples = map(list, self.diffs[plugin][state][compare_state])
                    output.append(tabulate(rows_from_tuples, headers=self.config['plugins'][plugin]['comparison_fields'], tablefmt="html"))
        return output

    def LoadFile(self, file_path):
        with open(file_path) as f:
            self.results = json.load(f)
        self.InitTuples()
            

defualt_mem_diff_profile = {
    'plugins': {
        'dlllist': {'comparison_fields': ["Path"], 
        "output_filter": 
        {
            "Description": 'Filtered by entries that are not in c:\\windows\\system32',
            "fn": lambda x: 'c:\\windows\\system32\\' not in x[0].lower() and '.dll' in x[0].lower()
         }
         },
        'netscan': {'comparison_fields': ["LocalAddr", "ForeignAddr", "Proto", "State", "Owner"]},
        'pslist': {'comparison_fields': ["Name", "PID", "PPID"]},
        'hivelist': {'comparison_fields': ["Name"]},
    },
    'order':['postinstall','running']
}

if __name__ == "__main__":
    if len(sys.argv) == 0:
        print 'Wrong Number of args. Usage: ./memoryfiles'

    vq = VA(sys.argv[1], default_mem_diff_profile)
    #vq.IteratePlugins()
    vq.LoadFile('./results.json')
    vq.Diff()
    r = vq.ReportDiffs()
    print(len(r))
    #print vq.ReportDiffs()
    with open('./Report','w') as f:
        f.write("\n".join(vq.ReportDiffs()).encode('utf-8'))
    
