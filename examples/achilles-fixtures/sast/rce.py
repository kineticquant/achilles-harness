import os
import pickle
import yaml
import subprocess

def run(raw):
    eval(raw)
    pickle.loads(raw)
    yaml.load(raw)
    os.system("echo " + raw)
    subprocess.call(raw, shell=True)
