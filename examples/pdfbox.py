#!/usr/bin/env vpython3
import os
#os.environ['JAVA_HOME'] = '/usr/lib/jvm/msopenjdk-21-amd64/'
os.environ['JVM_PATH'] = '/usr/lib/jvm/msopenjdk-21-amd64/lib/server/libjvm.so'
import sys
import jnius_config

PATH=['.']
def walk(top):
    todo = []
    for fname in os.listdir(top):
        fqname = os.path.join(top, fname)
        if os.path.isdir(fqname):
            todo.append(fqname)
        elif fname.split('.')[-1] == 'jar':
            PATH.append(fqname)
    for fqname in todo:
        walk(fqname)

walk('/devel/lib/java/pdfbox')
jnius_config.set_classpath(*PATH)


import jnius
