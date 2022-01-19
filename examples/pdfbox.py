#!/usr/bin/env vpython3
import os

jars = [
'java/debugger-app-2.0.14.jar',
'java/fontbox-2.0.14.jar',
'java/java.activation-1.1.1.jar',
'java/javax.xml.bind-2.2.3.jar',
'java/pdfbox-2.0.14.jar',
'java/pdfbox-app-2.0.14.jar',
'java/pdfbox-debugger-2.0.14.jar',
'java/pdfbox-showsignature.jar',
'java/pdfbox-tools-2.0.14.jar',
'java/preflight-2.0.14.jar',
'java/preflight-app-2.0.14.jar',
'java/xades4j-1.5.1.jar',
'java/xmpbox-2.0.14.jar',
]
os.environ['CLASSPATH'] = ':'.join(jars)
os.environ['JAVA_HOME'] = '/usr/lib/jvm/default-java'

import jnius
