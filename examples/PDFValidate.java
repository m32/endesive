/*
apache pdf validator
https://pdfbox.apache.org/download.cgi

#!/bin/bash
jars="."
addjar(){
jars="$jars:$1"
}
addjar debugger-app-2.0.14.jar
addjar fontbox-2.0.14.jar
addjar pdfbox-2.0.14.jar
addjar pdfbox-app-2.0.14.jar
addjar pdfbox-debugger-2.0.14.jar
addjar pdfbox-tools-2.0.14.jar
addjar preflight-2.0.14.jar
addjar preflight-app-2.0.14.jar
addjar xmpbox-2.0.14.jar
javac -cp $jars PDFValidate.java
*/

/*
maven modueles:
https://mvnrepository.com/artifact/javax.xml.bind/jaxb-api/2.2.3
https://mvnrepository.com/artifact/javax.activation/activation/1.1.1
*/

import java.io.IOException;
import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.pdfbox.preflight.exception.SyntaxValidationException;
import org.apache.pdfbox.preflight.ValidationResult.ValidationError;
import org.apache.pdfbox.preflight.parser.PreflightParser;

public class PDFValidate {

    public static void main(String[] args)
    {
        try
        {
            PDFValidate.demo(args[0]);
        } catch (IOException e) {
            System.out.println("usage: PDFValidate <file name>");
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    public static void demo(String fileName) throws IOException
    {
        org.apache.pdfbox.preflight.ValidationResult result = null;

        org.apache.pdfbox.preflight.parser.PreflightParser parser = new PreflightParser(fileName);
        try
        {
            parser.parse();
            org.apache.pdfbox.preflight.PreflightDocument document = parser.getPreflightDocument();
            document.validate();
            // Get validation result
            result = document.getResult();
            document.close();
        }
        catch (SyntaxValidationException e)
        {
            result = e.getResult();
        }
        // display validation result
        if (result.isValid())
        {
            System.out.println("The file:" + fileName + " is a valid PDF/A-1b file");
        }
        else
        {
            System.out.println("The file:" + fileName + " is not valid, error(s) :");
            for (ValidationError error : result.getErrorsList())
            {
                System.out.println(error.getErrorCode() + " : " + error.getDetails());
            }
        }
    }

}
