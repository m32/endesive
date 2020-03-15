import java.io.File;
 
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;

public class PDFEncrypt {

   public static void main(String args[]) throws Exception {
      //Loading an existing document
      File file = new File(args[0]);
      PDDocument document = PDDocument.load(file);

      //Creating access permission object
      AccessPermission ap = new AccessPermission();

      //Creating StandardProtectionPolicy object
      StandardProtectionPolicy spp = new StandardProtectionPolicy(args[2], args[2], ap);

      //Setting the length of the encryption key
      spp.setEncryptionKeyLength(128);

      //Setting the access permissions
      spp.setPermissions(ap);

      //Protecting the document
      document.protect(spp);

      System.out.println("Document encrypted");

      //Saving the document
      document.save(args[1]);
      //Closing the document
      document.close();

   }
}
